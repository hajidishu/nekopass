"""Run on the dedicated test server only. Uses native systemd services.

NEKOPASS_E2E_ADMIN_FILE points at JSON {username,password}.
This creates test users/nodes/rules, restarts the agent, and stops/restarts control.
No external network traffic is generated.
"""
import concurrent.futures, http.cookiejar, json, os, pathlib, socket, socketserver, ssl, subprocess, threading, time, urllib.request, urllib.error, secrets

BASE = os.environ.get('NEKOPASS_E2E_BASE', 'http://127.0.0.1:8080/api/v1/')
CA = '/etc/nekopass/tls/server.crt'
CTX = ssl.create_default_context(cafile=CA)
def client():
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
ADMIN = client()
def api(path, data=None, method=None, opener=ADMIN):
    req=urllib.request.Request(BASE+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method=method)
    with opener.open(req,timeout=15) as r: return json.load(r)
def wait(f, timeout=20):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            value=f()
            if value: return value
        except (ConnectionError,urllib.error.URLError,OSError): pass
        time.sleep(.25)
    raise AssertionError('condition did not become true')
def service(action,name): subprocess.run(['systemctl',action]+([name] if name else []),check=True)
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data:=self.request.recv(65536): self.request.sendall(data)
        except OSError: pass
class Sink(socketserver.BaseRequestHandler):
    total=0;lock=threading.Lock()
    def handle(self):
        try:
            while data:=self.request.recv(65536):
                with self.lock: Sink.total+=len(data)
        except OSError: pass
class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
def start_target(handler):
    s=TCPServer(('127.0.0.1',0),handler);threading.Thread(target=s.serve_forever,daemon=True).start();return s
def echo(port,n=65536):
    with socket.create_connection(('127.0.0.1',port),timeout=12) as c:
        block=b'x'*min(n,16384);sent=0
        while sent<n:
            piece=block[:min(len(block),n-sent)];c.sendall(piece);received=b''
            while len(received)<len(piece):
                chunk=c.recv(len(piece)-len(received))
                if not chunk: raise AssertionError('unexpected EOF')
                received+=chunk
            assert received==piece;sent+=len(piece)
        c.shutdown(socket.SHUT_WR)
        assert c.recv(1)==b''
class PlanFixture:
    def __init__(self,node,quota=1<<30,speed=100):
        self.node=node; suffix=secrets.token_hex(5)
        self.group=api('admin/node-groups',{'name':'fixture-'+suffix,'enabled':True,'description':'','sort_order':0,'node_ids':[node]},'POST')['id']
        self.plan={'name':'fixture-'+suffix,'description':'','enabled':True,'speed_mbps':speed,'quota_bytes':quota,'max_rules':20,'max_connections':100,'ip_limit':0,'rule_speed_mbps':0,'rule_ip_limit':0,'rule_connection_limit':0,'duration_days':0,'node_group_ids':[self.group]}
        self.plan_id=api('admin/plans',self.plan,'POST')['id']
        self.user={'username':'fixture-'+suffix,'password':secrets.token_hex(12),'enabled':True,'plan_id':self.plan_id}
        self.uid=api('users',self.user,'POST')['id']
    def request(self,path,data=None,method=None):return api('admin/users/'+str(self.uid)+'/'+path,data,method)
    def update_plan(self,**values):
        revision=next(n for n in api('admin/nodes') if n['id']==self.node)['applied_revision']
        self.plan.update(values);api('admin/plans/'+str(self.plan_id),self.plan,'PUT')
        wait(lambda:next(n for n in api('admin/nodes') if n['id']==self.node)['applied_revision']>revision)
    def close(self):
        rows=self.request('rules')
        if rows:self.request('rules/batch',{'ids':[r['id'] for r in rows],'action':'delete'},'POST')
        for g in self.request('rule-groups'):self.request('rule-groups/'+str(g['id']),{},'DELETE')
        api('users/'+str(self.uid),{**self.user,'enabled':False,'plan_id':0},'PUT')
        api('admin/plans/'+str(self.plan_id),{},'DELETE');api('admin/node-groups/'+str(self.group),{},'DELETE')

def main():
    credentials=json.loads(pathlib.Path(os.environ.get('NEKOPASS_E2E_ADMIN_FILE','/root/nekopass-test-access.json')).read_text())
    wait(lambda:api('login',credentials,'POST'))
    node=next(n for n in api('admin/nodes') if n['online'])['id']
    f=PlanFixture(node);q=PlanFixture(node,quota=1<<20,speed=1000);target=start_target(Echo);sink=start_target(Sink)
    def create(f,port):
        rid=f.request('rules',{'node_id':node,'targets':['127.0.0.1:'+str(port)],'enabled':True},'POST')['id']
        return wait(lambda:next((r for r in f.request('rules') if r['id']==rid and r['status']=='active'),None))['listen_port']
    def usage(f):return next(u for u in api('users') if u['id']==f.uid)
    try:
        port=create(f,target.server_address[1]);port2=create(f,target.server_address[1])
        echo(port,65536);wait(lambda:usage(f)['traffic_bytes']==131072)
        print('PASS exact bidirectional accounting',flush=True)
        start=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:list(pool.map(lambda p:echo(p,16<<20),[port,port2]))
        mbps=(64<<20)*8/(time.monotonic()-start)/1e6;assert 75<mbps<115,mbps
        print('PASS package user cap shared by rules: %.2f Mbps'%mbps,flush=True)
        time.sleep(2);old=usage(f)['traffic_bytes'];service('stop','nekopass')
        try:echo(port,1<<20)
        finally:service('start','nekopass')
        wait(lambda:usage(f)['traffic_bytes']>=old+(2<<20));stable=usage(f)['traffic_bytes'];time.sleep(3);assert usage(f)['traffic_bytes']==stable
        print('PASS offline forwarding and deduplicated replay',flush=True)
        qp=create(q,sink.server_address[1])
        with socket.create_connection(('127.0.0.1',qp),timeout=15) as c:
            try:c.sendall(b'q'*(2<<20));c.shutdown(socket.SHUT_WR);c.recv(1)
            except OSError:pass
        wait(lambda:Sink.total==1<<20);wait(lambda:usage(q)['traffic_bytes']==1<<20)
        service('restart','nekopass-agent');time.sleep(3)
        with socket.create_connection(('127.0.0.1',qp),timeout=15) as c:
            try:c.sendall(b'q'*1024);c.shutdown(socket.SHUT_WR);c.recv(1)
            except OSError:pass
        assert Sink.total==1<<20
        print('PASS package quota cutoff and no replay after Agent restart',flush=True)
        print('ALL CORE E2E TESTS PASSED',flush=True)
    finally:
        f.close();q.close();target.shutdown();sink.shutdown()
if __name__=='__main__':main()
