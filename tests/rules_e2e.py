"""Additional direct-forwarding integration checks for a dedicated systemd test host."""
import json, pathlib, secrets, socket, socketserver, struct, threading, time
from e2e import api, client, wait, echo, PlanFixture

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

def target(proxy=False):
    received=[]
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            received.append('connection')
            try:
                with self.request.makefile('rb') as stream:
                    if proxy: received.append(stream.readline().decode().strip())
                    while data:=stream.read1(65536): self.request.sendall(data)
            except OSError: pass
    s=Server(('127.0.0.1',0),Handler)
    threading.Thread(target=s.serve_forever,daemon=True).start()
    return s,received

def main():
    creds=json.loads(pathlib.Path('/root/nekopass-test-access.json').read_text())
    api('login',creds,'POST')
    node=next(n for n in api('admin/nodes') if n['online'])['id']
    f=PlanFixture(node);uid=f.uid;user=f.user;manage=f.request
    gid=manage('rule-groups',{'name':'test-group','user_id':uid},'POST')['id']
    a,ac=target();b,bc=target();proxy,pc=target(True)
    owned=[]
    def latest(rid): return next(r for r in manage('rules') if r['id']==rid)
    def synced(rid): return wait(lambda: latest(rid) if latest(rid)['status']=='active' else None)
    def put(rid,config):
        f.update_plan(rule_speed_mbps=config.get('speed_mbps',0),rule_ip_limit=config.get('ip_limit',0),rule_connection_limit=config.get('connection_limit',0))
        manage('rules/'+str(rid),{**config,'speed_mbps':0,'ip_limit':0,'connection_limit':0},'PUT');return synced(rid)
    def usage(): return next(u for u in api('users') if u['id']==uid)
    base={'user_id':uid,'node_id':node,'name':'multi-target','group_id':gid,'listen_port':0,'targets':['127.0.0.1:'+str(a.server_address[1]),'127.0.0.1:'+str(b.server_address[1])],'balance':'round_robin','enabled':True,'speed_mbps':0,'ip_limit':0,'connection_limit':0,'proxy_accept':'off','proxy_send':'off','proxy_trusted_cidrs':[]}
    try:
        f.update_plan(rule_speed_mbps=8)
        rid=manage('rules',base,'POST')['id'];owned.append(rid);r=synced(rid);port=r['listen_port']
        node_config=next(n for n in api('admin/nodes') if n['id']==node)
        assert node_config['port_min']<=port<=node_config['port_max'] and r['group_id']==gid
        for _ in range(6):echo(port,128)
        assert len(ac)==3 and len(bc)==3,(ac,bc)
        print('PASS random port, grouping, round-robin real TCP targets',flush=True)
        time.sleep(.3);start=time.monotonic();echo(port,1<<20);duration=time.monotonic()-start
        mbps=(2<<20)*8/duration/1e6
        assert 3<mbps<9.2,mbps
        print('PASS actual bidirectional rule limit: %.2f Mbps'%mbps,flush=True)
        config=dict(base,listen_port=port,speed_mbps=0,connection_limit=1)
        put(rid,config)
        with socket.create_connection(('127.0.0.1',port),timeout=4) as first:
            first.sendall(b'ok');assert first.recv(2)==b'ok'
            with socket.create_connection(('127.0.0.1',port),timeout=4) as second:
                try:second.sendall(b'no');assert second.recv(2)==b''
                except (ConnectionResetError,BrokenPipeError):pass
        print('PASS active connection cap',flush=True)
        config.update(connection_limit=0,ip_limit=1);put(rid,config)
        with socket.create_connection(('127.0.0.1',port),timeout=4) as first:
            first.sendall(b'ok');assert first.recv(2)==b'ok'
            with socket.create_connection(('127.0.0.1',port),timeout=4,source_address=('127.0.0.2',0)) as second:
                try:second.sendall(b'no');assert second.recv(2)==b''
                except (ConnectionResetError,BrokenPipeError):pass
        print('PASS active source-IP cap',flush=True)
        config.update(ip_limit=0,proxy_accept='v2',proxy_send='v1',proxy_trusted_cidrs=['127.0.0.0/8'],targets=['127.0.0.1:'+str(proxy.server_address[1])])
        put(rid,config);before=latest(rid)['traffic_bytes']
        with socket.create_connection(('127.0.0.1',port),timeout=6) as c:
            header=b'\r\n\r\n\0\r\nQUIT\n'+bytes([0x21,0x11])+struct.pack('!H',12)+socket.inet_aton('203.0.113.7')+socket.inet_aton('192.0.2.1')+struct.pack('!HH',1234,443)
            c.sendall(header+b'hello');assert c.recv(5)==b'hello';c.shutdown(socket.SHUT_WR);assert c.recv(1)==b''
        wait(lambda:latest(rid)['traffic_bytes']==before+10)
        assert 'PROXY TCP4 203.0.113.7 192.0.2.1 1234 443' in pc,pc
        print('PASS PROXY v2 acceptance, v1 sending, header excluded from accounting',flush=True)
        old_used=usage()['traffic_bytes'];old_charged=usage()['charged_bytes']
        manage('rules/batch',{'ids':[rid],'action':'clear'},'POST')
        assert latest(rid)['traffic_bytes']==0
        assert usage()['traffic_bytes']==old_used and usage()['charged_bytes']==old_charged
        stats=manage('rules/stats?rule_id='+str(rid));assert sum(v['bytes'] for v in stats)>0
        print('PASS display reset preserves quota and historical statistics',flush=True)
        imported=manage('rules/import',{'rules':[dict(base,name='import-a'),dict(base,name='import-b')]},'POST')['ids'];owned.extend(imported)
        assert len(imported)==2
        manage('rules/batch',{'ids':imported,'action':'disable'},'POST')
        assert all(latest(i)['status']=='disabled' for i in imported)
        manage('rules/batch',{'ids':imported,'action':'group','group_id':0},'POST')
        assert all(latest(i)['group_id'] is None for i in imported)
        manage('rules/batch',{'ids':imported,'action':'enable'},'POST')
        for i in imported:synced(i)
        manage('rules/batch',{'ids':imported,'action':'switch','node_id':node},'POST')
        for i in imported:echo(synced(i)['listen_port'],100)
        print('PASS atomic import, pause/start, move group and switch ingress',flush=True)
        regular=client();api('login',{'username':user['username'],'password':user['password']},'POST',regular)
        assert all(r['user_id']==uid for r in api('rules',opener=regular))
        original=api('announcement')['content']
        try:
            api('announcement',{'content':'公告测试\n<literal text>'},'PUT')
            assert api('announcement',opener=regular)['content']=='公告测试\n<literal text>'
        finally:api('announcement',{'content':original},'PUT')
        print('PASS announcement persistence and ordinary user rule isolation',flush=True)
        print('ALL RULES V2 E2E TESTS PASSED',flush=True)
    finally:
        f.close()
        for server in [a,b,proxy]:server.shutdown();server.server_close()

if __name__=='__main__':main()
