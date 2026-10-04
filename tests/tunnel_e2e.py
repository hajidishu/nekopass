"""Disposable database and two isolated native systemd Agents only."""
import os,json,pathlib,subprocess,socket,socketserver,threading,time,secrets,urllib.error
os.environ['NEKOPASS_E2E_BASE']='http://127.0.0.1:18080/api/v1/'
from e2e import api,client,wait

ROOT=pathlib.Path('/opt/nekopass-tunnel-e2e')
class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  try:
   while data:=self.request.recv(65536):self.request.sendall(data)
  except OSError:pass
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
def node(name, **changes):
 return {'name':name,'enabled':True,'public_address':'127.0.0.1','notes':'','group_ids':[],
  'listen_host':'127.0.0.1','port_min':21000,'port_max':21999,'max_connections':1000,
  'dial_timeout_seconds':8,'idle_timeout_seconds':300,'probe_interval_seconds':5,
  'disk_path':'/','network_interfaces':[],'allow_direct':True,'tunnel_exit_enabled':False,
  'tunnel_protocol':'plain_tcp','tunnel_listen_host':'127.0.0.1','tunnel_listen_port':0,
  'tunnel_public_host':'','allowed_ingress_ids':[],**changes}
def start_agent(name,token):
 service='nekopass-tunnel-'+name+'-e2e';env=ROOT/(name+'.env');env.write_text('NEKOPASS_SERVER=127.0.0.1:19443\nNEKOPASS_NODE_TOKEN='+token+'\nNEKOPASS_CA=/etc/nekopass/tls/server.crt\n');env.chmod(0o600)
 subprocess.run(['systemd-run','--unit='+service,'--property=User=nekopass-agent','--property=Group=nekopass-agent','--property=EnvironmentFile='+str(env),'--property=StateDirectory='+service,str(ROOT/'bin/nekopass-agent'),'-state','/var/lib/'+service+'/state.db'],check=True)
def main():
 admin=json.loads(pathlib.Path('/root/nekopass-tunnel-e2e-access.json').read_text());api('login',admin,'POST')
 entry=node('tunnel-e2e-ingress');entryid=api('admin/nodes',entry,'POST');entry['token']=entryid['token'];entry['group_ids']=[]
 exitnode=node('tunnel-e2e-egress',tunnel_exit_enabled=True,tunnel_listen_port=31199,tunnel_public_host='127.0.0.1',allowed_ingress_ids=[entryid['id']]);exitid=api('admin/nodes',exitnode,'POST');exitnode['token']=exitid['token']
 ingress_group=api('admin/node-groups',{'name':'tunnel-e2e-entry-group','enabled':True,'description':'','sort_order':0,'node_ids':[entryid['id']]},'POST')['id']
 exit_group=api('admin/node-groups',{'name':'tunnel-e2e-exit-group','enabled':True,'description':'','sort_order':0,'node_ids':[exitid['id']]},'POST')['id']
 plan=api('admin/plans',{'name':'tunnel-e2e-plan','enabled':True,'description':'','prices':{},'speed_mbps':100,'quota_bytes':128<<20,'max_rules':10,'max_connections':100,'ip_limit':0,'rule_speed_mbps':0,'rule_ip_limit':0,'rule_connection_limit':0,'duration_days':30,'node_group_ids':[ingress_group,exit_group]},'POST')['id']
 user={'username':'tunnel-e2e-user','password':secrets.token_hex(20)}
 uid=api('admin/users',{**user,'enabled':True,'plan_id':plan},'POST')['id']
 uc=client();api('login',user,'POST',uc)
 def own(path,body=None,method=None):return api(path,body,method,uc)
 start_agent('ingress',entryid['token']);start_agent('exit',exitid['token'])
 def n(id):return next(n for n in api('admin/nodes') if n['id']==id)
 wait(lambda:n(entryid['id'])['online'] and n(exitid['id'])['online'])
 echo=Server(('127.0.0.1',0),Echo);threading.Thread(target=echo.serve_forever,daemon=True).start()
 try:
  target='127.0.0.1:'+str(echo.server_address[1])
  base={'node_id':entryid['id'],'egress_node_id':exitid['id'],'name':'tunnel-e2e-rule','listen_port':0,'targets':[target],'enabled':True,'balance':'random','proxy_accept':'off','proxy_send':'off'}
  rid=own('rules',base,'POST')['id']
  def rule():return next(r for r in own('rules') if r['id']==rid)
  wait(lambda:rule()['status']=='active',timeout=25)
  def transfer():
   with socket.create_connection(('127.0.0.1',rule()['listen_port']),timeout=8) as c:
    c.settimeout(8);payload=b'tunnel'*16384;c.sendall(payload);received=b''
    while len(received)<len(payload):
     part=c.recv(len(payload)-len(received))
     if not part:raise ConnectionError('upstream closed before echo completed')
     received+=part
    assert received==payload
  transfer();wait(lambda:own('profile')[0]['traffic_bytes']>=len(b'tunnel'*16384)*2)
  print('PASS two Agent plaintext tunnel transfers bytes; ingress counts both directions once',flush=True)
  subprocess.run(['systemctl','stop','nekopass-tunnel-exit-e2e'],check=True)
  time.sleep(1)
  try:transfer();raise AssertionError('tunnel worked without exit Agent')
  except (BrokenPipeError,ConnectionResetError,ConnectionError,TimeoutError,socket.timeout,OSError):pass
  direct={**base,'egress_node_id':0}
  own('rules/'+str(rid),direct,'PUT');wait(lambda:rule()['status']=='active',timeout=25);transfer()
  print('PASS choosing #0 direct still forwards while exit Agent is stopped',flush=True)
  entry['allow_direct']=False;entry['group_ids']=[ingress_group]
  try:api('admin/nodes/'+str(entryid['id']),entry,'PUT');raise AssertionError('disabled direct mode with direct rule')
  except urllib.error.HTTPError as e:assert e.code==409
  own('rules/'+str(rid),base,'PUT')
  api('admin/nodes/'+str(entryid['id']),entry,'PUT')
  try:own('rules',{**direct,'name':'forbidden-direct'},'POST');raise AssertionError('user bypassed direct setting')
  except urllib.error.HTTPError as e:assert e.code==400
  start_agent('exit',exitid['token'])
  wait(lambda:rule()['status']=='active',timeout=25);transfer()
  print('PASS direct selection is optional per ingress; tunnel resumes when exit reconnects',flush=True)
 finally:echo.shutdown();echo.server_close()
 print('ALL TUNNEL E2E TESTS PASSED',flush=True)
if __name__=='__main__':main()
