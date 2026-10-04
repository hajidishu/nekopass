"""Disposable panel/database and native two-Agent fixture only; no production data."""
import json,pathlib,secrets,socket,threading,subprocess,time,ssl,http.client,urllib.error
from tunnel_e2e import ROOT,Server,Echo,node,start_agent
from e2e import api,client,wait

def main():
 api('login',json.loads(pathlib.Path('/root/nekopass-tunnel-e2e-access.json').read_text()),'POST')
 entry=node('h2-ingress');entryid=api('admin/nodes',entry,'POST');entry['token']=entryid['token']
 tls={'server_name':'tunnel.example.test','fingerprint':'chrome','certificate_mode':'self_signed','path':'/api/stream','pool_size':2,'stream_window_mib':16,'connection_window_mib':64,'max_streams':256,'site_title':'Welcome','http_challenge_port':80}
 exitnode=node('h2-exit',tunnel_protocol='tls_h2',tls=tls,tunnel_exit_enabled=True,tunnel_listen_port=31199,tunnel_public_host='127.0.0.1',allowed_ingress_ids=[entryid['id']])
 exitid=api('admin/nodes',exitnode,'POST');exitnode['token']=exitid['token']
 group=api('admin/node-groups',{'name':'h2-group','enabled':True,'node_ids':[entryid['id'],exitid['id']]},'POST')['id']
 plan=api('admin/plans',{'name':'h2-plan','enabled':True,'speed_mbps':0,'quota_bytes':4<<20,'max_rules':10,'max_connections':100,'duration_days':30,'node_group_ids':[group]},'POST')['id']
 user={'username':'h2-user','password':secrets.token_hex(20)}
 uid=api('admin/users',{**user,'enabled':True,'plan_id':plan},'POST')['id'];uc=client();api('login',user,'POST',uc)
 own=lambda path,data=None,method=None:api(path,data,method,uc)
 start_agent('ingress',entryid['token']);start_agent('exit',exitid['token'])
 n=lambda id:next(n for n in api('admin/nodes') if n['id']==id)
 wait(lambda:n(entryid['id'])['online'] and n(exitid['id'])['online'],timeout=30)
 echo=Server(('127.0.0.1',0),Echo);threading.Thread(target=echo.serve_forever,daemon=True).start()
 try:
  rule={'node_id':entryid['id'],'egress_node_id':exitid['id'],'listen_port':0,'targets':['127.0.0.1:'+str(echo.server_address[1])],'enabled':True}
  rid=own('rules',rule,'POST')['id'];row=lambda:next(r for r in own('rules') if r['id']==rid)
  wait(lambda:row()['status']=='active',timeout=30)
  payload=b'h2data'*16384
  def transfer(data):
   with socket.create_connection(('127.0.0.1',row()['listen_port']),timeout=8) as conn:
    conn.settimeout(8);conn.sendall(data);result=b''
    while len(result)<len(data):
     part=conn.recv(len(data)-len(result))
     if not part:raise ConnectionError('incomplete h2 transfer')
     result+=part
    assert result==data
  transfer(payload)
  wait(lambda:own('profile')[0]['traffic_bytes']==2*len(payload),timeout=20)
  assert n(exitid['id'])['tls_status']=='ready'
  assert n(entryid['id'])['protocol_version']==7 and n(exitid['id'])['protocol_version']==7
  for path in ['nodes','admin/nodes']:
   try:own(path);raise AssertionError('ordinary user read TLS administration')
   except urllib.error.HTTPError as err:assert err.code==403
  assert all('tls' not in n for n in own('rule-nodes'))
  cert=subprocess.check_output(['runuser','-u','postgres','--','psql','-XAt','-d','nekopass_tunnel_e2e','-c','SELECT tls_certificate FROM nodes WHERE id='+str(exitid['id'])],text=True)
  context=ssl.create_default_context(cadata=cert)
  raw=socket.create_connection(('127.0.0.1',31199),timeout=5)
  with context.wrap_socket(raw,server_hostname='tunnel.example.test') as conn:
   assert conn.version()=='TLSv1.3'
   conn.sendall(b'GET / HTTP/1.1\r\nHost: tunnel.example.test\r\nConnection: close\r\n\r\n')
   response=http.client.HTTPResponse(conn);response.begin();assert response.status==200 and b'Welcome' in response.read()
  print('PASS two real systemd Agents: TLS 1.3/h2, exact business-byte accounting, public HTTPS page, TLS administration privacy',flush=True)
  entry['tls']={'fingerprint':'firefox'};entry['group_ids']=[group]
  api('admin/nodes/'+str(entryid['id']),entry,'PUT');wait(lambda:row()['status']=='active',timeout=30);transfer(payload)
  wait(lambda:own('profile')[0]['traffic_bytes']==4*len(payload),timeout=20)
  print('PASS changed ingress fingerprint to Firefox and preserved transfer/accounting',flush=True)
  subprocess.run(['systemctl','stop','nekopass-tunnel-exit-e2e'],check=True);time.sleep(.5)
  try:transfer(payload);raise AssertionError('TLS silently bypassed stopped exit')
  except (ConnectionError,OSError,TimeoutError):pass
  print('PASS unavailable TLS exit fails closed without plaintext/direct fallback',flush=True)
 finally:echo.shutdown();echo.server_close()
 print('ALL H2 E2E TESTS PASSED',flush=True)
if __name__=='__main__':main()
