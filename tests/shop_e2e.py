"""Dedicated disposable shop database/controller only. Never run on production.
Requires the fixture controller on HTTP 18080 / gRPC TLS 19443.
Creates a separate native systemd Agent and records fixtures for the browser test.
The orchestration cleanup removes the entire isolated fixture environment.
"""
import os,json,pathlib,subprocess,socket,socketserver,threading,time,secrets,urllib.error
os.environ['NEKOPASS_E2E_BASE']='http://127.0.0.1:18080/api/v1/'
from e2e import api,client,wait

class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  try:
   while data:=self.request.recv(65536):self.request.sendall(data)
  except OSError:pass
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True

def sql(statement):
 return subprocess.check_output(['runuser','-u','postgres','--','psql','-XAt','-d','nekopass_shop_e2e','-v','ON_ERROR_STOP=1','-c',statement],text=True).strip()
def main():
 access=json.loads(pathlib.Path('/root/nekopass-shop-e2e-access.json').read_text());api('login',access,'POST')
 node=api('admin/nodes',{'name':'shop-e2e-node'},'POST');nid=node['id']
 group=api('admin/node-groups',{'name':'shop-e2e-group','enabled':True,'description':'Disposable isolated fixture','sort_order':0,'node_ids':[nid]},'POST')['id']
 plan={'name':'shop-e2e-plan','description':'Monthly quota fixture','enabled':True,'prices':{'monthly':'10.00','quarterly':'25.00','annual':'90.00','onetime':'50.00'},'speed_mbps':0,'quota_bytes':128<<20,'max_rules':10,'max_connections':100,'ip_limit':0,'rule_speed_mbps':0,'rule_ip_limit':0,'rule_connection_limit':0,'duration_days':30,'node_group_ids':[group]}
 pid=api('admin/plans',plan,'POST')['id']
 user={'username':'shop-e2e-user','password':secrets.token_hex(20)}
 uid=api('admin/users',{**user,'enabled':True,'plan_id':0},'POST')['id'];c=client();api('login',user,'POST',c)
 def u(path,body=None,method=None):return api(path,body,method,c)
 def profile():return u('profile')[0]
 def buy(cycle='monthly',key=None):
  q=u('shop/quote',{'plan_id':pid,'cycle':cycle},'POST')
  body={'plan_id':pid,'cycle':cycle,'request_key':key or secrets.token_hex(24),'expected_price_cents':q['amount_cents'],'expected_epoch':q['epoch']}
  return u('shop/purchase',body,'POST'),body
 try:buy();raise AssertionError('purchase without funds accepted')
 except urllib.error.HTTPError as e:assert e.code==409
 recharge={'amount':'100.00','note':'isolated fixture credit','request_key':secrets.token_hex(24)}
 api('admin/users/'+str(uid)+'/recharge',recharge,'POST');api('admin/users/'+str(uid)+'/recharge',recharge,'POST')
 assert u('wallet')['balance_cents']==10000
 result,request=buy();u('shop/purchase',request,'POST');assert u('wallet')['balance_cents']==9000
 assert profile()['quota_epoch']==1 and profile()['next_reset_at']
 print('PASS credit then balance-only purchase, insufficient funds and duplicate request protection',flush=True)
 env=pathlib.Path('/opt/nekopass-shop-e2e/agent.env');env.write_text('NEKOPASS_SERVER=127.0.0.1:19443\nNEKOPASS_NODE_TOKEN='+node['token']+'\nNEKOPASS_CA=/etc/nekopass/tls/server.crt\n');env.chmod(0o600)
 subprocess.run(['systemd-run','--unit=nekopass-shop-agent-e2e','--property=User=nekopass-agent','--property=Group=nekopass-agent','--property=EnvironmentFile='+str(env),'--property=StateDirectory=nekopass-shop-agent-e2e','/opt/nekopass-shop-e2e/bin/nekopass-agent','-state','/var/lib/nekopass-shop-agent-e2e/state.db'],check=True)
 wait(lambda:next(n for n in api('admin/nodes') if n['id']==nid)['online'])
 echo=Server(('127.0.0.1',0),Echo);threading.Thread(target=echo.serve_forever,daemon=True).start()
 try:
  rid=u('rules',{'node_id':nid,'name':'shop-e2e-forward','listen_port':0,'targets':['127.0.0.1:'+str(echo.server_address[1])],'enabled':True,'balance':'random','proxy_accept':'off','proxy_send':'off'},'POST')['id']
  def rule():return next(r for r in u('rules') if r['id']==rid)
  wait(lambda:next(n for n in api('admin/nodes') if n['id']==nid)['applied_revision']>=rule()['config_revision']) if 'config_revision' in rule() else time.sleep(2)
  def transfer():
   with socket.create_connection(('127.0.0.1',rule()['listen_port']),timeout=12) as conn:
    payload=b'x'*65536;conn.sendall(payload);received=b''
    while len(received)<len(payload):
     part=conn.recv(len(payload)-len(received));assert part;received+=part
    assert received==payload
  transfer();wait(lambda:profile()['traffic_bytes']>=131072)
  old_epoch=profile()['quota_epoch'];buy();assert u('wallet')['balance_cents']==8000
  wait(lambda:profile()['quota_epoch']==old_epoch+1 and profile()['traffic_bytes']==0)
  time.sleep(2);transfer();wait(lambda:profile()['traffic_bytes']>=131072)
  assert profile()['traffic_bytes']==131072
  print('PASS live TCP traffic, renewal clears current usage and late old reports stay in their period',flush=True)
  subprocess.run(['systemctl','restart','nekopass-shop-agent-e2e'],check=True)
  wait(lambda:next(n for n in api('admin/nodes') if n['id']==nid)['online'] and not next(n for n in api('admin/nodes') if n['id']==nid)['sync_error'])
  time.sleep(2);transfer();wait(lambda:profile()['traffic_bytes']==262144)
  old_epoch=profile()['quota_epoch']
  sql("UPDATE users SET reset_anchor_at=now()-interval '1 month',reset_index=1,next_reset_at=now()-interval '1 second',subscription_expires_at=now()+interval '90 days' WHERE id="+str(uid))
  wait(lambda:profile()['quota_epoch']==old_epoch+1 and profile()['traffic_bytes']==0)
  time.sleep(2);transfer();wait(lambda:profile()['traffic_bytes']==131072)
  print('PASS Agent restart retains period identity and automatic monthly reset starts fresh quota',flush=True)
  # A persistent connection must stop when the subscription ends.
  conn=socket.create_connection(('127.0.0.1',rule()['listen_port']),timeout=5);conn.sendall(b'ok');assert conn.recv(2)==b'ok'
  sql("UPDATE users SET subscription_expires_at=now()-interval '1 second',next_reset_at=NULL WHERE id="+str(uid))
  conn.settimeout(8)
  try:assert conn.recv(1)==b''
  except ConnectionResetError:pass
  finally:conn.close()
  buy();time.sleep(2);transfer();wait(lambda:profile()['traffic_bytes']>=131072)
  print('PASS expiry closes existing connections; renewed subscription resumes forwarding',flush=True)
  assert len(u('orders')['items'])==4
  assert all(o['status']=='paid' for o in u('orders')['items'])
  pathlib.Path('/root/nekopass-shop-e2e-fixtures.json').write_text(json.dumps({'user':user,'uid':uid,'node_id':nid,'group_id':group,'plan_id':pid}))
 finally:echo.shutdown();echo.server_close()
 print('ALL SHOP E2E TESTS PASSED',flush=True)
if __name__=='__main__':main()
