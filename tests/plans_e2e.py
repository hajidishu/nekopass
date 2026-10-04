"""Dedicated test host only: validates plan enforcement, node control and probe privacy."""
import json,pathlib,secrets,socket,time,urllib.error
from e2e import api,client,wait,echo
from rules_e2e import target

NODE_FIELDS=['name','token','public_address','notes','enabled','group_ids','listen_host','port_min','port_max','max_connections','dial_timeout_seconds','idle_timeout_seconds','probe_interval_seconds','disk_path','network_interfaces','ingress_enabled','allow_direct','tunnel_exit_enabled','tunnel_protocol','tunnel_listen_host','tunnel_listen_port','tunnel_public_host','allowed_ingress_ids']
def main():
 api('login',json.loads(pathlib.Path('/root/nekopass-test-access.json').read_text()),'POST')
 admin=api('me');nodes=api('admin/nodes');node=next(n for n in nodes if n['online']);nid=node['id'];original={k:node[k] for k in NODE_FIELDS}
 suffix=secrets.token_hex(4);target_server,_=target();gid=pid=0;users=[];rule_ids={}
 def prefix(uid):return 'admin/users/'+str(uid)+'/'
 def rules(uid):return api(prefix(uid)+'rules')
 def row(uid,rid):return next(r for r in rules(uid) if r['id']==rid)
 def synced(uid,rid):return wait(lambda:row(uid,rid) if row(uid,rid)['status']=='active' else None)
 def node_row():return next(n for n in api('admin/nodes') if n['id']==nid)
 def sync_after(action):
  before=node_row()['applied_revision'];action();wait(lambda:node_row()['applied_revision']>before)
 try:
  members=[nid]+[n['id'] for n in nodes if n['id']!=nid][:1]
  gid=api('admin/node-groups',{'name':'plan-test-'+suffix,'description':'','enabled':True,'sort_order':0,'node_ids':members},'POST')['id']
  plan={'name':'plan-test-'+suffix,'description':'integration fixture','enabled':True,'speed_mbps':100,'quota_bytes':128<<20,'max_rules':10,'max_connections':50,'ip_limit':1,'rule_speed_mbps':8,'rule_ip_limit':1,'rule_connection_limit':1,'duration_days':1,'node_group_ids':[gid]}
  pid=api('admin/plans',plan,'POST')['id']
  for label in ['a','b']:
   value={'username':'plan-'+label+'-'+suffix,'password':secrets.token_hex(12),'enabled':True,'plan_id':pid}
   uid=api('users',value,'POST')['id'];users.append((uid,value));rule_ids[uid]=[]
  uid,user=users[0];other=users[1][0]
  ordinary=client();api('login',{'username':user['username'],'password':user['password']},'POST',ordinary)
  for path in ['admin/plans','admin/nodes','admin/node-groups',prefix(other)+'rules','nodes']:
   try:api(path,opener=ordinary);raise AssertionError('admin endpoint exposed '+path)
   except urllib.error.HTTPError as e:assert e.code==403
  assert all(r['user_id']==admin['id'] for r in api('rules'))
  config={'node_id':nid,'name':'plan-rule','targets':['127.0.0.1:'+str(target_server.server_address[1])],'enabled':True,'listen_port':0}
  for owner in [uid,uid,other]:
   rid=api(prefix(owner)+'rules',dict(config,user_id=admin['id']),'POST')['id'];rule_ids[owner].append(rid);synced(owner,rid)
  rid=rule_ids[uid][0];port=row(uid,rid)['listen_port'];second_port=row(uid,rule_ids[uid][1])['listen_port'];third_port=row(other,rule_ids[other][0])['listen_port']
  assert all(r['user_id']==uid for r in api('rules',opener=ordinary))
  assert all(r['user_id']==uid for r in rules(uid))
  print('PASS current-user rule page scope and separate admin user-management scope',flush=True)
  probe=wait(lambda: next((n for n in api('node-status',opener=ordinary) if n['id']==nid and n['metrics'] and n['metrics'].get('cpu_ready') and n['metrics'].get('network_ready')),None))
  data=api('node-status',opener=ordinary);assert {n['id'] for n in data if n['group_id']==gid}==set(members)
  raw=json.dumps(data)
  for field in ['public_address','listen_host','token_hash','disk_path','sync_error','network_interfaces','notes']:assert field not in raw,field
  assert probe['metrics']['memory_total']>0 and probe['metrics']['disk_total']>0
  print('PASS grouped native CPU/memory/disk/network/load probe; no address or configuration fields',flush=True)
  echo(port,1024);time.sleep(.2);start=time.monotonic();echo(port,1<<20);speed=(2<<20)*8/(time.monotonic()-start)/1e6;assert 3<speed<9.5,speed
  print('PASS package rule speed enforced: %.2f Mbps'%speed,flush=True)
  plan['rule_speed_mbps']=16;sync_after(lambda:api('admin/plans/'+str(pid),plan,'PUT'))
  start=time.monotonic();echo(port,1<<20);speed=(2<<20)*8/(time.monotonic()-start)/1e6;assert 10<speed<19,speed
  assert row(uid,rid)['speed_mbps']==16
  print('PASS plan edit propagated to bound users and Agent: %.2f Mbps'%speed,flush=True)
  with socket.create_connection(('127.0.0.1',port),timeout=5) as a:
   a.sendall(b'ok');assert a.recv(2)==b'ok'
   with socket.create_connection(('127.0.0.1',second_port),timeout=5,source_address=('127.0.0.2',0)) as b:
    try:b.sendall(b'no');assert b.recv(2)==b''
    except (ConnectionResetError,BrokenPipeError):pass
  print('PASS package user IP limit shared across rules',flush=True)
  changed={**original,'group_ids':list(set(original['group_ids']+[gid])),'max_connections':2,'probe_interval_seconds':2,'idle_timeout_seconds':10}
  sync_after(lambda:api('admin/nodes/'+str(nid),changed,'PUT'))
  with socket.create_connection(('127.0.0.1',port),timeout=5) as a,socket.create_connection(('127.0.0.1',second_port),timeout=5) as b:
   a.sendall(b'ok');assert a.recv(2)==b'ok';b.sendall(b'ok');assert b.recv(2)==b'ok'
   with socket.create_connection(('127.0.0.1',third_port),timeout=5) as c:
    try:c.sendall(b'no');assert c.recv(2)==b''
    except (ConnectionResetError,BrokenPipeError):pass
  wait(lambda:node_row()['active_connections']==0)
  with socket.create_connection(('127.0.0.1',port),timeout=14) as a:
   a.sendall(b'ok');assert a.recv(2)==b'ok';start=time.monotonic();assert a.recv(1)==b'';assert 8<time.monotonic()-start<14
  print('PASS centrally pushed node connection cap and idle timeout without Agent local edits',flush=True)
  before=next(u for u in api('users') if u['id']==uid)
  newer={**plan,'name':'alternative-'+suffix};newpid=api('admin/plans',newer,'POST')['id']
  user['plan_id']=newpid;api('users/'+str(uid),{**user,'password':''},'PUT')
  after=next(u for u in api('users') if u['id']==uid);assert after['traffic_bytes']>=before['traffic_bytes'] and after['charged_bytes']>=before['charged_bytes']
  assigned=after['plan_started_at'];api('users/'+str(uid),{**user,'password':''},'PUT');assert next(u for u in api('users') if u['id']==uid)['plan_started_at']==assigned
  user['plan_id']=pid;api('users/'+str(uid),{**user,'password':''},'PUT');api('admin/plans/'+str(newpid),{},'DELETE')
  print('PASS plan switching preserves consumption; account edits do not renew expiry',flush=True)
  plan['enabled']=False;sync_after(lambda:api('admin/plans/'+str(pid),plan,'PUT'))
  assert api('rule-nodes',opener=ordinary)==[] and api('node-status',opener=ordinary)==[]
  try:echo(port,100);raise AssertionError('disabled plan forwarded')
  except (OSError,ConnectionError):pass
  print('PASS disabled plan removes forwarding and probe access',flush=True)
  print('ALL PLANS / NODES E2E TESTS PASSED',flush=True)
 finally:
  for uid,user in users:
   if rule_ids[uid]:api(prefix(uid)+'rules/batch',{'ids':rule_ids[uid],'action':'delete'},'POST')
   api('users/'+str(uid),{**user,'enabled':False,'plan_id':0},'PUT')
  if pid:api('admin/plans/'+str(pid),{},'DELETE')
  api('admin/nodes/'+str(nid),original,'PUT')
  if gid:api('admin/node-groups/'+str(gid),{},'DELETE')
  target_server.shutdown();target_server.server_close()
if __name__=='__main__':main()
