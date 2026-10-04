"""Unlimited modes and transitions on the dedicated systemd test host."""
import json,pathlib,socket,subprocess,time
from e2e import api,wait,echo,service,PlanFixture,start_target,Echo,Sink
from plans_e2e import NODE_FIELDS

def main():
 api('login',json.loads(pathlib.Path('/root/nekopass-test-access.json').read_text()),'POST')
 node=next(n for n in api('admin/nodes') if n['online']);nid=node['id'];original={k:node[k] for k in NODE_FIELDS}
 f=PlanFixture(nid,quota=-1,speed=0);target=start_target(Echo);sink=start_target(Sink);connections=[]
 def usage():return next(u for u in api('users') if u['id']==f.uid)
 def row(rid):return next(r for r in f.request('rules') if r['id']==rid)
 def create(port):
  rid=f.request('rules',{'node_id':nid,'targets':['127.0.0.1:'+str(port)],'enabled':True},'POST')['id']
  r=wait(lambda:row(rid) if row(rid)['status']=='active' else None);return rid,r['listen_port']
 try:
  f.update_plan(max_rules=0,max_connections=0,duration_days=0)
  changed={**original,'group_ids':list(set(original['group_ids']+[f.group])),'max_connections':0}
  before=node['applied_revision'];api('admin/nodes/'+str(nid),changed,'PUT');wait(lambda:next(n for n in api('admin/nodes') if n['id']==nid)['applied_revision']>before)
  _,port=create(target.server_address[1]);_,port2=create(target.server_address[1]);_,sink_port=create(sink.server_address[1])
  assert len(f.request('rules'))==3 and usage()['max_rules']==0 and usage()['max_connections']==0 and usage()['speed_mbps']==0 and usage()['expires_at'] is None
  for _ in range(20):
   c=socket.create_connection(('127.0.0.1',port),timeout=5);c.sendall(b'ok');assert c.recv(2)==b'ok';connections.append(c)
  for c in connections:c.close()
  connections=[]
  print('PASS unlimited rule count and user/node connections; forever expiry',flush=True)
  echo(port,2<<20);wait(lambda:usage()['traffic_bytes']>4<<20)
  issued=int(subprocess.check_output(['runuser','-u','postgres','--','psql','-d','nekopass','-Atc',f'SELECT COALESCE(sum(issued),0) FROM grants WHERE user_id={int(f.uid)}'],text=True))
  assert issued==0,issued
  print('PASS unlimited traffic transfers with zero finite grants; usage still recorded',flush=True)
  old=usage()['traffic_bytes'];service('stop','nekopass')
  try:echo(port,8<<20)
  finally:service('start','nekopass')
  wait(lambda:usage()['traffic_bytes']>=old+(16<<20))
  stable=usage()['traffic_bytes'];time.sleep(2);assert usage()['traffic_bytes']==stable
  print('PASS unlimited offline transfer and deduplicated replay',flush=True)
  service('restart','nekopass-agent');time.sleep(3);echo(port,65536);wait(lambda:usage()['traffic_bytes']==stable+131072)
  print('PASS unlimited mode survives Agent restart without resetting consumption',flush=True)
  old=usage()['traffic_bytes'];finite_quota=usage()['allocated_bytes']+(1<<20)
  f.update_plan(quota_bytes=finite_quota,speed_mbps=40,max_rules=3,max_connections=2,duration_days=1)
  assert usage()['traffic_bytes']==old
  before_sink=Sink.total
  with socket.create_connection(('127.0.0.1',sink_port),timeout=15) as c:
   try:c.sendall(b'q'*(2<<20));c.shutdown(socket.SHUT_WR);c.recv(1)
   except OSError:pass
  wait(lambda:Sink.total==before_sink+(1<<20));wait(lambda:usage()['traffic_bytes']==old+(1<<20))
  print('PASS switching to finite restores exact remaining quota; historical unlimited usage retained',flush=True)
  f.update_plan(quota_bytes=-1,speed_mbps=0,max_rules=0,max_connections=0,duration_days=0)
  echo(port2,1024)
  subprocess.run(['runuser','-u','postgres','--','psql','-d','nekopass','-c',f"UPDATE users SET plan_started_at=now()-interval '5 years' WHERE id={int(f.uid)}"],check=True,stdout=subprocess.DEVNULL)
  f.update_plan(duration_days=1)
  assert usage()['expires_at'] is not None
  try:echo(port,1);raise AssertionError('expired user forwarded')
  except (OSError,ConnectionError):pass
  f.update_plan(duration_days=0);assert usage()['expires_at'] is None;echo(port,1024)
  print('PASS finite expiry blocks forwarding, forever expiry re-enables it',flush=True)
  print('ALL UNLIMITED E2E TESTS PASSED',flush=True)
 finally:
  for c in connections:c.close()
  api('admin/nodes/'+str(nid),original,'PUT')
  f.close();target.shutdown();sink.shutdown()
if __name__=='__main__':main()
