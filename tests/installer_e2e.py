"""Dedicated Linux test host only; installs an isolated native systemd Agent.
Requires release assets at /tmp/nekopass-oss and installer in that tree.
Never overwrites the normal nekopass-agent service or its state.
"""
import functools,http.server,json,os,pathlib,secrets,ssl,subprocess,threading,time,urllib.error
os.environ.setdefault('NEKOPASS_E2E_BASE','http://127.0.0.1:18080/api/v1/')
from e2e import api,wait
PANEL=os.environ['NEKOPASS_E2E_BASE'].removesuffix('/api/v1/').rstrip('/')

SERVICE='nekopass-agent-installtest'
BASE='https://127.0.0.1:10443/nekopass'
ASSETS=pathlib.Path(os.environ.get('NEKOPASS_INSTALL_ASSETS','/tmp/nekopass-oss'))
SCRIPT=ASSETS/'nekopass/install-agent.sh'
ROOT=pathlib.Path('/etc')/SERVICE
BIN=pathlib.Path('/opt')/SERVICE/'bin/nekopass-agent'
STATE=pathlib.Path('/var/lib')/SERVICE/'state.db'
CA='/etc/nekopass/tls/server.crt'
class Quiet(http.server.SimpleHTTPRequestHandler):
 def log_message(self,*args):pass
def command(*args,ok=True):
 p=subprocess.run(['bash',str(SCRIPT),'--service-name',SERVICE,'--ca-file',CA,*args],capture_output=True,text=True,timeout=180)
 if ok and p.returncode:raise AssertionError('installer failed: '+p.stdout+p.stderr)
 if not ok and not p.returncode:raise AssertionError('invalid installation unexpectedly succeeded')
 return p
def main():
 assert not list(ASSETS.rglob('SHA256SUMS')) and not list(ASSETS.rglob('*.sha256')), 'fixture should contain no checksum artifacts'
 api('login',json.loads(pathlib.Path('/root/nekopass-shop-e2e-access.json').read_text()),'POST')
 original=api('admin/settings')['settings'];node=0
 primary_pid=subprocess.check_output(['systemctl','show','nekopass-agent','-p','MainPID','--value'],text=True).strip()
 assert not ROOT.exists() and not STATE.parent.exists() and not BIN.parent.parent.exists(),'isolated test paths already exist; inspect instead of overwriting'
 handler=functools.partial(Quiet,directory=str(ASSETS));server=http.server.ThreadingHTTPServer(('127.0.0.1',10443),handler)
 tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(CA,'/etc/nekopass/tls/server.key');server.socket=tls.wrap_socket(server.socket,server_side=True);threading.Thread(target=server.serve_forever,daemon=True).start()
 try:
  cfg={**original,'panel_url':PANEL,'agent_host':'127.0.0.1','agent_port':19443,'installer_url':BASE+'/install-agent.sh','release_base_url':BASE+'/releases','agent_version':'v0.6.0'}
  api('admin/settings',cfg,'PUT')
  created=api('admin/nodes',{'name':'installer-e2e-'+secrets.token_hex(4)},'POST');node=created['id']
  generated=api('admin/nodes/'+str(node)+'/install-command',{},'POST')
  import re
  ticket=re.search(r"'--install-token' '([a-f0-9]{64})'",generated['command']).group(1)
  # Download failures must not leave a partial installation.
  bad=command('--server','127.0.0.1:19443','--token',created['token'],'--binary-url',BASE+'/missing-binary',ok=False)
  assert not ROOT.exists()
  # Exercise the panel's download wrapper too. The local artifact
  # fixture uses the test CA; a public OSS endpoint uses the system trust store.
  wrapper=generated['command'].replace('bash "$installer" ', 'bash "$installer" --service-name '+SERVICE+' --ca-file '+CA+' ')
  installed=subprocess.run(['bash','-c',wrapper],env={**os.environ,'CURL_CA_BUNDLE':CA},capture_output=True,text=True,timeout=180)
  assert installed.returncode==0, installed.stdout+installed.stderr
  info=lambda:next(n for n in api('admin/nodes') if n['id']==node)
  wait(lambda:info()['online'] and info()['applied_revision']>0)
  assert info()['token']==created['token']
  assert STATE.exists() and (ROOT/'agent.env').stat().st_mode&0o777==0o600
  original_env=(ROOT/'agent.env').read_bytes();old_binary=BIN.read_bytes()
  assert subprocess.check_output([str(BIN),'-version'],text=True).startswith('nekopass-agent v0.6.0 linux/amd64')
  print('PASS download without checksum files, persistent node key, enrollment and isolated systemd start',flush=True)
  duplicate=command('--panel-url',PANEL,'--install-token',ticket,'--upgrade',ok=False)
  assert (ROOT/'agent.env').read_bytes()==original_env and BIN.read_bytes()==old_binary
  new=api('admin/nodes/'+str(node)+'/install-command',{},'POST')
  upgrade=re.search(r"'--install-token' '([a-f0-9]{64})'",new['command']).group(1)
  assert new['existing_node']
  command('--panel-url',PANEL,'--install-token',upgrade,'--upgrade')
  wait(lambda:info()['online'] and not info()['sync_error'])
  assert (ROOT/'agent.env').read_bytes()==original_env
  assert subprocess.check_output(['systemctl','show','nekopass-agent','-p','MainPID','--value'],text=True).strip()==primary_pid
  command('--server','127.0.0.1:19443','--token','a'*64,'--download-base',BASE+'/releases','--upgrade',ok=False)
  assert (ROOT/'agent.env').read_bytes()==original_env
  print('PASS upgrade preserves identity/state, reused tickets and rebinding rejected; primary Agent untouched',flush=True)
 finally:
  if node:
   n=next(n for n in api('admin/nodes') if n['id']==node)
   from plans_e2e import NODE_FIELDS
   cfg={k:n[k] for k in NODE_FIELDS};cfg['enabled']=False
   api('admin/nodes/'+str(node),cfg,'PUT')
   if STATE.exists():wait(lambda:next(n for n in api('admin/nodes') if n['id']==node)['applied_revision']>=next(n for n in api('admin/nodes') if n['id']==node)['config_revision'])
  subprocess.run(['systemctl','disable','--now',SERVICE],capture_output=True)
  if node:api('admin/nodes/'+str(node),{},'DELETE')
  api('admin/settings',original,'PUT');server.shutdown()
  # Exact isolated fixture directories only; never remove the production state.
  import shutil
  for p in [ROOT,STATE.parent,BIN.parent.parent]:
   assert p.name==SERVICE and SERVICE!='nekopass-agent'
   if p.exists():shutil.rmtree(p)
  pathlib.Path('/etc/systemd/system/'+SERVICE+'.service').unlink(missing_ok=True)
  subprocess.run(['systemctl','daemon-reload'],check=True)
 print('ALL INSTALLER E2E TESTS PASSED',flush=True)
if __name__=='__main__':main()
