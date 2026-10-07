"""Validate updater inputs without network access or system changes."""
import importlib.util,io,json,pathlib,sys,tarfile,tempfile,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
# Input/archive validation also runs on Windows; fcntl/pwd are Linux-only helpers.
if sys.platform=='win32':
 sys.modules.setdefault('fcntl',types.ModuleType('fcntl'))
 sys.modules.setdefault('pwd',types.ModuleType('pwd'))
spec=importlib.util.spec_from_file_location('updater',ROOT/'scripts/nekopass-update.py')
updater=importlib.util.module_from_spec(spec);spec.loader.exec_module(updater)
class UpdaterTests(unittest.TestCase):
 def test_curl_download_retries_without_disabling_certificate_checks(self):
  with tempfile.TemporaryDirectory() as temp:
   target=pathlib.Path(temp)/'package'
   def complete(args,**kwargs):target.write_bytes(b'fixture-package')
   with patch.object(updater.shutil,'which',return_value='/usr/bin/curl'),patch.object(updater,'run',side_effect=complete) as run:
    updater.download('https://github.com/example/fixture',target)
    args=run.call_args.args[0]
    self.assertIn('--retry-all-errors',args)
    self.assertIn('--max-filesize',args)
    self.assertIn('--proto-redir',args)
    self.assertNotIn('--insecure',args)
    self.assertNotIn('-k',args)
 def test_bundled_panel_service_invokes_the_existing_cli(self):
  original_path=pathlib.Path
  with tempfile.TemporaryDirectory() as temp:
   root=original_path(temp).resolve()
   (root/'var/lib').mkdir(parents=True)
   (root/'etc/systemd/system').mkdir(parents=True)
   def isolated_path(value):return root / value.lstrip('/')
   user=types.SimpleNamespace(pw_uid=123,pw_gid=123)
   with patch.object(updater.pathlib,'Path',isolated_path),patch.object(updater,'run') as run,patch.object(updater.subprocess,'check_output',return_value='fixture-panel\n'),patch.object(updater.pwd,'getpwnam',return_value=user,create=True),patch.object(updater.os,'chown',create=True):
    updater.setup_panel_update('nekopass')
    unit=(root/'etc/systemd/system/nekopass-update.service').read_text()
    self.assertIn('ExecStart=/usr/local/bin/nekopassctl panel update\n',unit)
    self.assertNotIn('--request',unit)
    self.assertTrue((root/'var/lib/nekopass/panel-update-ready').exists())
    run.assert_any_call(['systemctl','enable','--now','nekopass-update.path'])
 def test_normal_panel_update_prepares_integration_automatically(self):
  with tempfile.TemporaryDirectory() as temp:
   lock=pathlib.Path(temp)/'lock';real_open=pathlib.Path.open
   def open_path(path,*args,**kwargs):return real_open(lock,*args,**kwargs)
   with patch.object(sys,'argv',['updater','--service','nekopass','--version','v0.13.3']),patch.object(updater.os,'geteuid',return_value=0,create=True),patch.object(updater.pathlib.Path,'open',open_path),patch.object(updater.fcntl,'flock',create=True),patch.object(updater.fcntl,'LOCK_EX',1,create=True),patch.object(updater,'setup_panel_update') as setup,patch.object(updater,'update') as update:
    self.assertEqual(updater.main(),0)
    setup.assert_called_once_with('nekopass')
    update.assert_called_once_with('nekopass','v0.13.3')
 @unittest.skipIf(sys.platform=='win32','Linux directory modes')
 def test_staged_panel_can_be_executed_under_private_umask(self):
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp);archive=root/'panel.tar.gz';stage=root/'stage';stage.mkdir()
   with tarfile.open(archive,'w:gz') as f:
    member=tarfile.TarInfo('bin/nekopass');member.size=1;f.addfile(member,io.BytesIO(b'x'))
   mask=updater.os.umask(0o077)
   try:updater.extract_panel(archive,stage)
   finally:updater.os.umask(mask)
   self.assertEqual((stage/'bin').stat().st_mode&0o777,0o755)
   self.assertEqual((stage/'bin/nekopass').stat().st_mode&0o777,0o755)
 def test_panel_request_can_use_existing_helper(self):
  # No system changes: exercise main() request handling with the updater mocked.
  request={'generation':1,'version':'v0.13.1'}
  with tempfile.TemporaryDirectory() as temp:
   lock=pathlib.Path(temp)/'lock'
   real_open=pathlib.Path.open
   def open_path(path,*args,**kwargs):return real_open(lock,*args,**kwargs)
   with patch.object(sys,'argv',['updater','--service','nekopass','--request']),patch.object(updater.os,'geteuid',return_value=0,create=True),patch.object(updater.pathlib.Path,'resolve',lambda path:path),patch.object(updater.pathlib.Path,'open',open_path),patch.object(updater.pathlib.Path,'exists',return_value=True),patch.object(updater.pathlib.Path,'unlink'),patch.object(updater,'read_request',return_value=request),patch.object(updater,'write_result') as result,patch.object(updater,'update') as update,patch.object(updater.fcntl,'flock',create=True),patch.object(updater.fcntl,'LOCK_EX',1,create=True):
    self.assertEqual(updater.main(),0)
    update.assert_called_once_with('nekopass','v0.13.1')
    self.assertEqual([call.args[3] for call in result.call_args_list],['running','completed'])
 def test_archive_cannot_escape_or_install_links(self):
  for name,kind in [('../escape',tarfile.REGTYPE),('/etc/escape',tarfile.REGTYPE),('web/symlink',tarfile.SYMTYPE),('bin/unknown',tarfile.REGTYPE)]:
   with tempfile.TemporaryDirectory() as temp:
    root=pathlib.Path(temp);archive=root/'bad.tar.gz'
    with tarfile.open(archive,'w:gz') as f:
     member=tarfile.TarInfo(name);member.type=kind;member.size=1 if kind==tarfile.REGTYPE else 0;f.addfile(member,io.BytesIO(b'x') if member.size else None)
    with self.assertRaises(ValueError):updater.extract_panel(archive,root/'stage')
 def test_stable_versions_only(self):
  for version in ['../v1.0.0','v1.0.0;id','v1.0.0\n','https://evil.example','v1.0.0-beta']:
   self.assertIsNone(updater.TAG.fullmatch(version))
  self.assertIsNotNone(updater.TAG.fullmatch('v0.10.0'))
 @unittest.skipIf(sys.platform=='win32','Linux installation paths')
 def test_panel_assets_failure_keeps_compatible_binary_and_can_retry(self):
  self.panel_failure_recovery('assets')
 @unittest.skipIf(sys.platform=='win32','Linux installation paths')
 def test_panel_install_failure_never_migrates_or_starts_an_incompatible_binary(self):
  self.panel_failure_recovery('install')
 @unittest.skipIf(sys.platform=='win32','Linux installation paths')
 def test_partial_migration_failure_keeps_old_binary_stopped(self):
  self.panel_failure_recovery('migration')
 def panel_failure_recovery(self,failure):
  original_path=pathlib.Path;real_replace=updater.os.replace;real_copytree=updater.shutil.copytree
  with tempfile.TemporaryDirectory() as temp:
   root=original_path(temp);base=root/'opt/nekopass';(base/'bin').mkdir(parents=True)
   binary=base/'bin/nekopass';binary.write_bytes(b'\x7fELFold')
   def paths(value):
    value=str(value)
    return root/value.lstrip('/') if value.startswith(('/opt/','/usr/local/')) else original_path(value)
   def extract(archive,stage):
    (stage/'bin').mkdir();(stage/'bin/nekopass').write_bytes(b'\x7fELFnew')
    (stage/'web').mkdir();(stage/'web/index.html').write_text('new')
   def copytree(source,target,**kwargs):
    if failure=='assets':raise OSError('fixture assets copy failure')
    return real_copytree(source,target,**kwargs)
   def replace(source,target):
    if failure=='install' and target==binary:raise OSError('fixture install failure')
    return real_replace(source,target)
   def run(args,**kwargs):
    if failure=='migration' and args[0]=='systemd-run':raise OSError('fixture partial migration failure')
   def version(path,agent):return 'v0.15.1' if path.read_bytes()==b'\x7fELFold' else 'v0.15.2'
   active=types.SimpleNamespace(returncode=0)
   with patch.object(updater.pathlib,'Path',paths),patch.object(updater.platform,'machine',return_value='x86_64'),patch.object(updater,'download'),patch.object(updater,'extract_panel',side_effect=extract),patch.object(updater,'current',side_effect=version),patch.object(updater.subprocess,'run',return_value=active),patch.object(updater.subprocess,'check_output',return_value='nekopass\n'),patch.object(updater,'run',side_effect=run) as commands,patch.object(updater.time,'sleep'),patch.object(updater.shutil,'copytree',side_effect=copytree),patch.object(updater.os,'replace',side_effect=replace):
    with self.assertRaises(OSError):updater.update('nekopass','v0.15.2')
    pending=base/'bin/nekopass.update-pending'
    self.assertEqual(json.loads(pending.read_text()),{'version':'v0.15.2','was_active':True})
    starts=[call for call in commands.call_args_list if call.args[0]==['systemctl','start','nekopass']]
    if failure=='assets':
     self.assertEqual(binary.read_bytes(),b'\x7fELFnew');self.assertEqual(len(starts),1)
    elif failure=='install':
     self.assertEqual(binary.read_bytes(),b'\x7fELFold');self.assertEqual(len(starts),0)
     self.assertTrue((base/'bin/nekopass.next').exists())
     self.assertFalse(any(call.args[0][0]=='systemd-run' for call in commands.call_args_list))
    else:
     self.assertEqual(binary.read_bytes(),b'\x7fELFnew');self.assertEqual(len(starts),0)
    with self.assertRaises(ValueError):updater.update('nekopass','v0.15.1')
    # A retry must repair assets even if the installed executable is latest.
    failure='none';active.returncode=1;commands.reset_mock();updater.update('nekopass','v0.15.2')
    commands.assert_any_call(['systemctl','start','nekopass'])
    self.assertFalse(pending.exists());self.assertEqual((base/'web/index.html').read_text(),'new')
    self.assertEqual(binary.read_bytes(),b'\x7fELFnew')
 @unittest.skipIf(sys.platform=='win32','Linux request flags')
 def test_request_schema_and_symlink(self):
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp);request=root/'request.json'
   request.write_text(json.dumps({'generation':1,'version':'v0.10.0'}));self.assertEqual(updater.read_request(request)['generation'],1)
   for data in [{'generation':True,'version':'v0.10.0'},{'generation':0,'version':'v0.10.0'},{'generation':1,'version':'../oops'},{'generation':1,'version':'v0.10.0','url':'https://evil.example'}]:
    request.write_text(json.dumps(data))
    with self.assertRaises(ValueError):updater.read_request(request)
   link=root/'link';link.symlink_to(request)
   with self.assertRaises(OSError):updater.read_request(link)
if __name__=='__main__':unittest.main()
