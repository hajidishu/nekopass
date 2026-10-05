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
