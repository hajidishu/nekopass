"""Validate updater inputs without network access or system changes."""
import importlib.util,io,json,pathlib,sys,tarfile,tempfile,types,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
# Input/archive validation also runs on Windows; fcntl/pwd are Linux-only helpers.
if sys.platform=='win32':
 sys.modules.setdefault('fcntl',types.ModuleType('fcntl'))
 sys.modules.setdefault('pwd',types.ModuleType('pwd'))
spec=importlib.util.spec_from_file_location('updater',ROOT/'scripts/nekopass-update.py')
updater=importlib.util.module_from_spec(spec);spec.loader.exec_module(updater)
class UpdaterTests(unittest.TestCase):
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
