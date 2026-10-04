"""Public release guard regression tests; use temporary Git repositories only."""
import importlib.util
import json
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('public_guard', ROOT / 'scripts/check-public.py')
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class PublicGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.local').mkdir(exist_ok=True)

    def test_runtime_paths_and_links_blocked(self):
        for name in ['.local/access.json', 'dist/release.zip', 'web/node_modules/x.js',
                     'deploy/agent.env', 'deploy/agent.env.bak.20260101', 'internal/state.db-wal',
                     'docs/server.key', 'docs/server.crt', '../README.md',
                     'docs/.vitepress/cache/deps.js', 'docs/.vitepress/temp/app.js',
                     'docs/.vitepress/.temp/app.js',
                     'docs/.vitepress/dist/index.html', 'docs/node_modules/vitepress/package.json']:
            self.assertTrue(GUARD.inspect(name, b''), name)
        self.assertTrue(GUARD.inspect('README.md', b'', '120000'))
        self.assertTrue(GUARD.inspect('web/src/a.svg', b'\0binary'))
        self.assertFalse(GUARD.inspect('deploy/agent.env.example', b'NEKOPASS_NODE_TOKEN=copy-node-key-from-admin-panel\n'))

    def test_secrets_detected_without_printing_values(self):
        token = secrets.token_hex(32)
        for data in [f'api_token = "{token}"', 'postgres://user:' + token + '@example.com/db',
                     'gh' + 'p_' + token, '-----BEGIN ' + 'PRIVATE KEY-----',
                     'NEKOPASS_NODE_TOKEN=' + token, 'Authorization: Bearer ' + token,
                     '-- PostgreSQL ' + 'database dump\n']:
            findings = GUARD.inspect('README.md', data.encode())
            self.assertTrue(findings)
            self.assertNotIn(token, repr(findings))
        self.assertTrue(GUARD.inspect('README.md', b'Local password mentioned in prose', known=['password']))

    def setup_repository(self, root):
        self.git(root, 'init', '-q')
        self.git(root, 'config', 'user.name', 'Public guard fixture')
        self.git(root, 'config', 'user.email', 'fixture@example.invalid')
        self.git(root, 'config', 'maintenance.auto', 'false')
        self.git(root, 'config', 'gc.auto', '0')

    def git(self, root, *args):
        return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)

    def checker(self, root, *args):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/check-public.py'),
                               '--root', str(root), *args], capture_output=True, text=True)

    def test_force_added_ignored_credentials_blocked(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local') as directory:
            root = pathlib.Path(directory)
            self.setup_repository(root)
            (root / '.gitignore').write_text('*.env\n')
            (root / 'agent.env').write_text('NEKOPASS_NODE_TOKEN=' + secrets.token_hex(32))
            self.git(root, 'add', '-f', 'agent.env')
            result = self.checker(root, '--staged')
            self.assertEqual(result.returncode, 1)
            self.assertIn('runtime-or-credential-file', result.stdout + result.stderr)

    def test_deleted_secret_remains_blocked_in_history(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local') as directory:
            root = pathlib.Path(directory)
            self.setup_repository(root)
            token = secrets.token_hex(32)
            (root / 'README.md').write_text('postgres://user:' + token + '@example.invalid/db')
            self.git(root, 'add', 'README.md')
            self.git(root, 'commit', '-qm', 'Fixture containing a dummy credential')
            (root / 'README.md').write_text('Sanitized source')
            self.git(root, 'add', 'README.md')
            self.git(root, 'commit', '-qm', 'Remove dummy credential')
            self.assertEqual(self.checker(root, '--staged').returncode, 0)
            result = self.checker(root, '--history')
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(token, result.stdout + result.stderr)

    def test_git_commit_hook_blocks_forced_credential_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local') as directory:
            root = pathlib.Path(directory)
            self.setup_repository(root)
            (root / 'scripts').mkdir()
            shutil.copyfile(ROOT / 'scripts/check-public.py', root / 'scripts/check-public.py')
            self.git(root, 'config', 'core.hooksPath', str(ROOT / '.githooks'))
            token = secrets.token_hex(32)
            (root / 'agent.env').write_text('NEKOPASS_NODE_TOKEN=' + token)
            self.git(root, 'add', 'agent.env')
            result = subprocess.run(['git', '-C', str(root), 'commit', '-m', 'Blocked fixture'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('runtime-or-credential-file', result.stderr)
            self.assertNotIn(token, result.stdout + result.stderr)

    def test_git_push_hook_blocks_deleted_historical_credential(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local') as directory:
            root = pathlib.Path(directory)
            self.setup_repository(root)
            token = secrets.token_hex(32)
            (root / 'README.md').write_text('postgres://fixture:' + token + '@example.invalid/db')
            self.git(root, 'add', 'README.md')
            self.git(root, 'commit', '-qm', 'Dummy historical credential')
            (root / 'README.md').write_text('Sanitized fixture')
            self.git(root, 'add', 'README.md')
            self.git(root, 'commit', '-qm', 'Sanitize fixture')
            (root / 'scripts').mkdir()
            shutil.copyfile(ROOT / 'scripts/check-public.py', root / 'scripts/check-public.py')
            self.git(root, 'config', 'core.hooksPath', str(ROOT / '.githooks'))
            remote = root / 'remote.git'
            subprocess.run(['git', 'init', '--bare', '-q', str(remote)], check=True, capture_output=True)
            self.git(root, 'remote', 'add', 'fixture', str(remote))
            result = subprocess.run(['git', '-C', str(root), 'push', 'fixture', 'HEAD:refs/heads/main'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('database-password', result.stdout + result.stderr)
            self.assertNotIn(token, result.stdout + result.stderr)
            refs = subprocess.run(['git', '-C', str(remote), 'show-ref'], capture_output=True)
            self.assertEqual(refs.returncode, 1)
            self.assertFalse(refs.stdout)

    def test_export_contains_source_only_and_blocks_known_local_secret(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local') as directory:
            root = pathlib.Path(directory)
            (root / 'README.md').write_text('Public source')
            (root / '.local').mkdir()
            password = secrets.token_hex(16)
            (root / '.local/test-access.json').write_text(json.dumps({'password': password}), encoding='utf-16')
            (root / 'dist').mkdir()
            (root / 'dist/old-release.zip').write_bytes(b'private fixture')
            output = root / 'dist/public/source.zip'
            result = self.checker(root, '--export', str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.namelist(), ['nekopass/README.md'])
            (root / 'README.md').write_text('Credential accidentally pasted: ' + password)
            blocked = root / 'dist/public/blocked.zip'
            result = self.checker(root, '--export', str(blocked))
            self.assertEqual(result.returncode, 1)
            self.assertFalse(blocked.exists())
            self.assertNotIn(password, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
