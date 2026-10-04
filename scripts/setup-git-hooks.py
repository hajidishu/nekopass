#!/usr/bin/env python3
"""Enable repository-local commit/push guards after git init. Does not initialize/push."""
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
result = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'], capture_output=True)
if result.returncode or pathlib.Path(result.stdout.decode().strip()).resolve() != root:
    sys.exit('Initialize this project as its own Git repository first; no settings changed.')
for name in ['pre-commit', 'pre-push']:
    path = root / '.githooks' / name
    path.write_bytes(path.read_bytes().replace(b'\r\n', b'\n'))
    path.chmod(0o755)
subprocess.run(['git', '-C', str(root), 'config', '--local', 'core.hooksPath', '.githooks'], check=True)
print('Enabled pre-commit index scan and pre-push history scan for this repository.')
