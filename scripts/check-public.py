#!/usr/bin/env python3
"""Offline public-source guard. Prints locations/categories, never matched secrets.

Only source files are exported. Git modes inspect index/history, not just .gitignore.
"""
import argparse
import collections
import json
import math
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT_FILES = {'.gitignore', '.gitattributes', 'README.md', 'SECURITY.md', 'LICENSE',
              'go.mod', 'go.sum', 'sqlc.yaml', '开发指南.md'}
SOURCE_DIRS = {'.github', '.githooks', 'api', 'cmd', 'deploy', 'docs', 'internal',
               'scripts', 'tests', 'web'}
PRIVATE_DIRS = {'.git', '.local', '.tools', 'node_modules', 'dist', '__pycache__',
                '.ssh', '.aws', '.codex', '.agents', '.vscode', '.idea', 'coverage', 'cache', 'temp', '.temp'}
EXTENSIONS = {'.go', '.mod', '.sum', '.sql', '.proto', '.yaml', '.yml', '.md', '.txt',
              '.sh', '.ps1', '.py', '.ts', '.mts', '.js', '.cjs', '.mjs', '.json', '.vue',
              '.html', '.css', '.svg', '.example', '.service'}
MAX_FILE = 2 * 1024 * 1024
RULES = [
    ('private-key', re.compile(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----')),
    ('cloud-access-key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('github-token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b')),
    ('service-token', re.compile(r'\b(?:npm_[A-Za-z0-9]{30,255}|xox[baprs]-[A-Za-z0-9-]{20,255})\b')),
    ('database-password', re.compile(r'(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s/:@]+:([^\s/@]+)@', re.I)),
    ('database-dump', re.compile(r'^-- (?:PostgreSQL|MySQL) database dump|^COPY\s+[^\r\n]+\sFROM stdin;', re.M | re.I)),
    ('literal-bearer', re.compile(r'''(?i)Authorization["']?\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9._-]{16,256})''')),
]
ASSIGNMENT = re.compile(r'''(?ix)\b[\w-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w-]*["']?\s*(?::=|=|:)\s*["']([^"'\r\n]{8,})["']''')
ENV_CREDENTIAL = re.compile(r'''(?m)^\s*(?:export\s+)?[A-Z_]*(?:PASSWORD|TOKEN|SECRET|API_KEY|ACCESS_KEY)[A-Z_]*\s*=\s*([^\s"'\r\n#]+)''')


def path_problem(name):
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
        return 'unsafe-path'
    if any(part in PRIVATE_DIRS for part in path.parts):
        return 'private-directory'
    lower = path.name.lower()
    if (lower in {'.npmrc', '.netrc', 'known_hosts'} or lower.startswith(('id_rsa', 'id_ed25519'))
        or re.search(r'(?:\.env(?:\..*)?|\.db(?:-.*)?|\.sqlite\w*|\.key|\.pem|\.crt|\.cer|\.p12|\.pfx|\.dump|\.bak(?:\..*)?|\.backup|\.log|\.pyc|\.exe|\.zip|\.tar(?:\.gz)?|\.tgz)$', lower)
        or lower.endswith('access.json') or 'credentials' in lower):
        if not lower.endswith('.example'):
            return 'runtime-or-credential-file'
    if len(path.parts) == 1:
        return None if name in ROOT_FILES else 'unreviewed-root-file'
    if path.parts[0] not in SOURCE_DIRS:
        return 'unreviewed-directory'
    if path.parts[0] == '.githooks' and path.name in {'pre-commit', 'pre-push'}:
        return None
    return None if path.suffix.lower() in EXTENSIONS else 'unreviewed-file-type'


def placeholder(value):
    lower = value.lower()
    return (lower in {'password', 'changeme', 'change-me', 'your_password', 'your-password'}
            or lower.startswith(('your_', 'your-', 'example-', 'fixture-', 'clitest-', 'copy-node-key-'))
            or value.startswith('$') or '${' in value or '$(' in value)


def entropy(value):
    return -sum((n / len(value)) * math.log2(n / len(value))
                for n in collections.Counter(value).values())


def inspect(name, data, mode='100644', known=()):
    problem = path_problem(name)
    if problem:
        return [(name, 0, problem)]
    if mode == 'oversized':
        return [(name, 0, 'oversized-source-file')]
    if mode not in {'100644', '100755'}:
        return [(name, 0, 'symlink-or-submodule')]
    if len(data) > MAX_FILE:
        return [(name, 0, 'oversized-source-file')]
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        return [(name, 0, 'non-utf8-or-binary-file')]
    if '\0' in text:
        return [(name, 0, 'binary-file')]
    findings = []
    for category, pattern in RULES:
        for match in pattern.finditer(text):
            if category in {'database-password', 'literal-bearer'} and placeholder(match.group(1)):
                continue
            findings.append((name, text.count('\n', 0, match.start()) + 1, category))
    for match in ASSIGNMENT.finditer(text):
        value = match.group(1)
        if len(value) >= 20 and entropy(value) >= 3.5 and not placeholder(value):
            findings.append((name, text.count('\n', 0, match.start()) + 1, 'literal-credential'))
    for match in ENV_CREDENTIAL.finditer(text):
        value = match.group(1)
        if len(value) >= 8 and not placeholder(value):
            findings.append((name, text.count('\n', 0, match.start()) + 1, 'literal-env-credential'))
    for value in known:
        start = text.find(value)
        if start >= 0:
            findings.append((name, text.count('\n', 0, start) + 1, 'local-credential'))
    return findings


def local_credentials(root):
    # Local-only inventory. Values never enter generated archives or reports.
    values = set()
    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, str) and re.search(r'password|passwd|token|secret|key', key, re.I) and len(item) >= 8:
                    values.add(item)
                else:
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    for path in (root / '.local').glob('*.json'):
        try:
            raw = path.read_bytes()
            encoding = 'utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
            collect(json.loads(raw.decode(encoding)))
        except (ValueError, OSError):
            raise RuntimeError('Cannot read local credential inventory; check .local access files') from None
    for key, value in os.environ.items():
        if key.startswith('NEKOPASS_') and re.search(r'PASSWORD|TOKEN|SECRET|KEY', key) and len(value) >= 8:
            values.add(value)
    return values


def working_files(root):
    files = []
    for directory, subdirs, names in os.walk(root, followlinks=False):
        base = pathlib.Path(directory)
        # Private runtime directories are expected locally but never exported.
        subdirs[:] = sorted(d for d in subdirs if d not in PRIVATE_DIRS)
        for dirname in list(subdirs):
            if (base / dirname).is_symlink():
                files.append(((base / dirname).relative_to(root).as_posix(), b'', '120000'))
                subdirs.remove(dirname)
        for filename in sorted(names):
            path = base / filename
            name = path.relative_to(root).as_posix()
            mode = '120000' if path.is_symlink() else '100644'
            # Do not open private paths, symlinks or large files just to reject them.
            if mode == '100644' and not path_problem(name) and path.stat().st_size > MAX_FILE:
                mode = 'oversized'
            data = path.read_bytes() if mode == '100644' and not path_problem(name) else b''
            files.append((name, data, mode))
    return files


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True)
    if result.returncode:
        raise RuntimeError('Git check failed; initialize a repository or check the requested revision')
    return result.stdout


def indexed_files(root):
    # Inspect every indexed path, including old tracked files now ignored by Git.
    for record in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, oid, stage = metadata.decode().split()
        name = name.decode('utf-8')
        if stage != '0':
            raise RuntimeError('Resolve index conflicts before public release')
        data, mode = git_blob(root, name, oid, mode)
        yield name, data, mode


def git_blob(root, name, oid, mode, kind='blob'):
    if path_problem(name) or kind != 'blob' or mode not in {'100644', '100755'}:
        return b'', mode
    if int(git(root, 'cat-file', '-s', oid)) > MAX_FILE:
        return b'', 'oversized'
    return git(root, 'cat-file', 'blob', oid), mode


def history_files(root):
    # Include deleted files and all reachable refs, not only HEAD's current tree.
    seen = set()
    for revision in git(root, 'rev-list', '--all').decode().splitlines():
        for record in git(root, 'ls-tree', '-r', '-z', '--full-tree', revision).split(b'\0'):
            if not record:
                continue
            metadata, name = record.split(b'\t', 1)
            mode, kind, oid = metadata.decode().split()
            name = name.decode('utf-8')
            identity = (name, oid)
            if identity in seen:
                continue
            seen.add(identity)
            data, mode = git_blob(root, name, oid, mode, kind)
            yield name, data, mode


def export_archive(root, output, files):
    output = pathlib.Path(output).resolve()
    # Keep generated releases out of source trees/indexes.
    if not output.is_relative_to(root / 'dist') or output.suffix != '.zip':
        raise RuntimeError('Export target must be a .zip inside the workspace dist directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.public-', suffix='.zip', dir=output.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data, _mode in files:
                info = zipfile.ZipInfo('nekopass/' + name)
                info.compress_type = zipfile.ZIP_DEFLATED
                executable = name.endswith('.sh') or name.startswith('.githooks/')
                info.external_attr = (0o100755 if executable else 0o100644) << 16
                archive.writestr(info, data.replace(b'\r\n', b'\n') if executable else data)
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print('Public source archive:', output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--staged', action='store_true', help='inspect the entire Git index')
    parser.add_argument('--history', action='store_true', help='inspect all reachable Git history')
    parser.add_argument('--export', metavar='DIST_ZIP', help='export inspected source only')
    args = parser.parse_args()
    root = args.root.resolve()
    if args.export and (args.staged or args.history):
        parser.error('Export uses the working source tree; run Git checks separately')
    try:
        files = list(indexed_files(root) if args.staged else history_files(root) if args.history else working_files(root))
        known = local_credentials(root)
        findings = sorted(set(f for name, data, mode in files for f in inspect(name, data, mode, known)))
        if findings:
            for name, line, category in findings:
                # Paths are JSON escaped too: no terminal control characters from filenames.
                print(json.dumps({'file': name, 'line': line, 'reason': category}, ensure_ascii=True), file=sys.stderr)
            print('BLOCKED: public-source check failed. No archive generated.', file=sys.stderr)
            return 1
        print(f'PASS: inspected {len(files)} source files; no detected credentials or private paths.')
        if args.export:
            export_archive(root, args.export, files)
        return 0
    except (RuntimeError, OSError, UnicodeError, ValueError):
        print('BLOCKED: cannot complete public-source check; inspect repository/files/tool availability.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
