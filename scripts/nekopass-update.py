#!/usr/bin/python3
"""Native service updates from hajidishu/nekopass GitHub Releases."""
import argparse
import fcntl
import json
import os
import pathlib
import platform
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

REPOSITORY = 'hajidishu/nekopass'
BASE = 'https://github.com/' + REPOSITORY + '/releases/download'
TAG = re.compile(r'^v([0-9]{1,8})\.([0-9]{1,8})\.([0-9]{1,8})$')
SERVICE = re.compile(r'^nekopass(?:-agent(?:-[a-z0-9]{1,16})?|-panel-[a-z0-9]{1,16})?$')


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('Download redirect must use HTTPS')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, target, limit=120 * 1024 * 1024):
    assert url.startswith('https://')
    if shutil.which('curl'):
        # Match the installer download path: retry transient GitHub/CDN stalls,
        # bound each attempt, and keep redirects restricted to HTTPS.
        run(['curl', '--fail', '--silent', '--show-error', '--location',
             '--proto', '=https', '--proto-redir', '=https', '--http1.1',
             '--connect-timeout', '15', '--max-time', '120', '--retry', '2',
             '--retry-all-errors', '--max-filesize', str(limit),
             '--output', str(target), '--url', url], stderr=subprocess.DEVNULL)
        if not target.is_file() or target.stat().st_size > limit:
            raise ValueError('Download exceeds size limit')
        return
    opener = urllib.request.build_opener(HTTPSRedirect())
    req = urllib.request.Request(url, headers={'User-Agent': 'Nekopass-Updater'})
    started = time.monotonic()
    with opener.open(req, timeout=30) as response, target.open('wb') as output:
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit or time.monotonic() - started > 300:
                raise ValueError('Download exceeds size or time limit')
            output.write(chunk)


def latest():
    req = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + '/releases/latest', headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'Nekopass-Updater'})
    with urllib.request.urlopen(req, timeout=15) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('Invalid release response')
    release = json.loads(data)
    version = release.get('tag_name', '')
    if not TAG.fullmatch(version) or release.get('draft') or release.get('prerelease'):
        raise ValueError('No stable release available')
    required = {'nekopass-agent-linux-amd64', 'nekopass-agent-linux-arm64', 'nekopass-panel-linux-amd64.tar.gz', 'nekopass-panel-linux-arm64.tar.gz', 'install-agent.sh', 'install-panel.sh'}
    found = {asset['name'] for asset in release.get('assets', []) if asset.get('browser_download_url') == BASE + '/' + version + '/' + asset.get('name', '')}
    if not required.issubset(found):
        raise ValueError('Release files are incomplete')
    return version


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def current(binary, agent):
    output = subprocess.check_output([str(binary), '-version'], text=True, timeout=15).strip().split()
    if len(output) != 3 or output[0] != ('nekopass-agent' if agent else 'nekopass'):
        raise ValueError('Invalid service binary')
    return output[1]


def read_request(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        import stat
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError('Update request must be a regular file')
        data = file.read(4097)
    if len(data) > 4096:
        raise ValueError('Update request too large')
    request = json.loads(data)
    if set(request) != {'generation', 'version'} or type(request['generation']) is not int or not 1 <= request['generation'] <= 2**63-1 or not TAG.fullmatch(request['version']):
        raise ValueError('Invalid update request')
    return request


def write_result(directory, service, request, state, error=''):
    account = service if service.startswith('nekopass-agent') else subprocess.check_output(['systemctl', 'show', service, '-p', 'User', '--value'], text=True).strip()
    owner = pwd.getpwnam(account)
    fd, name = tempfile.mkstemp(prefix='.update-result-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as file:
            json.dump({**request, 'state': state, 'error': error[:500]}, file)
            file.flush()
            os.fsync(file.fileno())
        os.chown(name, owner.pw_uid, owner.pw_gid)
        os.chmod(name, 0o600)
        os.replace(name, directory / 'update-result.json')
    finally:
        pathlib.Path(name).unlink(missing_ok=True)


def extract_panel(package, stage):
    with tarfile.open(package, 'r:gz') as archive:
        total = 0
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not member.isfile() or not (member.name in {'LICENSE', 'bin/nekopass', 'bin/nekopassctl', 'bin/nekopass-update'} or member.name.startswith('web/')):
                raise ValueError('Unexpected panel archive member')
            total += member.size
            if total > 200 * 1024 * 1024:
                raise ValueError('Panel archive too large')
            target = stage.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            # The root update unit uses UMask=0077, but migration runs as the
            # panel user and needs to traverse the staged executable directory.
            for directory in [target.parent, *target.parent.parents]:
                if directory == stage.parent:
                    break
                directory.chmod(0o755)
            with archive.extractfile(member) as source, target.open('wb') as dest:
                shutil.copyfileobj(source, dest)
            target.chmod(0o755 if path.parts[0] == 'bin' else 0o644)


def setup_panel_update(service):
    if service.startswith('nekopass-agent'):
        raise ValueError('Panel service required')
    base = pathlib.Path('/opt/nekopass' if service == 'nekopass' else '/opt/' + service)
    directory = pathlib.Path('/var/lib') / service
    if base.resolve() != base or directory.resolve() != directory:
        raise ValueError('Invalid installation directory')
    run(['systemctl', 'daemon-reload'])
    account = subprocess.check_output(['systemctl', 'show', service, '-p', 'User', '--value'], text=True).strip()
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', account):
        raise ValueError('Invalid service user')
    owner = pwd.getpwnam(account)
    directory.mkdir(mode=0o700, exist_ok=True)
    os.chown(directory, owner.pw_uid, owner.pw_gid)
    dropin = pathlib.Path('/etc/systemd/system') / (service + '.service.d')
    dropin.mkdir(mode=0o755, exist_ok=True)
    (dropin / 'update.conf').write_text('[Service]\nStateDirectory=' + service + '\nEnvironment=NEKOPASS_PANEL_UPDATE_DIR=' + str(directory) + '\n')
    updater_unit = pathlib.Path('/etc/systemd/system') / (service + '-update.service')
    updater_unit.write_text(f'''[Unit]
Description=Nekopass panel release updater
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/nekopassctl {'panel' if service == 'nekopass' else service} update
TimeoutStartSec=600
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={base} {directory} /run/lock /etc/systemd/system /usr/local/bin/nekopassctl
''')
    path_unit = pathlib.Path('/etc/systemd/system') / (service + '-update.path')
    path_unit.write_text(f'''[Unit]
Description=Watch Nekopass panel update requests
[Path]
PathExists={directory}/update-request.json
Unit={service}-update.service
[Install]
WantedBy=multi-user.target
''')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', service + '-update.path'])
    marker = directory / 'panel-update-ready'
    marker.write_text('systemd\n')
    marker.chmod(0o644)


def update(service, version):
    agent = service.startswith('nekopass-agent')
    base = pathlib.Path('/opt/nekopass' if service in {'nekopass', 'nekopass-agent'} else '/opt/' + service)
    binary = base / 'bin' / ('nekopass-agent' if agent else 'nekopass')
    if base.resolve() != base or binary.is_symlink() or not binary.is_file():
        raise ValueError('Installation directory is invalid')
    old = current(binary, agent)
    if TAG.fullmatch(old) and tuple(map(int, TAG.fullmatch(old).groups())) >= tuple(map(int, TAG.fullmatch(version).groups())):
        print('Already up to date:', old, flush=True)
        return
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise ValueError('Only Linux amd64/arm64 is supported')
    active = subprocess.run(['systemctl', 'is-active', '--quiet', service]).returncode == 0
    # Staging stays on the binary filesystem, allowing atomic rename.
    with tempfile.TemporaryDirectory(prefix='.update-', dir=base) as temp:
        stage = pathlib.Path(temp)
        stage.chmod(0o755)
        if agent:
            replacement = stage / 'agent'
            download(BASE + '/' + version + '/nekopass-agent-linux-' + arch, replacement)
        else:
            package = stage / 'panel.tar.gz'
            download(BASE + '/' + version + '/nekopass-panel-linux-' + arch + '.tar.gz', package)
            extract_panel(package, stage)
            replacement = stage / 'bin/nekopass'
        with replacement.open('rb') as file:
            if file.read(4) != b'\x7fELF':
                raise ValueError('Downloaded file is not a Linux executable')
        replacement.chmod(0o755)
        if current(replacement, agent) != version:
            raise ValueError('Downloaded binary version does not match release')
        backup = binary.with_name(binary.name + '.previous')
        shutil.copy2(binary, backup)
        print('Updating', service, old, '->', version, flush=True)
        if active:
            run(['systemctl', 'stop', service])
        installed = False
        try:
            if not agent:
                config = '/etc/nekopass/control.env' if service == 'nekopass' else '/etc/' + service + '/control.env'
                user = subprocess.check_output(['systemctl', 'show', service, '-p', 'User', '--value'], text=True).strip()
                if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
                    raise ValueError('Invalid service user')
                # systemd reads EnvironmentFile directly; no sourcing or credential output.
                run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '-p', 'User=' + user, '-p', 'EnvironmentFile=' + config, '--', str(replacement), '-mode', 'migrate'])
                shutil.copytree(stage / 'web', base / 'web', dirs_exist_ok=True)
            os.replace(replacement, binary)
            installed = True
            if not agent:
                for name in ['nekopassctl', 'nekopass-update']:
                    source = stage / 'bin' / name
                    if source.is_file():
                        target = pathlib.Path('/usr/local/bin/nekopassctl') if name == 'nekopassctl' else base / 'bin' / name
                        shutil.copy2(source, target)
                        target.chmod(0o755)
                run([str(base / 'bin/nekopass-update'), '--service', service, '--setup-panel'])
            if active:
                run(['systemctl', 'start', service])
                time.sleep(3)
                run(['systemctl', 'is-active', '--quiet', service])
        except Exception:
            if agent:
                run(['systemctl', 'stop', service], stdout=subprocess.DEVNULL)
                shutil.copy2(backup, binary)
                if active:
                    run(['systemctl', 'start', service])
            elif not installed and active:
                run(['systemctl', 'start', service])
            raise
        print('Update complete:', version, flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--service', required=True)
    p.add_argument('--version', default='latest')
    p.add_argument('--check', action='store_true')
    p.add_argument('--request', action='store_true')
    p.add_argument('--setup-panel', action='store_true', help=argparse.SUPPRESS)
    args = p.parse_args()
    if not SERVICE.fullmatch(args.service) or os.geteuid() != 0:
        p.error('Run as root with a valid Nekopass service')
    if args.setup_panel:
        setup_panel_update(args.service)
        return 0
    # Ordinary CLI updates also prepare/repair the bundled panel integration,
    # including when the installed binary already is the latest version.
    if not args.service.startswith('nekopass-agent') and not args.check and not args.request:
        setup_panel_update(args.service)
    lock = pathlib.Path('/run/lock') / (args.service + '-update.lock')
    with lock.open('w') as locked:
        fcntl.flock(locked, fcntl.LOCK_EX)
        directory = pathlib.Path('/var/lib') / args.service
        request = None
        try:
            if args.request:
                if directory.resolve() != directory:
                    raise ValueError('Invalid update state directory')
                name = directory / 'update-request.json'
                if not name.exists():
                    return
                request = read_request(name)
                name.unlink()
                write_result(directory, args.service, request, 'running')
                version = request['version']
            else:
                version = latest() if args.version == 'latest' else args.version
            if not TAG.fullmatch(version):
                raise ValueError('Invalid release version')
            if args.check:
                agent = args.service.startswith('nekopass-agent')
                base = '/opt/nekopass' if args.service in {'nekopass', 'nekopass-agent'} else '/opt/' + args.service
                installed = current(pathlib.Path(base) / 'bin' / ('nekopass-agent' if agent else 'nekopass'), agent)
                print('Current:', installed, '\nLatest:', version, '\nRelease: https://github.com/' + REPOSITORY + '/releases/tag/' + version)
                return
            update(args.service, version)
            if request:
                write_result(directory, args.service, request, 'completed')
        except Exception as error:
            # Never echo response bodies, EnvironmentFile or credentials.
            print('Update failed:', type(error).__name__, '; inspect the service log and network connection.', file=sys.stderr)
            if request:
                write_result(directory, args.service, request, 'failed', '更新失败，请查看更新服务日志和网络连接')
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
