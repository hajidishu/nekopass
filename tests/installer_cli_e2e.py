"""Linux/root only: validate a bundled installer without creating panel data.

Arguments: packaged installer, Linux architecture Agent binary.
Uses an isolated service and an unreachable control endpoint; no real node key.
"""
import functools
import http.server
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading

SERVICE = 'nekopass-agent-clibundle'
CONFIG_DIR = pathlib.Path('/etc') / SERVICE
STATE_DIR = pathlib.Path('/var/lib') / SERVICE
BIN_DIR = pathlib.Path('/opt') / SERVICE
UNIT = pathlib.Path('/etc/systemd/system') / (SERVICE + '.service')
CA = '/etc/nekopass/tls/server.crt'


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def main():
    assert os.geteuid() == 0
    installer, binary = map(pathlib.Path, sys.argv[1:])
    assert not (installer.parent / 'nekopassctl.sh').exists(), 'Must exercise embedded payload'
    for path in [CONFIG_DIR, STATE_DIR, BIN_DIR, UNIT]:
        assert not path.exists(), 'Inspect existing fixture: ' + str(path)
    account_existed = subprocess.run(['id', '-u', SERVICE], capture_output=True).returncode == 0
    before = subprocess.check_output(['systemctl', 'show', 'nekopass.service', '-p', 'MainPID', '--value'])
    with tempfile.TemporaryDirectory(prefix='nekopass-cli-bundle-', dir='/var/tmp') as root:
        shutil.copyfile(binary, pathlib.Path(root) / 'agent')
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Quiet, directory=root))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(CA, '/etc/nekopass/tls/server.key')
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f'https://127.0.0.1:{server.server_port}/agent'
        args = ['bash', str(installer), '--service-name', SERVICE, '--server', 'http://127.0.0.1:1',
                '--token', 'cli-fixture-not-real-key', '--binary-url', url,
                '--panel-url', 'http://127.0.0.1:1']
        try:
            result = subprocess.run([*args, '--upgrade', '--no-start'], capture_output=True, text=True, timeout=180, env={**os.environ,'CURL_CA_BUNDLE':CA})
            assert result.returncode == 0, result.stdout + result.stderr
            cli = pathlib.Path('/usr/local/bin/nekopassctl')
            payload = installer.read_text().split("cat <<'NEKOPASS_MANAGER_PAYLOAD'\n", 1)[1].split('\nNEKOPASS_MANAGER_PAYLOAD\n', 1)[0] + '\n'
            assert cli.read_text() == payload and os.access(cli, os.X_OK)
            assert (CONFIG_DIR / 'agent.env').stat().st_mode & 0o777 == 0o600
            assert 'NEKOPASS_PANEL_URL=' not in (CONFIG_DIR / 'agent.env').read_text()
            assert 'ConditionPathExists=' + str(CONFIG_DIR / 'agent.env') in UNIT.read_text()
            enabled = subprocess.run(['systemctl', 'is-enabled', SERVICE], capture_output=True, text=True)
            assert enabled.stdout.strip() == 'disabled'
            original_env = (CONFIG_DIR / 'agent.env').read_bytes()
            result = subprocess.run([*args, '--upgrade'], capture_output=True, text=True, timeout=180, env={**os.environ,'CURL_CA_BUNDLE':CA})
            assert result.returncode == 0, result.stdout + result.stderr
            assert (CONFIG_DIR / 'agent.env').read_bytes() == original_env
            assert (STATE_DIR / 'state.db').exists()
            assert 'NEKOPASS_CA=' not in (CONFIG_DIR/'agent.env').read_text()
            assert 'NEKOPASS_PANEL_URL=' not in (CONFIG_DIR/'agent.env').read_text()
            assert subprocess.check_output(['systemctl', 'is-enabled', SERVICE], text=True).strip() == 'enabled'
            assert subprocess.check_output(['systemctl', 'is-active', SERVICE], text=True).strip() == 'active'
            assert subprocess.check_output(['systemctl', 'is-active', SERVICE+'-update.path'], text=True).strip() == 'active'
            assert (BIN_DIR/'bin/nekopass-update').is_file()
            assert subprocess.check_output(['systemctl', 'show', 'nekopass.service', '-p', 'MainPID', '--value']) == before
            assert not list(STATE_DIR.glob('state.db.before-reconfigure-*'))
            subprocess.run(['systemctl', 'stop', SERVICE], check=True)
            original_state = (STATE_DIR/'state.db').read_bytes()
            # New credentials/controller must not reuse old cached policies.
            # Archive the old database and create fresh recoverable state.
            modified = [*args, '--server', 'http://127.0.0.1:2', '--token', 'fixture-replacement-node-key']
            result = subprocess.run(modified, capture_output=True, text=True, timeout=180, env={**os.environ,'CURL_CA_BUNDLE':CA})
            assert result.returncode == 0, result.stdout + result.stderr
            updated = (CONFIG_DIR/'agent.env').read_text()
            assert 'NEKOPASS_SERVER=http://127.0.0.1:2' in updated
            assert 'NEKOPASS_NODE_TOKEN=fixture-replacement-node-key' in updated
            assert 'NEKOPASS_PANEL_URL=' not in updated and 'NEKOPASS_CA=' not in updated
            assert (STATE_DIR/'state.db').exists()
            backups = list(STATE_DIR.glob('state.db.before-reconfigure-*'))
            assert len(backups) == 1 and backups[0].read_bytes() == original_state
            assert (STATE_DIR/'state.db').read_bytes() != original_state
            print('PASS automatic fresh/reinstall, legacy upgrade compatibility, config overwrite, archived old state and native service startup')
        finally:
            server.shutdown()
            server.server_close()
            subprocess.run(['systemctl', 'disable', '--now', SERVICE], capture_output=True)
            subprocess.run(['systemctl', 'disable', '--now', SERVICE+'-update.path'], capture_output=True)
            subprocess.run(['systemctl', 'stop', SERVICE+'-update.service'], capture_output=True)
            for suffix in ['-update.path','-update.service']:
                pathlib.Path('/etc/systemd/system',SERVICE+suffix).unlink(missing_ok=True)
            UNIT.unlink(missing_ok=True)
            for path in [CONFIG_DIR, STATE_DIR, BIN_DIR]:
                assert path.name == SERVICE
                if path.exists():
                    shutil.rmtree(path)
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            if not account_existed:
                subprocess.run(['userdel', SERVICE], capture_output=True)
    print('Installer CLI E2E passed; isolated fixture removed')


if __name__ == '__main__':
    main()
