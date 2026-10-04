"""Linux/root only. Exercise nekopassctl using a disposable systemd sleep service.

Does not restart or configure the real panel/Agent, nor create panel records.
"""
import os
import pathlib
import shutil
import signal
import subprocess
import time

SERVICE = 'nekopass-agent-clitest'
CONFIG_DIR = pathlib.Path('/etc') / SERVICE
CONFIG = CONFIG_DIR / 'agent.env'
UNIT = pathlib.Path('/etc/systemd/system') / (SERVICE + '.service')
CLI = os.environ.get('NEKOPASS_CLI', '/usr/local/bin/nekopassctl')


def call(*args, ok=True, stdin=None):
    result = subprocess.run([CLI, SERVICE, *args], input=stdin, capture_output=True,
                            text=True, timeout=20)
    assert (result.returncode == 0) == ok, (args, result.stdout, result.stderr)
    return result


def systemctl(*args):
    result = subprocess.run(['systemctl', *args], capture_output=True, text=True)
    assert result.returncode == 0 or args[0] == 'is-enabled', result.stderr
    return result.stdout.strip()


def main():
    assert os.geteuid() == 0 and pathlib.Path('/run/systemd/system').exists()
    assert not UNIT.exists() and not CONFIG_DIR.exists(), 'Inspect existing fixture first'
    CONFIG_DIR.mkdir(mode=0o755)
    UNIT.write_text(f'''[Unit]
Description=Nekopass disposable CLI test
ConditionPathExists={CONFIG}
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
''')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    try:
        missing = call('start', ok=False)
        assert '配置' in missing.stderr
        call('enable')
        assert systemctl('is-enabled', SERVICE) == 'enabled'
        subprocess.run(['systemctl', 'start', SERVICE], check=True)
        assert systemctl('show', SERVICE, '-p', 'ActiveState', '--value') == 'inactive'
        bad = call('configure', ok=False, stdin='localhost:70000\n')
        assert '端口' in bad.stderr and not CONFIG.exists()
        call('configure', stdin='localhost:9443\nclitest-token-1234\n\n')
        assert CONFIG.stat().st_mode & 0o777 == 0o600
        assert 'NEKOPASS_NODE_TOKEN=clitest-token-1234' in CONFIG.read_text()
        CONFIG.write_text(CONFIG.read_text() + 'EXTRA_SETTING=keep-me\n')
        call('configure', stdin='localhost:9444\nclitest-token-1234\n\n')
        assert 'EXTRA_SETTING=keep-me' in CONFIG.read_text()
        assert list(CONFIG_DIR.glob('agent.env.bak.*'))
        call('start')
        first_pid = systemctl('show', SERVICE, '-p', 'MainPID', '--value')
        assert int(first_pid) > 0
        call('status')
        call('restart')
        assert systemctl('show', SERVICE, '-p', 'MainPID', '--value') != first_pid
        call('logs')
        # Non-interactive editor invocation must preserve permissions and backup.
        edited = subprocess.run([CLI, SERVICE, 'edit'], env={**os.environ, 'EDITOR': 'true'},
                                capture_output=True, text=True, timeout=20)
        assert edited.returncode == 0
        assert CONFIG.stat().st_mode & 0o777 == 0o600
        call('disable')
        assert systemctl('is-enabled', SERVICE) == 'disabled'
        assert systemctl('is-active', SERVICE) == 'active', 'disable must not stop service'
        # Ctrl+C during live logs should return to the service menu.
        menu = subprocess.Popen([CLI, SERVICE], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        try:
            menu.stdin.write('8\n')
            menu.stdin.flush()
            time.sleep(1)
            os.killpg(menu.pid, signal.SIGINT)
            time.sleep(0.5)
            out, err = menu.communicate('0\n', timeout=10)
            assert menu.returncode == 0 and out.count('请选择：') >= 2, (out, err)
        finally:
            if menu.poll() is None:
                os.killpg(menu.pid, signal.SIGKILL)
                menu.wait()
        call('stop')
        assert systemctl('show', SERVICE, '-p', 'ActiveState', '--value') == 'inactive'
        call('status', ok=False)
        print('PASS start/stop/restart/status, boot enable/disable, logs, menu Ctrl+C, config/backup/permissions')
    finally:
        subprocess.run(['systemctl', 'disable', '--now', SERVICE], capture_output=True)
        UNIT.unlink(missing_ok=True)
        assert CONFIG_DIR.name == SERVICE
        shutil.rmtree(CONFIG_DIR)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
    print('CLI E2E passed; isolated fixture removed')


if __name__ == '__main__':
    main()
