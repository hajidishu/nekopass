"""Start the actual panel after migration, using an explicitly isolated database."""
import argparse
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    binary = pathlib.Path(args.binary).resolve()
    database = os.environ.get('NEKOPASS_TEST_DATABASE_URL', '')
    parsed = urllib.parse.urlsplit(database)
    if parsed.scheme not in ('postgres', 'postgresql') or not parsed.path.removeprefix('/').endswith('_test'):
        raise RuntimeError('NEKOPASS_TEST_DATABASE_URL must name an isolated *_test database')
    env = os.environ.copy()
    env['NEKOPASS_DATABASE_URL'] = database
    for name in ['NEKOPASS_TLS_CERT', 'NEKOPASS_TLS_KEY', 'NEKOPASS_GRPC_TLS_CERT', 'NEKOPASS_GRPC_TLS_KEY', 'NEKOPASS_TRUSTED_PROXIES']:
        env.pop(name, None)
    subprocess.run([str(binary), '-mode', 'migrate'], env=env, check=True, timeout=30)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='nekopass-startup-test-') as directory, tempfile.TemporaryFile() as logs:
        child = subprocess.Popen([str(binary), '-http', '127.0.0.1:' + str(port), '-grpc', '127.0.0.1:0', '-web', directory], env=env, stdout=logs, stderr=logs)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise RuntimeError('Panel exited before becoming healthy after migration')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:' + str(port) + '/healthz', timeout=1) as response:
                        assert response.status == 200 and json.load(response)['status'] == 'ok'
                    break
                except urllib.error.URLError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('Panel startup health check timed out')
            child.terminate()
            if child.wait(timeout=5) != 0:
                raise RuntimeError('Panel did not shut down cleanly')
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    print('PASS migrated schema accepted by actual panel; HTTP health and graceful shutdown')


if __name__ == '__main__':
    main()
