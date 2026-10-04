"""Linux/root: install an isolated panel, exercise recovery and node CA bootstrap.

Requires unpacked release fixtures at /var/tmp/nekopass-panel-install-e2e.
Never installs over the normal panel or resets its administrator password.
"""
import functools
import http.cookiejar
import http.server
import json
import os
import pathlib
import pty
import re
import shutil
import ssl
import subprocess
import threading
import tarfile
import io
import urllib.error
import urllib.request

ROOT = pathlib.Path('/var/tmp/nekopass-panel-install-e2e')
SERVICE = 'nekopass-panel-installtest'
AGENT = 'nekopass-agent-paneltest'
CONFIG = pathlib.Path('/etc')/SERVICE
BASE = 'http://127.0.0.1:28080'
DB_PORT = os.environ.get('NEKOPASS_INSTALL_TEST_DB_PORT','5432')
PG_VERSION = os.environ.get('NEKOPASS_INSTALL_TEST_PG_VERSION','17')

def run(args, *, expected=True, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=240, **kwargs)
    if (result.returncode == 0) != expected:
        # Captured installer output contains generated passwords: keep it private.
        log=ROOT/'failure.log'
        log.write_text(result.stdout+result.stderr)
        log.chmod(0o600)
        raise AssertionError('Command result unexpected; private diagnostic saved in fixture directory')
    return result

def sql(query, database='postgres'):
    return run(['runuser','-u','postgres','--','psql','-p',DB_PORT,'-d',database,'-XAtqc',query]).stdout.strip()

def opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def api(client, path, data=None, *, expected=200):
    request=urllib.request.Request(BASE+'/api/v1/'+path,
        data=None if data is None else json.dumps(data).encode(),
        headers={'Content-Type':'application/json'})
    try:
        with client.open(request,timeout=15) as response:
            assert response.status == expected
            return json.load(response)
    except urllib.error.HTTPError as error:
        assert error.code == expected, 'Unexpected API status'
        return None

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self,*args): pass

def cleanup():
    for service in [AGENT,SERVICE]:
        subprocess.run(['systemctl','disable','--now',service],capture_output=True)
        subprocess.run(['systemctl','reset-failed',service],capture_output=True)
        (pathlib.Path('/etc/systemd/system')/(service+'.service')).unlink(missing_ok=True)
    run(['runuser','-u','postgres','--','dropdb','-p',DB_PORT,'--if-exists',SERVICE])
    run(['runuser','-u','postgres','--','dropuser','-p',DB_PORT,'--if-exists',SERVICE])
    for service in [AGENT,SERVICE]:
        for parent in ['/opt','/etc','/var/lib']:
            path=pathlib.Path(parent)/service
            assert path.parent==pathlib.Path(parent) and path.name in [AGENT,SERVICE]
            if path.exists(): shutil.rmtree(path)
        subprocess.run(['userdel',service],capture_output=True)
        subprocess.run(['groupdel',service],capture_output=True)
    run(['systemctl','daemon-reload'])

def main():
    assert os.geteuid()==0 and pathlib.Path('/run/systemd/system').is_dir()
    assert ROOT.is_dir()
    for service in [SERVICE,AGENT]:
        assert not (pathlib.Path('/etc')/service).exists()
        assert not (pathlib.Path('/etc/systemd/system')/(service+'.service')).exists()
    assert sql("SELECT count(*) FROM pg_database WHERE datname='"+SERVICE+"'")=='0'
    production=sql("SELECT json_build_object('users',(SELECT count(*) FROM users),'plans',(SELECT count(*) FROM plans),'nodes',(SELECT json_agg(json_build_array(id,token_hash,token)) FROM nodes),'settings',(SELECT config FROM site_settings WHERE id=1),'balance',(SELECT sum(balance_cents) FROM wallet_accounts))",'nekopass')
    previous_cli=pathlib.Path('/usr/local/bin/nekopassctl').read_bytes()
    server=None
    try:
        # A privileged installer must reject both escaping paths and symlinks.
        for member_name,link in [('../../nekopass-panel-traversal-marker',False),('bin/escape',True)]:
            invalid=ROOT/'invalid.tar.gz'
            with tarfile.open(invalid,'w:gz') as archive:
                info=tarfile.TarInfo(member_name)
                if link:info.type=tarfile.SYMTYPE;info.linkname='/etc'
                else:info.size=1
                archive.addfile(info,None if link else io.BytesIO(b'x'))
            run(['bash',str(ROOT/'install-panel.sh'),'--package',str(invalid),
                 '--service-name',SERVICE,'--host','127.0.0.1','--yes','--skip-dependencies'],expected=False)
            assert not CONFIG.exists()
            assert not pathlib.Path('/var/tmp/nekopass-panel-traversal-marker').exists()
        invalid.unlink()
        # Real interactive input via a tty; all defaults below are isolated flags.
        master,slave=pty.openpty()
        try:
            os.write(master,b'\n'*11)
            installed=run(['bash',str(ROOT/'install-panel.sh'),'--package',str(ROOT/'panel.tar.gz'),
                '--service-name',SERVICE,'--host','127.0.0.1','--http-port','28080','--grpc-port','29443',
                '--postgres-version',PG_VERSION,'--db-port',DB_PORT,'--skip-dependencies','--firewall','skip',
                '--agent-installer','https://127.0.0.1:28443/install-agent.sh',
                '--agent-releases','https://127.0.0.1:28443/releases'],stdin=slave)
        finally:
            os.close(slave);os.close(master)
        password=re.search(r'管理员密码：([^\s]+)',installed.stdout).group(1)
        assert len(password)==32
        assert '可用 PostgreSQL 版本' in installed.stdout
        assert '安装完成' in installed.stdout
        assert run(['systemctl','is-enabled',SERVICE]).stdout.strip()=='enabled'
        assert CONFIG.joinpath('control.env').stat().st_mode&0o777==0o600
        assert CONFIG.joinpath('tls/server.key').stat().st_mode&0o777==0o640
        cert_text=CONFIG.joinpath('tls/ca.crt').read_text()
        assert 'PRIVATE' not in cert_text
        client=opener()
        api(client,'login',{'username':'admin','password':password})
        settings=api(client,'admin/settings')['settings']
        assert settings['panel_url']==BASE and settings['agent_port']==29443
        assert api(client,'admin/users')
        page=client.open(BASE+'/admin/nodes',timeout=15)
        assert page.status==200 and b'<html' in page.read()
        # A second installation must fail before overwriting identities/configuration.
        original_env=CONFIG.joinpath('control.env').read_bytes()
        run(['bash',str(ROOT/'install-panel.sh'),'--package',str(ROOT/'panel.tar.gz'),
             '--service-name',SERVICE,'--yes','--skip-dependencies'],expected=False)
        assert CONFIG.joinpath('control.env').read_bytes()==original_env
        reset=run(['/usr/local/bin/nekopassctl',SERVICE,'reset-password'],input='admin\n')
        new_password=re.search(r'新的管理员密码：([^\s]+)',reset.stdout).group(1)
        assert new_password!=password and len(new_password)==32
        api(client,'admin/users',expected=401)
        api(opener(),'login',{'username':'admin','password':password},expected=401)
        client=opener();api(client,'login',{'username':'admin','password':new_password})
        node=api(client,'admin/nodes',{'name':'panel-install-node'})
        command=api(client,'admin/nodes/'+str(node['id'])+'/install-command',{})
        ticket=re.search(r"'--install-token' '([a-f0-9]{64})'",command['command']).group(1)
        # Use a private, verified HTTPS fixture for downloads, not a public OSS.
        handler=functools.partial(Quiet,directory=str(ROOT/'downloads'))
        server=http.server.ThreadingHTTPServer(('127.0.0.1',28443),handler)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(CONFIG/'tls/server.crt',CONFIG/'tls/server.key')
        server.socket=tls.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        run(['bash',str(ROOT/'downloads/install-agent.sh'),'--service-name',AGENT,
             '--panel-url',BASE,'--install-token',ticket,'--ca-file',str(CONFIG/'tls/ca.crt')])
        agent_env=(pathlib.Path('/etc')/AGENT/'agent.env').read_text()
        assert 'NEKOPASS_CA=' in agent_env
        ca=(pathlib.Path('/etc')/AGENT/'tls/ca.crt').read_text()
        assert ca==cert_text
        import time
        online=False
        for _ in range(20):
            nodes=api(client,'admin/nodes')
            if any(n['id']==node['id'] and n['online'] for n in nodes):online=True;break
            time.sleep(1)
        assert online, 'Installed Agent did not connect with generated control certificate'
        assert sql("SELECT json_build_object('users',(SELECT count(*) FROM users),'plans',(SELECT count(*) FROM plans),'nodes',(SELECT json_agg(json_build_array(id,token_hash,token)) FROM nodes),'settings',(SELECT config FROM site_settings WHERE id=1),'balance',(SELECT sum(balance_cents) FROM wallet_accounts))",'nekopass')==production
        print('PASS interactive install, PostgreSQL selection, systemd/autostart, HTTP UI, random admin, password recovery/session revocation, existing-install protection and real Agent CA bootstrap; production unchanged')
    finally:
        if server:server.shutdown();server.server_close()
        cleanup()
        pathlib.Path('/usr/local/bin/nekopassctl').write_bytes(previous_cli)
        print('Isolated panel/Agent services, databases, accounts and state removed')

if __name__=='__main__': main()
