"""Exercise the actual installer prompt in a PTY without installing anything."""
import errno
import os
import pathlib
import select
import signal
import subprocess
import sys
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux'), 'Requires Linux PTY')
class InstallerPromptTests(unittest.TestCase):
    def script(self, default, extra='', yes=False):
        source = (ROOT/'scripts/install-panel.sh').read_text()
        function = 'prompt() {' + source.split('\nprompt() {', 1)[1].split('\n}\n', 1)[0] + '\n}'
        # Test constants only; never evaluate user or credential content.
        return 'set -eu\nYES='+str(int(yes))+"\ndie() { printf 'ERROR\\n' >&2; exit 1; }\n" + function + "\nprompt HOST 'Address' '"+default+"'\nprintf '\\nRESULT:%s\\n' \"$HOST\"\n"+extra

    def interact(self, default, keys, tty_fallback=False):
        import pty
        pid, master = pty.fork()
        if pid == 0:
            if tty_fallback:
                # The controlling terminal remains available via /dev/tty.
                null = os.open('/dev/null', os.O_RDONLY)
                os.dup2(null, 0)
                os.close(null)
            os.execve('/bin/bash', ['bash', '--noprofile', '--norc', '-c', self.script(default)], {**os.environ, 'TERM': 'xterm-256color'})
        data = bytearray()
        sent = False
        end = time.monotonic()+8
        try:
            while time.monotonic()<end:
                if not select.select([master], [], [], .2)[0]:
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                data.extend(chunk)
                if not sent and b'Address' in data:
                    os.write(master, keys+b'\r')
                    sent = True
            else:
                self.fail('Installer prompt hung')
            _, status = os.waitpid(pid, 0)
            pid = 0
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertNotIn(b'^[[', data)
            return bytes(data).split(b'RESULT:', 1)[1].splitlines()[0].decode()
        finally:
            os.close(master)
            if pid:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

    def test_enter_preserves_default(self):
        self.assertEqual(self.interact('10.0.1.18', b''), '10.0.1.18')

    def test_arrow_and_delete_edit_default(self):
        # Left twice, forward-delete "1", insert "2", right, backspace "2", insert "3".
        keys=b'\x1b[D\x1b[D\x1b[3~2\x1b[C\x7f3'
        self.assertEqual(self.interact('10.0.1.18', keys), '10.0.1.23')

    def test_home_end_and_vertical_arrows(self):
        # Empty history must not insert arrow escape sequences into the value.
        keys=b'\x1b[A\x1b[B\x1b[H\x1b[3~2\x1b[F\x7f9'
        self.assertEqual(self.interact('10.0.1.18', keys), '20.0.1.19')

    def test_piped_stdin_uses_controlling_terminal(self):
        self.assertEqual(self.interact('8080', b'\x15' + b'9090', tty_fallback=True), '9090')

    def test_empty_input_falls_back_to_default(self):
        self.assertEqual(self.interact('8080', b'\x15'), '8080')

    def test_backslash_is_preserved(self):
        self.assertEqual(self.interact('', b'fixture\\path'), 'fixture\\path')

    def test_yes_does_not_read_stdin(self):
        result=subprocess.run(['bash', '-c', self.script('8080', "read -r remainder; printf 'UNREAD:%s\\n' \"$remainder\"\n", yes=True)],input='fixture-piped-input\n',capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0)
        self.assertIn('RESULT:8080',result.stdout)
        self.assertIn('UNREAD:fixture-piped-input',result.stdout)


if __name__ == '__main__':
    unittest.main()
