"""CLI tests for win2nix (plan section 9, items 15-27).

Every test drives ``win2nix.main([...])`` on fixtures built in a TemporaryDirectory; stdout/stderr
are captured and the interactive terminal is simulated by patching ``Console.open``.
"""
import calendar
import contextlib
import errno
import hashlib
import io
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
import win2nix  # noqa: E402

EXAMPLE_DIR = os.path.join(PROJECT, 'example')
ORIG_OPEN = win2nix.Console.open
BAK = win2nix.BACKUP_SUFFIX
TMP_PREFIX = win2nix.TMP_PREFIX
T2001_NS = calendar.timegm((2001, 1, 1, 0, 0, 0)) * 10 ** 9

# >= 8 Russian words: detected as `sure` in any of the three 8-bit encodings
SURE_RU = ('Сегодня утром мы долго обсуждали план работы на следующую неделю.\n'
           'Нужно закончить отчёт, проверить документы и отправить письмо заказчику.\n'
           'Потом поедем на дачу, если погода будет хорошая.\n')
UNSURE_RU = 'ёж\n'              # two letters in cp866: level unsure, 8-bit codec -> backup
UNSURE_RU2 = 'ёжик и ёлка\n'    # cp866, unsure as well (used as the "edited" content)
LATIN1 = 'café et thé, déjà vu, naïve, Noël\n'
BINARY = b'\x00\x01binary\r\n'


class FakeTTY:
    """Scripted /dev/tty: readline() returns the next answer, '' (EOF) once the script runs out."""

    def __init__(self, answers=()):
        self.answers = list(answers)
        self.written = []

    def write(self, s):
        self.written.append(s)

    def flush(self):
        pass

    def close(self):
        pass

    def readline(self):
        return self.answers.pop(0) + '\n' if self.answers else ''

    @property
    def prompts(self):
        return [s for s in self.written if s.startswith('overwrite ')]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CLICase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix='w2n-test-')
        self.tmp = self._td.name
        self._cwd = os.getcwd()

    def tearDown(self):
        win2nix.Console.open = ORIG_OPEN
        os.chdir(self._cwd)
        self._td.cleanup()

    # ---- fixtures -------------------------------------------------------------------------
    def mk(self, name, text, enc, eol='\r\n', bom=False, ctrlz=False):
        """Write `text` (LF-separated) as `enc` with `eol`; return (path, expected UTF-8 LF bytes)."""
        path = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = text.replace('\n', eol).encode(enc)
        if bom:
            data = b'\xef\xbb\xbf' + data
        if ctrlz:
            data += b'\x1a'
        self.write(path, data)
        return path, text.encode('utf-8')

    @staticmethod
    def read(path) -> bytes:
        with open(path, 'rb') as f:
            return f.read()

    @staticmethod
    def write(path, data: bytes):
        with open(path, 'wb') as f:
            f.write(data)

    def names(self, d=None):
        return sorted(os.listdir(d or self.tmp))

    def backups(self, d=None):
        return [n for n in self.names(d) if win2nix.BACKUP_RE.search(n)]

    def temps(self, d=None):
        return [n for n in self.names(d) if n.startswith(TMP_PREFIX)]

    @staticmethod
    def tree_hashes(root):
        out = {}
        for dirpath, _dirs, files in os.walk(root):
            for n in files:
                p = os.path.join(dirpath, n)
                with open(p, 'rb') as f:
                    out[os.path.relpath(p, root)] = sha256(f.read())
        return out

    # ---- driver ----------------------------------------------------------------------------
    def run_cli(self, *args, tty=None):
        """Run win2nix.main(args) with the terminal replaced by `tty` (None = no /dev/tty)."""
        win2nix.Console.open = lambda console: setattr(console, 'tty', tty)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = win2nix.main(list(args))
            except SystemExit as e:        # argparse usage errors
                code = e.code
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def action_of(out, name):
        """The `-> action` part of the report line for the file whose display path ends with `name`."""
        for line in out.splitlines():
            head, sep, action = line.partition(' -> ')
            if sep and head.split(':')[0].endswith(name):
                return action.split('  ', 1)[0]        # drop the `-v` details block
        return None


class InPlaceTests(CLICase):
    def test_inplace_sure_no_backup(self):                                              # 15
        path, expected = self.mk('notes.txt', SURE_RU, 'cp1251')
        os.chmod(path, 0o640)
        os.utime(path, ns=(T2001_NS, T2001_NS))
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path), expected)
        st = os.stat(path)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o640)
        self.assertEqual(st.st_mtime_ns, T2001_NS)
        self.assertEqual(self.backups(), [])
        self.assertIn(f'{path}: cp1251 crlf={SURE_RU.count(chr(10))} -> converted', out)
        self.assertNotIn('backup', out)
        self.assertIn('win2nix: 1 file: 1 converted', out)

    def test_inplace_unsure_backup(self):                                               # 16
        path, _ = self.mk('short.txt', UNSURE_RU, 'cp866')
        orig = self.read(path)
        os.utime(path, ns=(T2001_NS, T2001_NS))
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 0, err)
        bak = path + BAK
        self.assertEqual(self.read(bak), orig)
        self.assertEqual(os.stat(bak).st_mtime_ns, T2001_NS)
        new = self.read(path)
        self.assertNotEqual(new, orig)
        self.assertNotIn(b'\r', new)
        new.decode('utf-8')
        self.assertRegex(out, rf'{re.escape(path)}: \S+\? crlf=1 -> converted, backup: {re.escape(bak)}')
        self.assertIn('1 converted (1 with backup)', out)
        # second run after editing the file -> .w2n.1.bak
        edited = UNSURE_RU2.replace('\n', '\r\n').encode('cp866')
        self.write(path, edited)
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path + '.w2n.1.bak'), edited)
        self.assertEqual(self.read(bak), orig)
        self.assertIn(f'backup: {path}.w2n.1.bak', out)
        # same content as the first backup -> that backup is reused
        self.write(path, orig)
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 0, err)
        self.assertIn(f'backup: {bak}', out)
        self.assertEqual(self.backups(), ['short.txt.w2n.1.bak', 'short.txt.w2n.bak'])
        # UTF-8 with a single 'é' and CRLF: unsure label, converted, no backup
        path2, exp2 = self.mk('cafe.txt', 'café au lait\nsecond line\n', 'utf-8')
        code, out, err = self.run_cli(path2)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path2), exp2)
        self.assertIn(f'{path2}: utf-8? crlf=2 -> converted', out)
        self.assertNotIn('backup', out)
        self.assertFalse(os.path.exists(path2 + BAK))

    def test_backup_flags(self):                                                        # 17
        path, expected = self.mk('sure.txt', SURE_RU, 'cp1251')
        orig = self.read(path)
        code, out, err = self.run_cli('-b', path)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path), expected)
        self.assertEqual(self.read(path + BAK), orig)
        self.assertIn(f'backup: {path}{BAK}', out)

        path2, _ = self.mk('short.txt', UNSURE_RU, 'cp866')
        orig2 = self.read(path2)
        code, out, err = self.run_cli('-B', path2)
        self.assertEqual(code, 0, err)
        self.assertNotEqual(self.read(path2), orig2)
        self.assertFalse(os.path.exists(path2 + BAK))
        self.assertNotIn('backup', out)

        path3, _ = self.mk('x.txt', SURE_RU, 'cp1251')
        orig3 = self.read(path3)
        code, out, err = self.run_cli('-b', '-B', path3)
        self.assertEqual(code, 2)
        self.assertEqual(self.read(path3), orig3)

        # ENOSPC while writing the backup: error, original intact, no partial backup
        path4, _ = self.mk('u.txt', UNSURE_RU, 'cp866')
        orig4 = self.read(path4)
        with mock.patch('os.fsync', side_effect=OSError(errno.ENOSPC, 'No space left on device')):
            code, out, err = self.run_cli(path4)
        self.assertEqual(code, 3)
        self.assertIn('No space left on device', self.action_of(out, 'u.txt'))
        self.assertEqual(self.read(path4), orig4)
        self.assertEqual([n for n in self.names() if n.startswith('u.txt.')], [])
        self.assertEqual(self.temps(), [])

    def test_idempotent(self):                                                          # 18
        d = os.path.join(self.tmp, 'd')
        self.mk('d/sure.txt', SURE_RU, 'cp1251')
        p2, _ = self.mk('d/short.txt', UNSURE_RU, 'cp866')
        self.mk('d/plain.txt', 'plain ascii\n', 'ascii', eol='\n')
        code, out, err = self.run_cli(d)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.backups(d), ['short.txt.w2n.bak'])
        mtimes = {n: os.stat(os.path.join(d, n)).st_mtime_ns for n in self.names(d)}

        code, out, err = self.run_cli('-v', d)
        self.assertEqual(code, 0, err)
        for n in ('sure.txt', 'short.txt', 'plain.txt'):
            self.assertEqual(self.action_of(out, n), 'ok', out)
        self.assertIn('skipped: backup file', self.action_of(out, 'short.txt.w2n.bak'))
        self.assertEqual({n: os.stat(os.path.join(d, n)).st_mtime_ns for n in self.names(d)}, mtimes)
        self.assertEqual(self.backups(d), ['short.txt.w2n.bak'])
        self.assertIn('3 ok, 1 backup file skipped', out)

        # `win2nix *` after the first run: backup names given explicitly are skipped
        code, out, err = self.run_cli(*[os.path.join(d, n) for n in self.names(d)])
        self.assertEqual(code, 0, err)
        self.assertIn('skipped: backup file', self.action_of(out, 'short.txt.w2n.bak'))
        self.assertEqual(self.read(p2 + BAK), UNSURE_RU.replace('\n', '\r\n').encode('cp866'))
        self.assertEqual({n: os.stat(os.path.join(d, n)).st_mtime_ns for n in self.names(d)}, mtimes)

    def test_unknown_skip(self):                                                        # 19
        path, _ = self.mk('fr.txt', LATIN1, 'latin-1')
        orig = self.read(path)
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 3)
        self.assertEqual(self.read(path), orig)
        action = self.action_of(out, 'fr.txt')
        self.assertIn('skipped: unknown encoding', action)
        self.assertIn('--from', action)
        self.assertEqual(self.backups(), [])
        self.assertIn('1 unknown encoding', out)


class DirectoryWalkTests(CLICase):                                                      # 20
    def build_tree(self):
        d = os.path.join(self.tmp, 'd')
        self.mk('d/text.txt', SURE_RU, 'cp1251')
        self.mk('d/sub/file.txt', SURE_RU, 'cp1251')
        self.mk('d/.git/config', SURE_RU, 'cp1251')
        self.mk('d/old.txt.w2n.bak', SURE_RU, 'cp1251')
        self.mk('d/.w2n-tmp-x', SURE_RU, 'cp1251')
        self.write(os.path.join(d, 'bin.dat'), BINARY)
        target, _ = self.mk('outside/target.txt', SURE_RU, 'cp1251')
        link = os.path.join(d, 'link.txt')
        os.symlink(target, link)
        return d, target, link

    def untouched(self, *paths):
        orig = SURE_RU.replace('\n', '\r\n').encode('cp1251')
        for p in paths:
            self.assertEqual(self.read(p), orig, p)

    def test_directory_walk_flat(self):
        d, target, link = self.build_tree()
        code, out, err = self.run_cli(d)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(os.path.join(d, 'text.txt')), SURE_RU.encode('utf-8'))
        self.untouched(target, os.path.join(d, 'sub', 'file.txt'), os.path.join(d, '.git', 'config'),
                       os.path.join(d, 'old.txt.w2n.bak'), os.path.join(d, '.w2n-tmp-x'))
        self.assertEqual(self.read(os.path.join(d, 'bin.dat')), BINARY)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(self.action_of(out, 'text.txt'), 'converted')
        self.assertIn('skipped: binary (NUL at byte 0)', self.action_of(out, 'bin.dat'))
        self.assertIn('skipped: symlink', self.action_of(out, 'link.txt'))
        self.assertIn('skipped: backup file', self.action_of(out, 'old.txt.w2n.bak'))
        self.assertIn('skipped: stale temp file', self.action_of(out, '.w2n-tmp-x'))
        self.assertIsNone(self.action_of(out, 'file.txt'))
        self.assertIn('subdirectory skipped (use -r)', out)
        self.assertEqual(self.backups(d), ['old.txt.w2n.bak'])

    def test_directory_walk_recursive(self):
        d, target, link = self.build_tree()
        code, out, err = self.run_cli('-r', d)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(os.path.join(d, 'text.txt')), SURE_RU.encode('utf-8'))
        self.assertEqual(self.read(os.path.join(d, 'sub', 'file.txt')), SURE_RU.encode('utf-8'))
        self.untouched(target, os.path.join(d, '.git', 'config'),
                       os.path.join(d, 'old.txt.w2n.bak'), os.path.join(d, '.w2n-tmp-x'))
        self.assertEqual(self.action_of(out, os.path.join('sub', 'file.txt')), 'converted')
        self.assertIsNone(self.action_of(out, 'config'))
        self.assertIn('skipped: symlink', self.action_of(out, 'link.txt'))
        self.assertIn('VCS directory skipped', out)
        self.assertIn('2 converted', out)

    def test_symlink_explicit(self):
        d, target, link = self.build_tree()
        code, out, err = self.run_cli(link)
        self.assertEqual(code, 0, err)
        self.assertIn('skipped: symlink', self.action_of(out, 'link.txt'))
        self.assertTrue(os.path.islink(link))
        self.untouched(target)
        self.assertIn('1 symlink skipped', out)

    def test_duplicate_inputs(self):
        self.mk('a.txt', SURE_RU, 'cp1251')
        os.chdir(self.tmp)
        code, out, err = self.run_cli('a.txt', './a.txt')
        self.assertEqual(code, 0, err)
        self.assertEqual(out.count(' -> '), 1)
        self.assertIn('win2nix: 1 file: 1 converted', out)
        self.assertIn('duplicate', err)
        self.assertEqual(self.read('a.txt'), SURE_RU.encode('utf-8'))

    def test_relative_unsure_from_cwd(self):
        self.mk('rel.txt', UNSURE_RU, 'cp866')
        orig = self.read(os.path.join(self.tmp, 'rel.txt'))
        os.chdir(self.tmp)
        code, out, err = self.run_cli('rel.txt')
        self.assertEqual(code, 0, err)
        self.assertNotEqual(self.read('rel.txt'), orig)
        self.assertEqual(self.read('rel.txt' + BAK), orig)
        self.assertRegex(out, re.compile(r'^rel\.txt: \S+\? crlf=1 -> converted, backup: .*rel\.txt\.w2n\.bak$', re.M))


class OutputDirTests(CLICase):                                                          # 21
    def build_src(self):
        src = os.path.join(self.tmp, 'src')
        _, ex = self.mk('src/x.txt', SURE_RU, 'cp1251')
        _, ey = self.mk('src/sub/y.txt', SURE_RU, 'cp1251')
        self.mk('src/readme.txt', 'plain\n', 'ascii', eol='\n')
        self.write(os.path.join(src, 'bin.dat'), BINARY)
        return src, ex, ey

    def test_output_dir_mirror(self):
        src, ex, ey = self.build_src()
        before = self.tree_hashes(src)
        out_dir = os.path.join(self.tmp, 'out')
        code, out, err = self.run_cli('-v', '-o', out_dir + '/', '-r', src)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(os.path.join(out_dir, 'x.txt')), ex)
        self.assertEqual(self.read(os.path.join(out_dir, 'sub', 'y.txt')), ey)
        self.assertEqual(self.read(os.path.join(out_dir, 'readme.txt')), b'plain\n')
        self.assertFalse(os.path.exists(os.path.join(out_dir, 'bin.dat')))
        self.assertEqual(self.tree_hashes(src), before)
        self.assertEqual(self.action_of(out, 'x.txt'), f'written: {os.path.join(out_dir, "x.txt")}')
        self.assertEqual(self.action_of(out, 'readme.txt'), f'copied: {os.path.join(out_dir, "readme.txt")}')
        self.assertIn('2 written, 1 copied, 1 binary, 1 non-text file not copied', out)
        self.assertEqual(self.backups(src), [])
        self.assertEqual(self.backups(out_dir), [])

        # nothing edited -> every file ok, no prompt
        tty = FakeTTY(['y'])
        code, out, err = self.run_cli('-v', '-o', out_dir, '-r', src, tty=tty)
        self.assertEqual(code, 0, err)
        for n in ('x.txt', 'y.txt', 'readme.txt'):
            self.assertEqual(self.action_of(out, n), 'ok', out)
        self.assertEqual(tty.prompts, [])
        self.assertEqual(self.tree_hashes(src), before)

        # out/readme.txt (a 'copied' file) edited: no terminal -> skipped, edit intact, exit 3
        readme_out = os.path.join(out_dir, 'readme.txt')
        self.write(readme_out, b'plain\nedited\n')
        code, out, err = self.run_cli('-o', out_dir, '-r', src, tty=None)
        self.assertEqual(code, 3)
        self.assertEqual(self.action_of(out, 'readme.txt'), 'skipped: exists (no terminal; use -y or -n)')
        self.assertEqual(self.read(readme_out), b'plain\nedited\n')
        self.assertIn('1 not overwritten', out)
        # with a terminal answering 'y' -> overwritten
        tty = FakeTTY(['y'])
        code, out, err = self.run_cli('-o', out_dir, '-r', src, tty=tty)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(readme_out), b'plain\n')
        self.assertEqual(len(tty.prompts), 1)
        self.assertIn(readme_out, tty.prompts[0])

    def test_output_dir_collision(self):
        a, _ = self.mk('a/x.txt', SURE_RU, 'cp1251')
        b, _ = self.mk('b/x.txt', SURE_RU, 'cp1251')
        out_dir = os.path.join(self.tmp, 'out')
        code, out, err = self.run_cli('-o', out_dir + '/', a, b)
        self.assertEqual(code, 2)
        self.assertIn('would both end up at', err)
        self.assertEqual(out, '')
        self.assertFalse(os.path.exists(out_dir) and os.listdir(out_dir))
        self.untouched_cp1251(a, b)

    def untouched_cp1251(self, *paths):
        for p in paths:
            self.assertEqual(self.read(p), SURE_RU.replace('\n', '\r\n').encode('cp1251'), p)

    def test_output_dir_inside_input(self):
        parent = os.path.join(self.tmp, 'parent')
        _, exp = self.mk('parent/doc.txt', SURE_RU, 'cp1251')
        stale, _ = self.mk('parent/out/stale.txt', SURE_RU, 'cp1251')
        out_dir = os.path.join(parent, 'out')
        code, out, err = self.run_cli('-o', out_dir + '/', '-r', parent)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(os.path.join(out_dir, 'doc.txt')), exp)
        self.untouched_cp1251(stale, os.path.join(parent, 'doc.txt'))
        self.assertFalse(os.path.exists(os.path.join(out_dir, 'out')))
        self.assertIsNone(self.action_of(out, 'stale.txt'))
        self.assertIn('lies inside the input tree', err)

    def test_output_dir_is_input_dir(self):
        docs = os.path.join(self.tmp, 'docs')
        path, exp = self.mk('docs/n.txt', SURE_RU, 'cp1251')
        code, out, err = self.run_cli('-o', docs + '/', '-r', docs)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path), exp)
        self.assertEqual(self.action_of(out, 'n.txt'), 'converted')
        self.assertIn('converting in place', err)
        self.assertEqual(self.names(docs), ['n.txt'])

    def test_output_dir_on_regular_file(self):
        f, _ = self.mk('file', 'plain\n', 'ascii', eol='\n')
        path, _ = self.mk('n.txt', SURE_RU, 'cp1251')
        code, out, err = self.run_cli('-o', f + '/', path)
        self.assertEqual(code, 2)
        self.assertIn('not a directory', err)
        self.untouched_cp1251(path)
        self.assertEqual(self.read(f), b'plain\n')


class OutputFileTests(CLICase):                                                         # 22
    def setUp(self):
        super().setUp()
        self.src, self.exp = self.mk('old.txt', SURE_RU, 'cp1251')
        self.orig = self.read(self.src)
        self.new = os.path.join(self.tmp, 'new.txt')

    def test_output_file_written(self):
        code, out, err = self.run_cli('-o', self.new, self.src)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(self.new), self.exp)
        self.assertEqual(self.read(self.src), self.orig)
        self.assertEqual(self.action_of(out, 'old.txt'), f'written: {self.new}')
        self.assertIn('1 written', out)
        self.assertEqual(self.backups(), [])

    def test_output_file_usage_errors(self):
        src2, _ = self.mk('old2.txt', SURE_RU, 'cp1251')
        d = os.path.join(self.tmp, 'd')
        os.mkdir(d)
        link = os.path.join(self.tmp, 'link.txt')
        os.symlink(self.src, link)
        for args in (('-o', self.new, self.src, src2),                      # two inputs
                     ('-o', self.new, d),                                   # a directory
                     ('-o', self.new, link),                                # a symlink
                     ('-o', os.path.join(self.tmp, 'nodir', 'n.txt'), self.src)):  # missing parent
            code, out, err = self.run_cli(*args)
            self.assertEqual(code, 2, args)
            self.assertIn('win2nix: error:', err)
        self.assertFalse(os.path.exists(self.new))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'nodir')))
        self.assertEqual(self.read(self.src), self.orig)

    def test_output_file_exists(self):
        self.write(self.new, b'other\n')
        # no terminal, no -y: not overwritten
        code, out, err = self.run_cli('-o', self.new, self.src, tty=None)
        self.assertEqual(code, 3)
        self.assertEqual(self.read(self.new), b'other\n')
        self.assertEqual(self.action_of(out, 'old.txt'), 'skipped: exists (no terminal; use -y or -n)')
        # -y: overwritten
        code, out, err = self.run_cli('-y', '-o', self.new, self.src)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(self.new), self.exp)
        self.assertEqual(self.temps(), [])
        # -n: skipped
        self.write(self.new, b'other\n')
        code, out, err = self.run_cli('-n', '-o', self.new, self.src)
        self.assertEqual(code, 3)
        self.assertEqual(self.read(self.new), b'other\n')
        self.assertEqual(self.action_of(out, 'old.txt'), 'skipped: exists (-n)')
        # -y -n together: usage error
        code, out, err = self.run_cli('-y', '-n', '-o', self.new, self.src)
        self.assertEqual(code, 2)

    def test_output_file_prompts(self):
        self.write(self.new, b'other\n')
        tty = FakeTTY(['n', 'y'])
        code, out, err = self.run_cli('-o', self.new, self.src, tty=tty)
        self.assertEqual(code, 3)
        self.assertEqual(self.read(self.new), b'other\n')
        self.assertEqual(self.action_of(out, 'old.txt'), 'skipped: not overwritten')
        code, out, err = self.run_cli('-o', self.new, self.src, tty=tty)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(self.new), self.exp)
        self.assertEqual(len(tty.prompts), 2)
        self.assertIn(f"overwrite '{self.new}'? [y/N/a/q] ", tty.prompts[0])
        # Russian yes
        self.write(self.new, b'other\n')
        code, out, err = self.run_cli('-o', self.new, self.src, tty=FakeTTY(['д']))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(self.new), self.exp)
        # EOF means no
        self.write(self.new, b'other\n')
        code, out, err = self.run_cli('-o', self.new, self.src, tty=FakeTTY([]))
        self.assertEqual(code, 3)
        self.assertEqual(self.read(self.new), b'other\n')

    def test_output_prompt_all_and_quit(self):
        a, ea = self.mk('a.txt', SURE_RU, 'cp1251')
        b, eb = self.mk('b.txt', SURE_RU + 'Ещё одна строка.\n', 'cp1251')
        out_dir = os.path.join(self.tmp, 'out')
        os.mkdir(out_dir)
        oa, ob = os.path.join(out_dir, 'a.txt'), os.path.join(out_dir, 'b.txt')
        self.write(oa, b'x\n')
        self.write(ob, b'y\n')
        tty = FakeTTY(['a'])
        code, out, err = self.run_cli('-o', out_dir, a, b, tty=tty)
        self.assertEqual(code, 0, err)
        self.assertEqual((self.read(oa), self.read(ob)), (ea, eb))
        self.assertEqual(len(tty.prompts), 1)
        # 'q' stops: the first file is not overwritten, the rest are not processed
        self.write(oa, b'x\n')
        self.write(ob, b'y\n')
        tty = FakeTTY(['q'])
        code, out, err = self.run_cli('-o', out_dir, a, b, tty=tty)
        self.assertEqual(code, 3)
        self.assertEqual((self.read(oa), self.read(ob)), (b'x\n', b'y\n'))
        self.assertEqual(self.action_of(out, 'a.txt'), 'skipped: not overwritten')
        self.assertIn('not processed (quit)', out)    # plan 7: every skipped result is printed
        self.assertEqual(len(tty.prompts), 1)

    def test_output_file_is_input(self):
        path, _ = self.mk('self.txt', UNSURE_RU, 'cp866')
        orig = self.read(path)
        code, out, err = self.run_cli('-o', path, path)
        self.assertEqual(code, 0, err)
        self.assertNotEqual(self.read(path), orig)
        self.assertEqual(self.read(path + BAK), orig)
        self.assertIn(f'converted, backup: {path}{BAK}', out)
        self.assertIn('output is the input', err)


class CheckModeTests(CLICase):                                                          # 23
    def build(self):
        d = os.path.join(self.tmp, 'd')
        self.mk('d/sure.txt', SURE_RU, 'cp1251')
        self.mk('d/short.txt', UNSURE_RU, 'cp866')
        self.mk('d/plain.txt', 'plain\n', 'ascii', eol='\n')
        self.mk('d/bom.txt', 'plain\n', 'utf-8', eol='\n', bom=True)
        self.write(os.path.join(d, 'bin.dat'), BINARY)
        return d

    def test_check_mode(self):
        d = self.build()
        before = self.tree_hashes(d)
        names = self.names(d)
        code, out, err = self.run_cli('-c', '-r', d)
        self.assertEqual(code, 1, err)
        self.assertEqual(self.tree_hashes(d), before)
        self.assertEqual(self.names(d), names)
        self.assertEqual(self.names(), ['d'])
        self.assertEqual(self.action_of(out, 'sure.txt'), 'would convert [crlf→lf, cp1251→utf-8]')
        self.assertRegex(self.action_of(out, 'short.txt'), r'^would convert \[.*\] \(unsure, backup\)$')
        self.assertEqual(self.action_of(out, 'bom.txt'), 'would convert [bom]')
        self.assertIn('skipped: binary', self.action_of(out, 'bin.dat'))
        self.assertIn('3 would be converted (1 unsure), 1 ok, 1 binary', out)
        # clean tree -> exit 0
        self.mk('clean/plain.txt', 'plain\n', 'ascii', eol='\n')
        code, out, err = self.run_cli('-c', os.path.join(self.tmp, 'clean'))
        self.assertEqual(code, 0, err)
        self.assertIn('1 file: 1 ok', out)

    def test_check_with_output_dir(self):
        d = self.build()
        before = self.tree_hashes(d)
        out_dir = os.path.join(self.tmp, 'out')
        code, out, err = self.run_cli('-c', '-o', out_dir + '/', '-r', d)
        self.assertEqual(code, 1, err)
        self.assertFalse(os.path.exists(out_dir))
        self.assertEqual(self.tree_hashes(d), before)
        self.assertEqual(self.action_of(out, 'sure.txt'), f'would write: {os.path.join(out_dir, "sure.txt")}')
        self.assertEqual(self.action_of(out, 'plain.txt'), f'would copy: {os.path.join(out_dir, "plain.txt")}')
        self.assertIn('non-text file not copied', out)
        # existing, differing output -> would overwrite (and still nothing is written)
        os.mkdir(out_dir)
        self.write(os.path.join(out_dir, 'sure.txt'), b'x')
        code, out, err = self.run_cli('-c', '-o', out_dir + '/', os.path.join(d, 'sure.txt'))
        self.assertEqual(code, 1, err)
        self.assertEqual(self.action_of(out, 'sure.txt'), f'would overwrite: {os.path.join(out_dir, "sure.txt")}')
        self.assertEqual(self.read(os.path.join(out_dir, 'sure.txt')), b'x')
        self.assertEqual(self.names(out_dir), ['sure.txt'])


class MetadataTests(CLICase):                                                           # 24
    def test_mtime_preserved_and_touch(self):
        path, exp = self.mk('m.txt', SURE_RU, 'cp1251')
        os.utime(path, ns=(T2001_NS, T2001_NS))
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path), exp)
        self.assertEqual(os.stat(path).st_mtime_ns, T2001_NS)

        path2, exp2 = self.mk('t.txt', SURE_RU, 'cp1251')
        os.utime(path2, ns=(T2001_NS, T2001_NS))
        t0 = time.time()
        code, out, err = self.run_cli('--touch', path2)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path2), exp2)
        self.assertGreaterEqual(os.stat(path2).st_mtime, t0 - 1)

    def test_readonly_file_converted(self):
        path, exp = self.mk('ro.txt', SURE_RU, 'cp1251')
        os.chmod(path, 0o444)
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path), exp)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o444)

    def test_group_preserved(self):
        others = [g for g in os.getgroups() if g != os.getgid()]
        if not others:
            self.skipTest('user has one group only')
        path, exp = self.mk('g.txt', SURE_RU, 'cp1251')
        try:
            os.chown(path, -1, others[0])
        except PermissionError:
            self.skipTest('cannot chgrp to a supplementary group here')
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path), exp)
        self.assertEqual(os.stat(path).st_gid, others[0])
        self.assertNotIn('warning', err)


class WriteSafetyTests(CLICase):                                                        # 25
    def test_hardlink(self):
        a, exp = self.mk('a.txt', SURE_RU, 'cp1251')
        orig = self.read(a)
        b = os.path.join(self.tmp, 'b.txt')
        os.link(a, b)
        code, out, err = self.run_cli(a)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(a), exp)
        self.assertEqual(self.read(b), orig)
        self.assertNotEqual(os.stat(a).st_ino, os.stat(b).st_ino)
        self.assertEqual(self.backups(), [])

    def test_race_guard(self):
        # The guard re-lstats the source right before os.replace (plan section 6), so the mutation
        # is injected at the last syscall before it: the fsync of the temp file.
        path, _ = self.mk('r.txt', SURE_RU, 'cp1251')
        orig = self.read(path)
        real_fsync = os.fsync

        def fsync_then_edit_source(fd):
            real_fsync(fd)
            with open(path, 'ab') as f:
                f.write(b'late edit\r\n')

        with mock.patch('os.fsync', side_effect=fsync_then_edit_source):
            code, out, err = self.run_cli(path)
        self.assertEqual(code, 3)
        self.assertEqual(self.action_of(out, 'r.txt'), 'error: file changed during conversion')
        self.assertEqual(self.read(path), orig + b'late edit\r\n')
        self.assertEqual(self.temps(), [])
        self.assertEqual(self.backups(), [])

    def test_write_failure_cleans_temp(self):
        path, _ = self.mk('w.txt', SURE_RU, 'cp1251')
        orig = self.read(path)
        with mock.patch('os.fsync', side_effect=OSError(errno.ENOSPC, 'No space left on device')):
            code, out, err = self.run_cli(path)
        self.assertEqual(code, 3)
        self.assertEqual(self.action_of(out, 'w.txt'), 'error: No space left on device')
        self.assertEqual(self.read(path), orig)
        self.assertEqual(self.temps(), [])
        self.assertIn('1 error', out)

        with mock.patch('os.fsync', side_effect=KeyboardInterrupt):
            code, out, err = self.run_cli(path)
        self.assertEqual(code, 130)
        self.assertIn('interrupted', err)
        self.assertEqual(self.read(path), orig)
        self.assertEqual(self.temps(), [])


class ReportTests(CLICase):                                                             # 26
    def test_exit_codes_and_summary(self):
        d = os.path.join(self.tmp, 'd')
        sure, _ = self.mk('d/sure.txt', SURE_RU, 'cp1251')
        self.mk('d/short.txt', UNSURE_RU, 'cp866')
        plain, _ = self.mk('d/plain.txt', 'plain\n', 'ascii', eol='\n')
        self.mk('d/fr.txt', LATIN1, 'latin-1')
        binary = os.path.join(d, 'bin.dat')
        self.write(binary, BINARY)
        code, out, err = self.run_cli(d)
        self.assertEqual(code, 3)
        self.assertIn('win2nix: 5 files: 2 converted (1 with backup), 1 ok, 1 binary, 1 unknown encoding', out)
        self.assertEqual(self.run_cli(binary)[0], 0)
        self.assertEqual(self.run_cli(plain)[0], 0)
        self.assertEqual(self.run_cli(os.path.join(self.tmp, 'missing.txt'))[0], 2)
        self.assertEqual(self.run_cli('-c', plain)[0], 0)
        self.assertEqual(self.run_cli('-c', sure)[0], 0)            # already converted
        self.mk('d2/sure.txt', SURE_RU, 'cp1251')
        self.assertEqual(self.run_cli('-c', os.path.join(self.tmp, 'd2'))[0], 1)
        code, out, err = self.run_cli('-q', plain)
        self.assertEqual((code, out), (0, ''))

    def test_non_utf8_filename(self):
        name = os.fsdecode(b'\xcf\xf0\xe8\xe2\xe5\xf2.txt')          # "Привет.txt" in cp1251 bytes
        path, exp = self.mk(name, SURE_RU, 'cp1251')
        code, out, err = self.run_cli(path)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(path), exp)
        self.assertIn('\\xcf\\xf0', out)
        self.assertIn('-> converted', out)
        self.assertIn('1 file: 1 converted', out)

    def test_large_slice(self):
        line = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.\n'
        n = (3 << 20) // len(line) + 1
        half = ''.join([line] * (n // 2))
        path, exp = self.mk('big.txt', half + SURE_RU + half, 'cp1251')
        self.assertGreater(os.path.getsize(path), 3 << 20)
        t0 = time.monotonic()
        code, out, err = self.run_cli(path)
        elapsed = time.monotonic() - t0
        self.assertEqual(code, 0, err)
        self.assertLess(elapsed, 5.0)
        self.assertRegex(self.action_of(out, 'big.txt'), r'^converted$')
        self.assertIn(f'{path}: cp1251 crlf=', out)
        self.assertEqual(self.read(path), exp)


class ExampleFilesTests(CLICase):                                                       # 27
    def test_example_files_smoke(self):
        ex = os.path.join(self.tmp, 'example')
        shutil.copytree(EXAMPLE_DIR, ex)
        originals = {n: self.read(os.path.join(ex, n)) for n in self.names(ex)}
        self.assertGreaterEqual(len(originals), 6)
        expected = {n: self._expected(n, data) for n, data in originals.items()}
        already_ok = [n for n, data in originals.items() if expected[n] == data]
        self.assertGreaterEqual(len(already_ok), 1)

        code, out, err = self.run_cli('-c', '-r', ex)
        self.assertEqual(code, 1, err)
        self.assertEqual({n: self.read(os.path.join(ex, n)) for n in self.names(ex)}, originals)

        code, out, err = self.run_cli('-v', '-r', ex)
        self.assertEqual(code, 0, err)
        for n, data in originals.items():
            new = self.read(os.path.join(ex, n))
            self.assertEqual(new, expected[n], n)
            self.assertNotIn(b'\r', new)
            self.assertEqual(self.action_of(out, n), 'ok' if n in already_ok else 'converted')
        lines = [ln for ln in out.splitlines() if ' -> ' in ln]
        self.assertEqual(len(lines), len(originals))
        for ln in lines:
            self.assertIn('level=sure', ln)
            self.assertNotIn('? ', ln.split(' -> ')[0])
        self.assertEqual(self.backups(ex), [])
        n_conv = len(originals) - len(already_ok)
        self.assertIn(f'{len(originals)} files: {n_conv} converted, {len(already_ok)} ok', out)

        code, out, err = self.run_cli('-c', '-r', ex)
        self.assertEqual(code, 0, err)
        self.assertIn(f'{len(originals)} ok', out)

    @staticmethod
    def _expected(name: str, data: bytes) -> bytes:
        codecs_by_suffix = {'_cp1251': 'cp1251', '_cp866': 'cp866', '_koi8r': 'koi8_r', '_utf8': 'utf-8'}
        stem = os.path.splitext(name)[0]
        codec = next(c for suffix, c in codecs_by_suffix.items() if suffix in stem)
        body = data[3:] if data.startswith(b'\xef\xbb\xbf') else data
        return re.sub(rb'\r+\n', b'\n', body).decode(codec).encode('utf-8')


if __name__ == '__main__':
    unittest.main()
