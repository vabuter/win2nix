"""Regression tests for the second review round (pty prompt, forced codec vs BOM, big files, gates, -o safety)."""
import contextlib
import io
import os
import pty
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import win2nix as w  # noqa: E402

RU = ('Привет, это обычный русский текст для проверки, в нём достаточно слов для уверенности '
      'и ещё немного, чтобы детектор не сомневался.')
EXAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'example')


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = w.main(argv)
    return rc, out.getvalue(), err.getvalue()


class NoTTY:
    def __init__(self):
        pass


class Round2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='w2n-r2-')
        self.d = self.tmp.name
        self._open = w.Console.open
        w.Console.open = lambda self_: setattr(self_, 'tty', None)

    def tearDown(self):
        w.Console.open = self._open
        self.tmp.cleanup()

    def path(self, name, data):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    # --- detection -------------------------------------------------------------------------
    def test_forced_single_byte_codec_beats_false_utf16_bom(self):
        data = 'яю - первые две буквы. Вчера мы ходили в кино, а потом гуляли.\r\n'.encode('cp1251')
        for payload in (data, data + b'.'):               # even and odd length
            out, a, changes, replaced = w.convert_bytes(payload, 'cp1251')
            self.assertEqual(a.detection.encoding, 'cp1251')
            self.assertEqual(a.detection.level, 'forced')
            self.assertTrue(out.decode('utf-8').startswith('яю - первые две буквы'))
        out, a, _, _ = w.convert_bytes(data)              # auto mode falls through to 8-bit detection
        self.assertEqual((a.detection.encoding, a.detection.level), ('cp1251', 'sure'))

    def test_large_single_line_utf8_is_not_cut_inside_a_character(self):
        with open(os.path.join(EXAMPLE_DIR, 'корпус_utf8.txt'), 'rb') as f:
            text = f.read().decode('utf-8').replace('\n', ' ')
        body = ('a' + text * 10).encode('utf-8')          # the 1-byte prefix shifts the cut into a multibyte char
        self.assertGreater(len(body), w.SCORE_SLICE)
        out, a, changes, _ = w.convert_bytes(body)
        self.assertEqual((a.detection.encoding, a.detection.level), ('utf-8', 'sure'))
        self.assertEqual(out, body)
        cr_only = ('a' + text * 10).replace(' ', '\r', 50000).encode('utf-8')
        out, a, changes, _ = w.convert_bytes(cr_only)
        self.assertEqual(a.detection.encoding, 'utf-8')
        self.assertIn('cr→lf', changes)
        self.assertNotIn(b'\r', out)
        # 8-bit single lines of the same shape stay correct
        for codec in ('cp1251', 'koi8_r', 'cp866'):
            big = (text * 10).encode(codec, 'ignore')
            out, a, _, _ = w.convert_bytes(big)
            self.assertEqual((a.detection.encoding, a.detection.level), (codec, 'sure'))

    def test_mac_cyrillic_prose_is_never_sure(self):
        mac = ('Вчера мы ходили в кино, а потом долго гуляли по набережной.\r\n'
               'Завтра собрание в десять, не опаздывай.\r\n'
               'Если сервер не отвечает, перезапустите службу.\r\n'
               'Дети ушли в школу, дома наконец тихо.\r\n').encode('mac_cyrillic')
        _, a, _, _ = w.convert_bytes(mac)
        self.assertNotEqual(a.detection.level, 'sure')
        self.assertTrue(any('mac-cyrillic' in n for n in a.detection.notes), a.detection.notes)

    def test_ukrainian_supersets_get_a_note(self):
        ukr = ('Сьогодні я нарешті розібрався з налаштуваннями мережі і все запрацювало. '
               'Дякую всім за допомогу, тепер усе працює як треба.')
        for codec, hint in (('koi8_u', 'koi8-u'), ('cp1125', 'cp1125')):
            _, a, _, _ = w.convert_bytes(ukr.encode(codec))
            self.assertEqual(a.detection.level, 'unsure', (codec, a.detection))
            self.assertTrue(any(hint in n for n in a.detection.notes), a.detection.notes)

    def test_latin_adjacent_cyrillic_with_real_words_is_unsure_not_unknown(self):
        game = ('Защита двух коней, партия номер пять\r\n'
                '1. e2-e4 e7-e5 2. Кg1-f3 Кb8-c6 3. Сf1-c4 Сf8-c5 4. 0-0 Кg8-f6\r\n').encode('cp1251')
        _, a, _, _ = w.convert_bytes(game)
        self.assertEqual(a.detection.encoding, 'cp1251')
        self.assertNotEqual(a.detection.level, 'unknown')
        french = "Voilà, c'est très élégant: où êtes-vous? À bientôt, Noël.".encode('cp1252')
        _, a, _, _ = w.convert_bytes(french)
        self.assertEqual(a.detection.level, 'unknown')

    def test_cr_only_file_with_utf8_lines_is_mixed(self):
        data = ('Первая строка в cp1251 с достаточным числом слов.\rВторая строка тоже.\r').encode('cp1251') \
            + 'Новая строка из Linux в UTF-8\r'.encode('utf-8')
        out, a, _, _ = w.convert_bytes(data)
        self.assertEqual(a.kind, 'mixed')
        self.assertEqual(out.decode('utf-8').split('\n')[:3],
                         ['Первая строка в cp1251 с достаточным числом слов.', 'Вторая строка тоже.',
                          'Новая строка из Linux в UTF-8'])

    # --- file layer ------------------------------------------------------------------------
    def test_console_prompt_works_on_a_real_tty(self):
        real_open = self._open                             # setUp patched Console.open with a stub
        pid, fd = pty.fork()
        if pid == 0:                                       # child: has the pty as controlling terminal
            try:
                c = w.Console()
                real_open(c)
                if not c.interactive:
                    os._exit(1)
                c.tty.write('overwrite? ')
                c.tty.flush()
                ans = c.tty.readline()
                os._exit(0 if ans.strip() == 'да' else 2)
            except BaseException:
                os._exit(3)
        else:
            try:
                os.read(fd, 1024)                          # wait for the prompt
                os.write(fd, 'да\n'.encode('utf-8'))
            except OSError:
                pass                                       # child already gone: its exit code tells why
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_output_may_not_overwrite_an_input(self):
        ru = (RU + '\r\n').encode('cp1251')
        victim = self.path('in/sub/x.txt', ru)
        self.path('in/in/sub/x.txt', 'ёж\r\n'.encode('cp866'))
        cwd = os.getcwd()
        os.chdir(os.path.join(self.d, 'in'))
        try:
            rc, out, err = run(['-y', '-o', '..', '-r', '.'])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 2)
        self.assertIn('would be written over the input', err)
        with open(victim, 'rb') as f:
            self.assertEqual(f.read(), ru)

    def test_backup_without_hard_links(self):
        p = self.path('u.txt', 'Это тест\r\n'.encode('koi8_r'))
        real_link = os.link

        def no_link(*args, **kwargs):
            raise PermissionError(1, 'Operation not permitted')
        os.link = no_link
        try:
            rc, out, err = run([p])
        finally:
            os.link = real_link
        self.assertEqual(rc, 0, out + err)
        self.assertIn('backup: ', out)
        with open(p + w.BACKUP_SUFFIX, 'rb') as f:
            self.assertEqual(f.read(), 'Это тест\r\n'.encode('koi8_r'))

    def test_unreadable_subdirectory_is_an_error(self):
        if os.geteuid() == 0:
            self.skipTest('root ignores directory permissions')
        self.path('t/a.txt', (RU + '\r\n').encode('cp1251'))
        locked = os.path.dirname(self.path('t/locked/b.txt', (RU + '\r\n').encode('cp1251')))
        os.chmod(locked, 0)
        try:
            rc, out, err = run(['-c', '-r', os.path.join(self.d, 't')])
        finally:
            os.chmod(locked, stat.S_IRWXU)
        self.assertEqual(rc, 3, out + err)
        self.assertIn('unreadable directory', out)

    def test_trailing_slash_does_not_follow_a_symlinked_directory(self):
        target = self.path('real/a.txt', (RU + '\r\n').encode('cp1251'))
        os.symlink('real', os.path.join(self.d, 'linkdir'))
        rc, out, err = run([os.path.join(self.d, 'linkdir') + '/'])
        self.assertEqual(rc, 0)
        self.assertIn('skipped: symlink', out)
        with open(target, 'rb') as f:
            self.assertEqual(f.read(), (RU + '\r\n').encode('cp1251'))

    def test_overwritten_output_is_reported(self):
        src = self.path('in/a.txt', 'уже нормальный utf-8 файл\n'.encode('utf-8'))
        dest = self.path('out/a.txt', 'СОВСЕМ ДРУГОЕ\n'.encode('utf-8'))
        rc, out, err = run(['-y', '-o', os.path.join(self.d, 'out') + '/', src])
        self.assertEqual(rc, 0)
        self.assertIn('overwritten: ', out)
        with open(dest, 'rb') as f:
            self.assertEqual(f.read(), 'уже нормальный utf-8 файл\n'.encode('utf-8'))

    def test_closed_streams_do_not_abort_the_run(self):
        p1 = self.path('c1.txt', (RU + '\r\n').encode('cp1251'))
        p2 = self.path('c2.txt', (RU + '\r\n').encode('cp1251'))
        saved = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = None, None
        try:
            rc = w.main([p1, p2])
        finally:
            sys.stdout, sys.stderr = saved
        self.assertEqual(rc, 0)
        for p in (p1, p2):
            with open(p, 'rb') as f:
                self.assertEqual(f.read(), (RU + '\n').encode('utf-8'))

    def test_non_text_codec_is_a_usage_error(self):
        p = self.path('a.txt', b'plain\r\n')
        for bad in ('base64', 'rot13', 'zlib'):
            rc, out, err = run(['-c', '--from', bad, p])
            self.assertEqual(rc, 2, (bad, err))
            self.assertIn('not a text encoding', err)


if __name__ == '__main__':
    unittest.main()
