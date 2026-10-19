"""Detection, transformation and analysis tests for win2nix (plan section 9, items 1-14).

Everything here is pure in-memory analysis plus a few `--from` CLI runs on files created in a
temporary directory.  The synthetic fixtures in example/ are copied out and never modified.
"""
from __future__ import annotations

import contextlib
import io
import math
import os
import random
import shutil
import sys
import tempfile
import unittest

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
import win2nix as w  # noqa: E402

EXAMPLE_DIR = os.path.join(PROJECT, 'example')
CORPUS_NAME = 'корпус_cp1251_lf.txt'     # cp1251, LF, > 9000 lines
FIXTURE_CODECS = {'_cp1251': 'cp1251', '_cp866': 'cp866', '_koi8r': 'koi8_r', '_utf8': 'utf-8'}
CODECS = ('cp1251', 'cp866', 'koi8_r')

# ~40 realistic lines: prose, ALL-CAPS, ini/bat/reg/csv, code with Russian comments, digits,
# names, abbreviations.  Every character must be encodable in all three 8-bit codecs.
SAMPLES = [
    'Сегодня я наконец-то разобрался с настройками сети и всё заработало.',
    'Надо не забыть купить хлеб, молоко и картошку на выходных.',
    'Она сказала, что приедет в пятницу вечером, если не будет пробок.',
    'Мы долго спорили о том, кто из нас прав, но так и не пришли к выводу.',
    'В этом году зима выдалась тёплой, снега почти не было до февраля.',
    'Если сервер не отвечает больше минуты, перезапустите службу вручную.',
    'ВНИМАНИЕ! ПЕРЕД УСТАНОВКОЙ ОБЯЗАТЕЛЬНО СДЕЛАЙТЕ РЕЗЕРВНУЮ КОПИЮ ДАННЫХ.',
    'СПИСОК ДЕЛ НА НЕДЕЛЮ: ПОЗВОНИТЬ В БАНК, ОПЛАТИТЬ СЧЕТА, ЗАБРАТЬ ПОСЫЛКУ.',
    'ИНСТРУКЦИЯ ПО ЭКСПЛУАТАЦИИ СТИРАЛЬНОЙ МАШИНЫ',
    '[Настройки]\nЯзык=Русский\nПуть=C:\\Документы\\Отчёты\nАвтосохранение=1',
    '; Параметры подключения к базе данных\nсервер=localhost\nпользователь=админ',
    '@echo off\nrem Копирование файлов отчёта в архив\ncopy *.doc "D:\\Архив\\Отчёты"\necho Готово',
    'Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Программа]\n"Имя"="Иван Петров"',
    'Фамилия;Имя;Отчество;Город;Телефон\nИванов;Иван;Иванович;Москва;123-45-67',
    'Дата;Сумма;Назначение\n01.03.2020;1500,00;Оплата за электроэнергию\n02.03.2020;320,50;Проезд',
    '# Считаем среднее значение по столбцу и выводим результат\nresult = sum(values) / len(values)',
    'int count = 0; // количество обработанных записей в текущем сеансе',
    '/* Функция возвращает индекс первого найденного элемента или -1 */',
    'print("Привет, мир!")  # проверка кодировки вывода в консоли',
    'Итого за квартал: 125 430 рублей 50 копеек, из них налоги 18 814 рублей.',
    'Встреча назначена на 14:30, аудитория 215, третий этаж, корпус Б.',
    'Температура воды 36,6 градуса, давление 760 мм рт. ст., влажность 45 процентов.',
    'Александр Сергеевич Пушкин родился в Москве в 1799 году.',
    'Передай привет Наташе, Серёже и дяде Володе, когда будешь в Петербурге.',
    'Директор ООО "Ромашка" Михаил Юрьевич Соколов подписал договор.',
    'МГУ, РАН, ФСБ, МВД, ГИБДД, ЖКХ, НДС, ОАО, ЗАО, ГОСТ, СНиП, ТУ.',
    'Согласно ГОСТ Р 51141-98 документы хранятся не менее пяти лет.',
    'Рассмотрим уравнение x^2 + 3x - 4 = 0, его корни равны 1 и -4.',
    'Полный путь к файлу: C:\\Users\\Пользователь\\Documents\\письмо.txt',
    'Компьютер зависает при загрузке драйвера видеокарты, помогает только перезагрузка.',
    'Ёжик, ёлка и её щенок - всё это было нарисовано на открытке.',
    'Съешь ещё этих мягких французских булок да выпей чаю.',
    'Широкая электрификация южных губерний даст мощный толчок подъёму сельского хозяйства.',
    'Вчера весь день шёл дождь, поэтому мы остались дома и смотрели старые фильмы.',
    'Пожалуйста, отправьте копию договора по электронной почте до конца рабочего дня.',
    'Чтобы собрать проект, выполните команду make в корневом каталоге.',
    'Ну что, пошли?',
    'Да, конечно.',
    'Отчёт за 2019 год',
    'Ошибка: файл не найден',
    'Жили-были дед да баба, и была у них курочка Ряба.',
    'Мой дядя самых честных правил, когда не в шутку занемог.',
]
PROSE = '\r\n'.join(SAMPLES[:3]) + '\r\n'

_TMP: tempfile.TemporaryDirectory | None = None
EXAMPLE_COPY = ''
CORPUS_TEXT = ''


def setUpModule():
    """Copy the read-only fixtures out of example/ once; everything works on the copies."""
    global _TMP, EXAMPLE_COPY, CORPUS_TEXT
    _TMP = tempfile.TemporaryDirectory(prefix='w2n-detection-')
    EXAMPLE_COPY = os.path.join(_TMP.name, 'example')
    shutil.copytree(EXAMPLE_DIR, EXAMPLE_COPY)
    with open(os.path.join(EXAMPLE_COPY, CORPUS_NAME), 'rb') as f:
        CORPUS_TEXT = f.read().decode('cp1251')


def tearDownModule():
    if _TMP is not None:
        _TMP.cleanup()


# --------------------------------------------------------------------------- helpers


def example_copies() -> list[tuple[str, bytes]]:
    out = []
    for name in sorted(os.listdir(EXAMPLE_COPY)):
        with open(os.path.join(EXAMPLE_COPY, name), 'rb') as f:
            out.append((name, f.read()))
    return out


def fixture_codec(name: str) -> str:
    """The source encoding of an example file is encoded in its name: _cp1251, _cp866, _koi8r, _utf8."""
    stem = os.path.splitext(name)[0]
    for suffix, codec in FIXTURE_CODECS.items():
        if suffix in stem:
            return codec
    raise AssertionError(f'fixture name without a codec suffix: {name}')


def expected_conversion(name: str, data: bytes) -> bytes:
    body = data[3:] if data.startswith(b'\xef\xbb\xbf') else data
    return w.CRLF_RE.sub('\n', body.decode(fixture_codec(name))).encode('utf-8')


def det(data: bytes, forced: str | None = None) -> w.Detection:
    a = w.analyze(data, forced)
    assert a.detection is not None, f'no detection: kind={a.kind} {a.binary_reason} {a.error}'
    return a.detection


def crlf(text: str) -> str:
    return text.replace('\n', '\r\n')


def cyr_words(text: str) -> int:
    return len(w.CYR_WORD_RE.findall(text))


def encodable(text: str, codec: str) -> bool:
    try:
        text.encode(codec)
        return True
    except UnicodeEncodeError:
        return False


def convert(data: bytes, forced: str | None = None) -> bytes | None:
    return w.convert_bytes(data, forced)[0]


def describe(d: w.Detection) -> str:
    ev = d.evidence
    return (f'{d.encoding} {d.level} margin={d.margin:.1f} n_ev={ev.n_ev} words3={ev.words3} '
            f'scores={ {k: round(v, 1) for k, v in d.scores.items()} } notes={d.notes}')


class FakeTTY:
    def __init__(self, answers=()):
        self.answers = list(answers)
        self.written: list[str] = []

    def write(self, s):
        self.written.append(s)

    def flush(self):
        pass

    def close(self):
        pass

    def readline(self):
        return self.answers.pop(0) + '\n' if self.answers else ''


@contextlib.contextmanager
def patched_console(answers=None):
    """Replace Console.open: scripted answers, or None for 'no terminal'."""
    orig = w.Console.open

    def fake_open(self):
        self.tty = FakeTTY(answers) if answers is not None else None

    w.Console.open = fake_open
    try:
        yield
    finally:
        w.Console.open = orig


def run_cli(argv: list[str], answers=None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with patched_console(answers), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = w.main(argv)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- 1. ascii / utf-8


class TestAsciiUtf8(unittest.TestCase):
    def test_ascii(self):
        d = det(b'hello\r\nworld\r\n')
        self.assertEqual((d.encoding, d.level), ('ascii', 'sure'))
        self.assertEqual(convert(b'hello\r\nworld\r\n'), b'hello\nworld\n')
        self.assertEqual(w.analyze(b'').kind, 'empty')
        # BOM alone: body is empty ASCII, output is an empty file
        out, a, changes, _ = w.convert_bytes(b'\xef\xbb\xbf')
        self.assertEqual(out, b'')
        self.assertTrue(a.has_bom)
        self.assertIn('bom', changes)

    def test_utf8_prose_and_emoji_sure(self):
        d = det(SAMPLES[0].encode('utf-8'))
        self.assertEqual((d.encoding, d.level), ('utf-8', 'sure'))
        d = det('Hello 😀 world 🎉 again 🚀 yes\r\n'.encode('utf-8'))
        self.assertEqual((d.encoding, d.level), ('utf-8', 'sure'))

    def test_utf8_cafe_unsure_never_unknown(self):
        d = det('Café'.encode('utf-8'))
        self.assertEqual((d.encoding, d.level), ('utf-8', 'unsure'), describe(d))
        # valid UTF-8 is never unknown, even for Latin-script text
        d = det('Grüße aus München, die Straße ist schön.\r\n'.encode('utf-8'))
        self.assertEqual(d.encoding, 'utf-8')
        self.assertNotEqual(d.level, 'unknown')

    def test_utf8_bom(self):
        d = det(b'\xef\xbb\xbf' + SAMPLES[0].encode('utf-8'))
        self.assertEqual((d.encoding, d.level, d.reason), ('utf-8', 'sure', 'bom'))
        # BOM glued onto a cp1251 body: 8-bit detection, at most unsure, with a note
        data = b'\xef\xbb\xbf' + crlf('\n'.join(SAMPLES[:5])).encode('cp1251')
        a = w.analyze(data)
        self.assertTrue(a.has_bom)
        self.assertEqual(a.detection.encoding, 'cp1251')
        self.assertEqual(a.detection.level, 'unsure')
        self.assertTrue(any('BOM' in n for n in a.detection.notes), a.detection.notes)
        self.assertEqual(convert(data), '\n'.join(SAMPLES[:5]).encode('utf-8'))


# --------------------------------------------------------------------------- 2. corpus


class TestCorpusNeverSureWrong(unittest.TestCase):
    def test_samples_are_encodable_everywhere(self):
        for s in SAMPLES:
            for c in CODECS:
                self.assertTrue(encodable(s, c), f'{s!r} not encodable in {c}')
                self.assertTrue(encodable(s.upper(), c), f'{s.upper()!r} not encodable in {c}')
        self.assertGreaterEqual(len(SAMPLES), 40)

    def test_samples_never_sure_wrong_and_long_ones_sure(self):
        wrong, rich, rich_sure = [], 0, 0
        for s in SAMPLES:
            for variant in (s, s.upper()):
                for c in CODECS:
                    d = det(variant.encode(c))
                    self.assertNotEqual(d.level, 'unknown', f'{c} {variant!r}: {describe(d)}')
                    if d.level == 'sure' and d.encoding != c:
                        wrong.append(f'{c} {variant!r} -> {describe(d)}')
                    if cyr_words(variant) >= 8:
                        rich += 1
                        rich_sure += d.level == 'sure' and d.encoding == c
        self.assertEqual(wrong, [])
        self.assertGreater(rich, 100)
        # 'sure' additionally needs dictionary evidence (two common words, or one in lowercase text);
        # single sentences made only of content words legitimately stay 'unsure' (backup)
        self.assertGreaterEqual(rich_sure / rich, 0.70, f'{rich_sure}/{rich} sure')

    def test_corpus_windows_never_sure_wrong(self):
        # 500 random 5-20-word windows from the copied corpus, re-encoded in all three codecs
        words = [x for x in CORPUS_TEXT.split() if all(encodable(x, c) for c in CODECS)]
        rng = random.Random(1234)
        wrong, unknown, rich, rich_sure = [], [], 0, 0
        for _ in range(500):
            n = rng.randint(5, 20)
            start = rng.randint(0, len(words) - n)
            s = ' '.join(words[start:start + n])
            for c in CODECS:
                data = s.encode(c)
                d = det(data)
                correct = {c, 'ascii'} if data.isascii() else {c}
                if d.level == 'sure' and d.encoding not in correct:
                    wrong.append(f'{c} {s!r} -> {describe(d)}')
                if d.level == 'unknown':
                    unknown.append(f'{c} {s!r} -> {describe(d)}')
                if cyr_words(s) >= 12:
                    rich += 1
                    rich_sure += d.level == 'sure' and d.encoding == c
        self.assertEqual(wrong, [])
        self.assertEqual(unknown, [])
        self.assertGreater(rich, 300)
        self.assertGreaterEqual(rich_sure / rich, 0.90, f'{rich_sure}/{rich} sure')


# --------------------------------------------------------------------------- 3. hard cases


class TestKnownHardCases(unittest.TestCase):
    def test_short_phrases_right_but_unsure(self):
        for s in ('Это тест', 'ЗАГОЛОВОК ФАЙЛА', 'ёжик и ёлка'):
            for c in CODECS:
                d = det(s.encode(c))
                self.assertEqual(d.encoding, c, f'{s!r}/{c}: {describe(d)}')
                self.assertEqual(d.level, 'unsure', f'{s!r}/{c}: {describe(d)}')

    def test_single_letters_never_sure(self):
        for s in ('Ё', 'х', 'Ё\r\n', 'х\r\n'):
            for c in CODECS:
                d = det(s.encode(c))
                self.assertNotEqual(d.level, 'sure', f'{s!r}/{c}: {describe(d)}')
                self.assertNotEqual(d.level, 'unknown', f'{s!r}/{c}: {describe(d)}')

    def test_size_lists_never_sure_wrong(self):
        sizes = '10 х 15\r\n13 х 18\r\n15 х 20\r\n20 х 30\r\n'
        metres = '5 м\r\n10 м\r\n15 м\r\n20 м\r\n'
        for s in (sizes, sizes * 2, 'Размеры фото:\r\n' + sizes, metres, 'Длины:\r\n' + metres):
            for c in CODECS:
                d = det(s.encode(c))
                self.assertFalse(d.level == 'sure' and d.encoding != c, f'{s[:14]!r}/{c}: {describe(d)}')
                self.assertNotEqual(d.level, 'unknown', f'{s[:14]!r}/{c}: {describe(d)}')

    def test_unlucky_words_never_sure(self):
        for s, c in (('штрафы сырью шэл', 'cp866'), ('хлебец ХЛЕБЕЦ', 'koi8_r'), ('объем ОБЪЕМ фух', 'cp1251')):
            d = det(s.encode(c))
            self.assertNotEqual(d.level, 'sure', f'{s!r}/{c}: {describe(d)}')
            self.assertNotEqual(d.level, 'unknown', f'{s!r}/{c}: {describe(d)}')


# --------------------------------------------------------------------------- 4. typography


class TestTypographyNeutral(unittest.TestCase):
    def check_cp1251_text(self, label: str, text: str) -> w.Detection:
        d = det(text.encode('cp1251'))
        self.assertEqual(d.encoding, 'cp1251', f'{label}: {describe(d)}')
        self.assertNotEqual(d.level, 'unknown', f'{label}: {describe(d)}')
        return d

    def test_typography_only_goes_to_cp1251(self):
        self.check_cp1251_text('nbsp numbers', '1\u00a0000\u00a0000\r\n2\u00a0500\u00a0000\r\n12\u00a0345\r\n')
        self.check_cp1251_text('degrees', "56° 11' N\r\n" * 8)
        self.check_cp1251_text('plus-minus', '25°C ± 2°\r\n' * 8)
        self.check_cp1251_text('registered', 'Microsoft® Windows®\r\n')
        d = self.check_cp1251_text('smart quotes', '“quoted” — text\r\n' * 6)
        self.assertEqual(d.level, 'unsure', describe(d))

    def test_prose_with_nbsp_table_sure_and_no_votes(self):
        table = 'Товар\tЦена\r\nСтол\t12\u00a0500\r\nСтул\t3\u00a0200\r\n'
        d = self.check_cp1251_text('prose + table', PROSE + table)
        self.assertEqual(d.level, 'sure', describe(d))
        d = self.check_cp1251_text('prose + nbsp lines', PROSE + '1\u00a0000\r\n2\u00a0000\r\n')
        self.assertEqual(d.level, 'sure', describe(d))
        self.assertEqual(d.votes, {})


# --------------------------------------------------------------------------- 5. cp866 pseudographics


BOX_TABLE = ('╔══════════╦══════════╗\r\n'
             '║ Товар    ║ Цена     ║\r\n'
             '╠══════════╬══════════╣\r\n'
             '║ Молоко   ║ 45 руб.  ║\r\n'
             '║ Хлеб     ║ 30 руб.  ║\r\n'
             '║ Сахар    ║ 60 руб.  ║\r\n'
             '╚══════════╩══════════╝\r\n')
NFO_HEADER = ('┌──────────────────────────────┐\r\n'
              '│  ▄▄▄ ▄▄▄ ▄▄▄  NFO  ▄▄▄ ▄▄▄  │\r\n'
              '│  ███ ███ ███       ███ ███  │\r\n'
              '└──────────────────────────────┘\r\n')


class TestCp866Pseudographics(unittest.TestCase):
    def test_box_table(self):
        d = det(BOX_TABLE.encode('cp866'))
        self.assertEqual(d.encoding, 'cp866', describe(d))
        self.assertIn(d.level, ('sure', 'unsure'), describe(d))
        self.assertGreaterEqual(d.margin, 100, describe(d))
        d = det(BOX_TABLE.encode('koi8_r'))
        self.assertEqual(d.encoding, 'koi8_r', describe(d))
        self.assertNotEqual(d.level, 'unknown')

    def test_pure_art_is_cp866_never_unknown(self):
        for label, art in (('gradient', '░▒▓█' * 10), ('corners', '┌─┐\r\n└─┘\r\n' * 5), ('nfo', NFO_HEADER)):
            d = det(art.encode('cp866'))
            self.assertEqual(d.encoding, 'cp866', f'{label}: {describe(d)}')
            self.assertNotEqual(d.level, 'unknown', f'{label}: {describe(d)}')
        self.assertEqual(convert(NFO_HEADER.encode('cp866')), NFO_HEADER.replace('\r\n', '\n').encode('utf-8'))


# --------------------------------------------------------------------------- 6. utf-8 collisions


class TestUtf8CollisionWords(unittest.TestCase):
    """cp866 words whose bytes happen to be valid UTF-8 (e.g. 'так' = E2 A0 AA)."""

    def test_collision_words_in_cp866(self):
        for s in ('рак и сад', 'так', 'так так так'):
            data = s.encode('cp866')
            d = det(data)
            self.assertFalse(d.level == 'sure' and d.encoding != 'cp866', f'{s!r}: {describe(d)}')
            self.assertNotEqual(d.level, 'unknown', f'{s!r}: {describe(d)}')
        d = det('рак и сад'.encode('cp866'))
        self.assertEqual(d.encoding, 'cp866', describe(d))

    def test_utf8_guess_allowed_only_unsure(self):
        for s, c in (('8 янв 2026', 'cp866'), ('её', 'koi8_r')):
            d = det(s.encode(c))
            self.assertIn(d.encoding, (c, 'utf-8'), f'{s!r}/{c}: {describe(d)}')
            self.assertEqual(d.level, 'unsure', f'{s!r}/{c}: {describe(d)}')


# --------------------------------------------------------------------------- 7. unknown gates


FRENCH = 'Le café est très bon, mais le thé est préféré par ma mère et mon père.\r\nÀ bientôt, mes amis!\r\n'
GERMAN = 'Grüße aus München! Die Straße ist schön, aber die Bäume sind größer als früher.\r\n'
CZECH = 'Příliš žluťoučký kůň úpěl ďábelské ódy. Dobrý den, jak se máte? Děkuji, mám se dobře.\r\n'
GREEK = ('Η ελληνική γλώσσα είναι μία από τις πιο παλιές γλώσσες του κόσμου και ομιλείται από '
         'εκατομμύρια ανθρώπους.\r\n')
BELARUSIAN = ('Беларуская мова — адна з усходнеславянскіх моў. Яна з’яўляецца дзяржаўнай мовай '
              'Рэспублікі Беларусь разам з рускай мовай. Ёсць шмат дыялектаў.\r\n')
UKRAINIAN = ('Українська мова належить до слов’янської групи індоєвропейської мовної сім’ї. '
             'Нею розмовляють мільйони людей в Україні та за її межами.\r\n')


class TestUnknownGates(unittest.TestCase):
    def test_latin_script_8bit_is_unknown(self):
        for label, data in (('french', FRENCH.encode('latin-1')), ('german', GERMAN.encode('latin-1')),
                            ('czech', CZECH.encode('cp1250'))):
            d = det(data)
            self.assertEqual(d.level, 'unknown', f'{label}: {describe(d)}')
            self.assertIn('Latin-script', d.reason)
            self.assertIsNone(convert(data), label)

    def test_greek_and_garbage_are_unknown_or_unsure(self):
        d = det(GREEK.encode('cp1253'))
        self.assertEqual(d.level, 'unknown', describe(d))
        self.assertIn('Russian', d.reason)
        d = det(GREEK.upper().encode('cp1253'))
        self.assertNotEqual(d.level, 'sure', describe(d))
        rng = random.Random(42)
        for label, data in (('high bytes', bytes(rng.randint(0x80, 0xff) for _ in range(300))),
                            ('high bytes + spaces',
                             bytes(rng.randint(0x80, 0xff) if rng.random() < 0.7 else 0x20 for _ in range(300)))):
            d = det(data)
            self.assertIn(d.level, ('unknown', 'unsure'), f'{label}: {describe(d)}')

    def test_abbreviations_not_unknown(self):
        d = det('ООО, ЗАО, ГОСТ, СНиП, ТУ\r\n'.encode('cp1251'))
        self.assertEqual(d.encoding, 'cp1251', describe(d))
        self.assertNotEqual(d.level, 'unknown', describe(d))

    def test_belarusian_ukrainian_cp1251_sure(self):
        for label, text in (('belarusian', BELARUSIAN), ('ukrainian', UKRAINIAN)):
            d = det(text.encode('cp1251'))
            self.assertEqual((d.encoding, d.level), ('cp1251', 'sure'), f'{label}: {describe(d)}')

    def test_mac_cyrillic_not_sure_with_note(self):
        for text in (PROSE.replace('\r\n', '\r'), 'Это текст в кодировке Mac Cyrillic, записанный на старом Макинтоше.\r\n'):
            d = det(text.encode('mac_cyrillic'))
            self.assertNotEqual(d.level, 'sure', describe(d))
            self.assertNotEqual(d.level, 'unknown', describe(d))
            self.assertTrue(any('mac-cyrillic' in n for n in d.notes), describe(d))


# --------------------------------------------------------------------------- 8. line votes


class TestLineVotes(unittest.TestCase):
    def test_cp866_lines_inside_cp1251_file(self):
        head = crlf('\n'.join(SAMPLES[:12])).encode('cp1251') + b'\r\n'
        head_lines = head.count(b'\n')                      # some SAMPLES carry embedded newlines
        block = crlf('\n'.join(SAMPLES[12:18])).encode('cp866') + b'\r\n'
        d = det(head + block)
        self.assertEqual(d.encoding, 'cp1251', describe(d))
        self.assertEqual(d.level, 'unsure', describe(d))
        self.assertGreaterEqual(d.votes.get('cp866', 0), 1, describe(d))
        self.assertTrue(any(n.startswith('mixed 8-bit') and 'cp866' in n for n in d.notes), describe(d))
        self.assertTrue(head_lines < d.first_vote_line <= head_lines + block.count(b'\n'), describe(d))
        d = det(head + SAMPLES[30].encode('cp866') + b'\r\n')
        self.assertEqual((d.encoding, d.level), ('cp1251', 'unsure'), describe(d))
        self.assertEqual(d.votes, {'cp866': 1}, describe(d))
        self.assertEqual(d.first_vote_line, head_lines + 1, describe(d))

    def test_clean_files_have_no_votes(self):
        for c in CODECS:
            d = det(crlf('\n'.join(SAMPLES)).encode(c))
            self.assertEqual((d.encoding, d.level, d.votes), (c, 'sure', {}), describe(d))
        for name, data in example_copies():
            d = det(data)
            self.assertEqual((d.level, d.votes), ('sure', {}), f'{name}: {describe(d)}')

    def test_cp866_block_after_line_9000(self):
        lines = CORPUS_TEXT.split('\n')
        self.assertGreater(len(lines), 9000)
        data = ('\n'.join(lines[:9000]) + '\n').encode('cp1251') \
            + ('\n'.join(SAMPLES[:10]) + '\n').encode('cp866') \
            + '\n'.join(lines[9000:]).encode('cp1251')
        d = det(data)
        self.assertEqual(d.encoding, 'cp1251', describe(d))
        self.assertEqual(d.level, 'unsure', describe(d))
        self.assertGreaterEqual(d.votes.get('cp866', 0), 3, describe(d))
        self.assertEqual(d.first_vote_line, 9001, describe(d))
        self.assertTrue(any('line 9001' in n for n in d.notes), d.notes)


# --------------------------------------------------------------------------- 9. mixed


class TestMixed(unittest.TestCase):
    def test_utf8_plus_cp1251_lines(self):
        parts = [(SAMPLES[0], 'cp1251'), (SAMPLES[1], 'utf-8'), ('plain ascii line', 'ascii'),
                 (SAMPLES[2], 'cp1251'), (SAMPLES[3], 'utf-8')]
        data = b''.join(s.encode(c) + b'\r\n' for s, c in parts)
        a = w.analyze(data)
        self.assertEqual(a.kind, 'mixed')
        self.assertEqual(a.detection.encoding, 'cp1251')
        self.assertEqual(a.detection.level, 'unsure')
        self.assertEqual(a.mixed_info[:2], (2, 2))
        self.assertTrue(any(n.startswith('mixed:') for n in a.notes), a.notes)
        self.assertEqual(convert(data), ''.join(s + '\n' for s, _ in parts).encode('utf-8'))

    def test_cp866_lines_plus_one_utf8_line(self):
        data = crlf('\n'.join(SAMPLES[:6])).encode('cp866') + b'\r\n' + 'Новая строка из Linux\n'.encode('utf-8')
        a = w.analyze(data)
        self.assertEqual(a.kind, 'mixed')
        self.assertEqual(a.detection.encoding, 'cp866', describe(a.detection))
        self.assertEqual(convert(data), ('\n'.join(SAMPLES[:6]) + '\nНовая строка из Linux\n').encode('utf-8'))

    def test_note_plus_single_utf8_line_is_mixed(self):
        data = crlf('\n'.join(SAMPLES[:6])).encode('cp1251') + b'\r\n' + 'Новая строка из Linux\n'.encode('utf-8')
        a = w.analyze(data)
        self.assertEqual(a.kind, 'mixed')
        self.assertEqual(a.mixed_info[0], 1)
        self.assertEqual(convert(data), ('\n'.join(SAMPLES[:6]) + '\nНовая строка из Linux\n').encode('utf-8'))

    def test_clean_files_not_mixed(self):
        for c in CODECS:
            self.assertEqual(w.analyze(crlf('\n'.join(SAMPLES)).encode(c)).kind, 'text', c)
        for name, data in example_copies():
            self.assertEqual(w.analyze(data).kind, 'text', name)


# --------------------------------------------------------------------------- 10. forced


class TestForced(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='w2n-forced-', dir=_TMP.name)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, name: str, data: bytes) -> str:
        p = os.path.join(self.dir, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    def test_from_cp866_is_forced(self):
        data = crlf(SAMPLES[0]).encode('cp866') + b'\r\n'
        d = det(data, 'cp866')
        self.assertEqual((d.encoding, d.level), ('cp866', 'forced'))
        self.assertEqual(convert(data, 'cp866'), (SAMPLES[0] + '\n').encode('utf-8'))
        p = self.path('dos.txt', data)
        code, out, err = run_cli(['-c', '--from', 'dos', p])
        self.assertEqual(code, 1, (out, err))
        self.assertIn('cp866', out)
        self.assertIn('would convert', out)
        self.assertNotIn('?', out.split('->')[0])     # forced is not reported as unsure

    def test_from_cp1251_with_undefined_byte(self):
        data = 'Текст '.encode('cp1251') + b'\x98' + ' здесь\r\n'.encode('cp1251')
        out, a, changes, replaced = w.convert_bytes(data, 'cp1251')
        self.assertEqual(a.detection.level, 'forced')
        self.assertEqual(replaced, 1)
        self.assertEqual(out, 'Текст \ufffd здесь\n'.encode('utf-8'))
        p = self.path('hole.txt', data)
        code, out_s, err = run_cli(['-f', 'windows-1251', p])
        self.assertEqual(code, 0, (out_s, err))
        self.assertIn('undecodable', err)
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), out)
        with open(p + w.BACKUP_SUFFIX, 'rb') as f:          # forced with replaced > 0 -> backup
            self.assertEqual(f.read(), data)

    def test_from_on_binary_stays_binary(self):
        for data in (b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', b'abc\x00def', b'\x89PNG\r\n\x1a\n'):
            self.assertEqual(w.analyze(data, 'cp866').kind, 'binary', data)
            self.assertIsNone(convert(data, 'cp866'))
        p = self.path('bin.dat', b'abc\x00def')
        code, out, err = run_cli(['-f', 'cp866', p])
        self.assertEqual(code, 0, (out, err))
        self.assertIn('skipped: binary', out)
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), b'abc\x00def')

    def test_codec_aliases(self):
        self.assertEqual(w.resolve_codec('windows-1251'), 'cp1251')
        self.assertEqual(w.resolve_codec('DOS'), 'cp866')
        self.assertEqual(w.resolve_codec('koi8'), 'koi8_r')
        self.assertEqual(w.resolve_codec('mac-cyrillic'), 'mac_cyrillic')
        with self.assertRaises(w.UsageError):
            w.resolve_codec('no-such-codec')
        p = self.path('x.txt', b'abc\r\n')
        code, out, err = run_cli(['-f', 'no-such-codec', p])
        self.assertEqual(code, 2)
        self.assertIn('unknown encoding', err)


# --------------------------------------------------------------------------- 11. binary


class TestBinary(unittest.TestCase):
    def test_control_bytes(self):
        a = w.analyze(b'abc\x00def')
        self.assertEqual((a.kind, a.binary_reason), ('binary', 'NUL at byte 3'))
        a = w.analyze(b'abc\x01def')
        self.assertEqual((a.kind, a.binary_reason), ('binary', 'control byte 0x01 at byte 3'))
        a = w.analyze(b'abc\x1adef')             # interior ^Z is binary, only a trailing run is text
        self.assertEqual(a.kind, 'binary')
        a = w.analyze(random.Random(7).randbytes(4096))
        self.assertEqual(a.kind, 'binary')
        self.assertIsNone(convert(b'abc\x00def'))

    def test_signatures(self):
        for data, name in ((b'%PDF-1.4\n1 0 obj\n', 'pdf'), (b'{\\rtf1\\ansi text}', 'rtf'),
                           (b'PK\x03\x04\x14\x00', 'zip'), (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole2'),
                           (b'MZ\x90\x00', 'exe'), (b'\x7fELF\x02', 'elf'), (b'\x1f\x8b\x08', 'gzip')):
            a = w.analyze(data)
            self.assertEqual(a.kind, 'binary', data)
            self.assertEqual(a.binary_reason, f'{name} signature')

    def test_text_control_chars_and_trailing_ctrlz(self):
        data = b'\x1b[1mbold\x1b[0m\ttab\x0cform feed\r\nlast\r\n\x1a\x1a'
        a = w.analyze(data)
        self.assertEqual(a.kind, 'text')
        self.assertTrue(a.ctrlz)
        out, _, changes, _ = w.convert_bytes(data)
        self.assertEqual(out, b'\x1b[1mbold\x1b[0m\ttab\x0cform feed\nlast\n')
        self.assertEqual(changes, ['ctrlz', 'crlf→lf'])


# --------------------------------------------------------------------------- 12. utf-16 / utf-32


WIDE_TEXT = 'Привет, мир!\r\nВторая строка № 5 — тест…\r\n'
WIDE_OUT = WIDE_TEXT.replace('\r\n', '\n').encode('utf-8')


class TestUtf16Utf32(unittest.TestCase):
    def test_with_bom_sure(self):
        for codec in ('utf-16-le', 'utf-16-be', 'utf-32-le', 'utf-32-be'):
            data = '\ufeff'.encode(codec) + WIDE_TEXT.encode(codec)
            a = w.analyze(data)
            self.assertEqual((a.kind, a.wide, a.has_bom), ('text', codec, True), codec)
            self.assertEqual((a.detection.encoding, a.detection.level), (codec, 'sure'))
            self.assertEqual(a.n_crlf, 2, codec)          # EOL counted on the decoded text
            out, _, changes, _ = w.convert_bytes(data)
            self.assertEqual(out, WIDE_OUT, codec)
            self.assertIn('crlf→lf', changes)
            self.assertIn(f'{codec}→utf-8', changes)

    def test_without_bom_unsure_not_binary(self):
        for text in (WIDE_TEXT, 'hello world\r\nsecond line\r\n'):
            for codec in ('utf-16-le', 'utf-16-be'):
                a = w.analyze(text.encode(codec))
                self.assertEqual(a.kind, 'text', f'{codec} {text!r}')
                self.assertEqual((a.detection.encoding, a.detection.level), (codec, 'unsure'))
                self.assertFalse(a.has_bom)
                self.assertTrue(any('without BOM' in n for n in a.notes), a.notes)
                self.assertEqual(convert(text.encode(codec)), text.replace('\r\n', '\n').encode('utf-8'))

    def test_corrupt(self):
        a = w.analyze(b'\xff\xfe' + WIDE_TEXT.encode('utf-16-le') + b'\x04')
        self.assertEqual(a.kind, 'error')
        self.assertIn('corrupt utf-16', a.error)
        self.assertIsNone(convert(b'\xff\xfe' + WIDE_TEXT.encode('utf-16-le') + b'\x04'))
        a = w.analyze(b'\xfe\xff' + b'\xd8\x00\x00\x41')       # lone high surrogate
        self.assertEqual(a.kind, 'error')


# --------------------------------------------------------------------------- 13. transform


class TestTransform(unittest.TestCase):
    def test_line_endings(self):
        self.assertEqual(convert(b'a\r\nb\rc\n'), b'a\nb\rc\n')          # lone CR kept
        self.assertEqual(convert(b'a\r\r\nb'), b'a\nb')                  # \r\r\n collapses
        out, a, changes, _ = w.convert_bytes(b'line1\rline2\rline3\r')   # Mac-only file
        self.assertTrue(a.mac_file)
        self.assertEqual(out, b'line1\nline2\nline3\n')
        self.assertIn('cr→lf', changes)
        a = w.analyze(b'a\r\nb\rc\n')
        self.assertEqual((a.n_crlf, a.n_cr, a.n_lf, a.mac_file), (1, 1, 1, False))

    def test_ctrlz_bom_and_no_newline_added(self):
        self.assertEqual(convert(b'hello\x1a\x1a'), b'hello')
        self.assertEqual(convert('\ufeffabc\ufeffdef'.encode('utf-8')), 'abc\ufeffdef'.encode('utf-8'))
        self.assertEqual(convert(b'\xef\xbb\xbf\xef\xbb\xbfabc'), b'abc')     # a double BOM is still leading
        text, changes = w.transform('\ufeffx\ufeffy', w.Analysis(kind='text'))
        self.assertEqual((text, changes), ('x\ufeffy', ['bom']))
        self.assertEqual(convert(b'no newline'), b'no newline')
        self.assertEqual(convert(SAMPLES[0].encode('cp1251')), SAMPLES[0].encode('utf-8'))
        self.assertEqual(convert(b'trailing\r\n'), b'trailing\n')
        self.assertEqual(convert(b'  \r\n\r\n'), b'  \n\n')

    def test_idempotent_on_all_fixtures(self):
        fixtures = [b'a\r\nb\rc\n', b'a\r\r\nb', b'line1\rline2\r', b'hello\x1a\x1a',
                    b'\xef\xbb\xbf' + PROSE.encode('cp1251'), '\ufeff'.encode('utf-16-le') + WIDE_TEXT.encode('utf-16-le'),
                    SAMPLES[0].encode('cp1251') + b'\r\n' + SAMPLES[1].encode('utf-8') + b'\r\n',
                    BOX_TABLE.encode('cp866'), NFO_HEADER.encode('cp866')]
        fixtures += [crlf('\n'.join(SAMPLES)).encode(c) + b'\r\n\x1a' for c in CODECS]
        fixtures += [data for _, data in example_copies()]
        for data in fixtures:
            once, a1, changes1, _ = w.convert_bytes(data)
            self.assertIsNotNone(once, data[:40])
            twice, a2, changes2, _ = w.convert_bytes(once)
            self.assertEqual(twice, once, data[:40])
            self.assertEqual(changes2, [], (data[:40], changes2))
            self.assertIn(a2.detection.encoding, ('ascii', 'utf-8'))

    def test_example_copies_convert_as_planned(self):
        for name, data in example_copies():
            out, a, changes, replaced = w.convert_bytes(data)
            self.assertEqual(replaced, 0, name)
            self.assertEqual(a.detection.level, 'sure', name)
            self.assertEqual(a.detection.encoding, fixture_codec(name), name)
            self.assertEqual(out, expected_conversion(name, data), name)
            if data.startswith(b'\xef\xbb\xbf'):
                self.assertIn('bom', changes, name)
            if out == data:
                self.assertEqual(changes, [], name)


# --------------------------------------------------------------------------- 14. table integrity


class TestTableIntegrity(unittest.TestCase):
    def test_bigram_table(self):
        tokens = w.BIGRAM_TABLE_STR.split()
        self.assertEqual(len(tokens), 308)
        keys = [t[:2] for t in tokens]
        self.assertEqual(len(set(keys)), 308, 'duplicate bigram keys')
        for tok in tokens:
            key, lift = tok[:2], float(tok[2:])
            self.assertRegex(key, '^[а-яё]{2}$', tok)
            self.assertTrue(0.1 <= lift <= 8.0, tok)
        self.assertEqual(len(w.LOG_LIFT), 308)
        lo, hi = math.log(0.1), math.log(8.0)
        for key, value in w.LOG_LIFT.items():
            self.assertTrue(lo - 1e-9 <= value <= hi + 1e-9, (key, value))
        self.assertEqual(sum(1 for k in keys if 'ъ' in k), 8)
        self.assertAlmostEqual(w.LOG_LIFT_FLOOR, math.log(0.2))
        self.assertAlmostEqual(sum(math.exp(v) for v in w.LOG_UNI.values()), 1.0, places=9)
        self.assertEqual(set(w.LOG_UNI), set('абвгдежзийклмнопрстуфхцчшщъыьэюяё'))


if __name__ == '__main__':
    unittest.main()
