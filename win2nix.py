#!/usr/bin/env python3
"""win2nix - bring Windows-era text files into Linux form.

Detects the encoding (UTF-8, CP1251, CP866, KOI8-R; UTF-16/32 by BOM), strips a UTF-8 BOM,
converts CRLF to LF and re-encodes to UTF-8.  Confident decisions overwrite the file in place;
unsure ones are backed up first (<name>.w2n.bak).  Standard library only.
"""
from __future__ import annotations

import argparse
import atexit
import codecs
import io
import math
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field

__version__ = '1.0.0'

# --------------------------------------------------------------------------- constants

CANDIDATES = ('cp1251', 'cp866', 'koi8_r')
EIGHT_BIT = set(CANDIDATES)
DISPLAY = {
    'cp1251': 'cp1251', 'cp866': 'cp866', 'koi8_r': 'koi8-r', 'koi8_u': 'koi8-u', 'cp1125': 'cp1125',
    'mac_cyrillic': 'mac-cyrillic', 'iso8859_5': 'iso-8859-5', 'utf-8': 'utf-8', 'ascii': 'ascii',
    'utf-16': 'utf-16', 'utf-16-le': 'utf-16-le', 'utf-16-be': 'utf-16-be',
    'utf-32-le': 'utf-32-le', 'utf-32-be': 'utf-32-be',
}
ENC_ALIASES = {
    'cp1251': 'cp1251', 'windows-1251': 'cp1251', 'windows1251': 'cp1251', 'win-1251': 'cp1251',
    'win1251': 'cp1251', 'win': 'cp1251', '1251': 'cp1251', 'ansi': 'cp1251',
    'cp866': 'cp866', 'ibm866': 'cp866', 'ibm-866': 'cp866', 'dos': 'cp866', '866': 'cp866', 'oem': 'cp866',
    'koi8-r': 'koi8_r', 'koi8r': 'koi8_r', 'koi8_r': 'koi8_r', 'koi8': 'koi8_r',
    'koi8-u': 'koi8_u', 'koi8u': 'koi8_u', 'koi8_u': 'koi8_u',
    'mac-cyrillic': 'mac_cyrillic', 'maccyrillic': 'mac_cyrillic', 'mac_cyrillic': 'mac_cyrillic',
    'iso-8859-5': 'iso8859_5', 'iso8859-5': 'iso8859_5', 'iso8859_5': 'iso8859_5',
    'utf-8': 'utf-8', 'utf8': 'utf-8',
    'utf-16': 'utf-16', 'utf16': 'utf-16',
    'utf-16le': 'utf-16-le', 'utf-16-le': 'utf-16-le', 'utf16le': 'utf-16-le',
    'utf-16be': 'utf-16-be', 'utf-16-be': 'utf-16-be', 'utf16be': 'utf-16-be',
    'utf-32le': 'utf-32-le', 'utf-32-le': 'utf-32-le', 'utf-32be': 'utf-32-be', 'utf-32-be': 'utf-32-be',
}
UNICODE_WIDE = ('utf-16', 'utf-16-le', 'utf-16-be', 'utf-32', 'utf-32-le', 'utf-32-be')

PRIOR = {'utf-8': 0.0, 'cp1251': math.log(0.5), 'cp866': math.log(0.25), 'koi8_r': math.log(0.25)}

_RU_UNIGRAM = {
    'о': 10.97, 'е': 8.45, 'а': 8.01, 'и': 7.35, 'н': 6.70, 'т': 6.26, 'с': 5.47, 'р': 4.73, 'в': 4.54,
    'л': 4.40, 'к': 3.49, 'м': 3.21, 'д': 2.98, 'п': 2.81, 'у': 2.62, 'я': 2.01, 'ы': 1.90, 'ь': 1.74,
    'г': 1.70, 'з': 1.65, 'б': 1.59, 'ч': 1.44, 'й': 1.21, 'х': 0.97, 'ж': 0.94, 'ш': 0.73, 'ю': 0.64,
    'ц': 0.48, 'щ': 0.36, 'э': 0.32, 'ф': 0.26, 'ъ': 0.04, 'ё': 0.30,
}
_total = sum(_RU_UNIGRAM.values())
LOG_UNI = {k: math.log(v / _total) for k, v in _RU_UNIGRAM.items()}

# bigram lift table P(ab)/(P(a)P(b)), derived from the user's own CP1251 corpus, clipped to [0.1, 8]
BIGRAM_TABLE_STR = (
    'то2.44 ть8.00 на3.28 по4.38 ст3.99 ро2.72 ат1.89 ра3.13 пр7.65 но1.91 ни2.92 ит2.16 де3.71 ка3.40 '
    'ен2.21 от1.24 не2.08 та1.49 ре2.64 ов2.36 ос1.64 ко2.32 до2.30 ет1.39 ем3.17 од2.20 ак2.60 ел2.84 '
    'ер2.16 ла2.55 за5.84 ва2.38 да2.48 ли3.29 во1.75 ан1.35 те1.11 ес1.62 го4.74 ол1.74 ри2.22 ор1.33 '
    'ти1.26 ом1.76 ал1.98 ль6.37 мо1.63 ав1.70 об3.03 тр1.58 ад1.79 ме2.00 чт4.27 ог3.64 он0.78 ло1.30 '
    'ве1.61 че3.71 ся5.02 ле1.67 ин1.21 ас1.05 ие0.91 ма1.60 ки1.94 бо2.44 ам1.52 им1.94 же6.02 се1.02 '
    'ил1.79 ис1.19 со0.70 ед1.33 ой3.55 ви1.52 ку3.70 оп0.98 ны3.77 эт8.00 ик1.52 ск1.88 ож3.77 ае0.51 '
    'уд3.47 ди1.47 ок0.87 бы8.00 ое0.38 аз2.41 вы5.15 ча2.24 бу6.34 хо4.30 ар0.77 ру2.35 сл1.61 пе1.03 '
    'ия2.40 пи1.25 ег2.71 чи2.69 ля4.28 аб1.84 ну1.64 ми1.24 ня2.44 из2.68 оч1.56 тв0.89 жн4.94 ус1.79 '
    'вс1.31 ай2.97 ты2.04 си0.74 нт0.54 ек0.85 ьн1.59 ач1.74 кт0.87 дн1.10 ап0.78 мы4.32 ир0.78 ут1.07 '
    'ту1.06 сп1.26 са0.50 па0.74 ду2.23 ей2.81 му2.31 ци8.00 еш4.10 тс0.51 ый8.00 ят1.41 бе1.45 ив0.81 '
    'нн0.55 ьс1.47 кр1.18 ше3.70 пл1.51 сс0.69 уч4.08 ая1.11 гр2.92 ез1.41 сд0.90 ич1.57 ид0.70 оз0.99 '
    'зн1.75 уж6.63 бр2.00 ги1.82 лу1.55 ои0.22 ыт1.21 ев0.49 вт0.50 вн0.64 ши3.43 нь0.94 ые1.13 тк0.51 '
    'мн0.71 ще6.07 уп1.45 кл1.09 дл1.10 св0.72 см0.80 еч1.07 ба0.92 шь8.00 еб0.98 пу1.37 ры1.81 ий2.06 '
    'вл0.97 чн1.35 жи2.29 аж1.72 аш2.26 лю6.53 ии0.30 ую8.00 зд2.25 сь0.93 ке0.43 аю2.58 га1.06 су0.83 '
    'ыв1.94 тн0.25 ук1.15 ыл2.00 це3.63 би1.01 сё8.00 ых8.00 др0.65 рн0.39 вр0.62 гд2.24 ещ4.52 чу2.33 '
    'зо0.63 ац3.08 бл1.68 ум1.09 сн0.33 зв1.73 вк0.73 сы1.18 ур0.76 ех1.81 ее0.15 аг0.81 ха1.59 ву0.86 '
    'рт0.26 ул0.91 ьк0.96 их2.06 ря1.04 иа0.16 иц3.41 шк3.62 иш2.00 ша1.45 кс0.44 жд2.60 фо2.47 уб1.66 '
    'щи4.22 жа1.05 ош1.13 ию2.24 бщ8.00 фи3.91 еп0.27 гу2.08 рг1.27 рв0.43 гл1.60 рм0.48 ах1.29 уг2.02 '
    'лж2.34 ьш4.31 фа2.76 уш3.98 уе0.33 ды1.25 ио0.10 нд0.33 щё8.00 нк0.32 ох0.99 зу1.63 иб0.62 нс0.22 '
    'иг0.80 зи0.66 оц1.58 оя0.34 уз1.51 мя1.04 зм1.23 ср0.27 вь0.64 ью4.42 ым1.11 тя0.42 лн0.27 бя1.81 '
    'мм0.51 йт0.75 ца1.67 ыс0.67 дв0.41 рс0.24 йс1.09 еа0.10 чк0.93 оо0.10 пы0.97 ип0.24 нг0.69 мс0.30 '
    'ют1.21 зы2.00 мп0.42 еж0.70 тп0.18 юч5.42 бъ8.00 дъ8.00 съ8.00 зъ8.00 ъе7.00 ъя8.00 ъю8.00 ъё8.00'
)


def parse_bigram_table(s: str) -> dict[str, float]:
    table = {}
    for tok in s.split():
        table[tok[:2]] = math.log(float(tok[2:]))
    return table


LOG_LIFT = parse_bigram_table(BIGRAM_TABLE_STR)
LOG_LIFT_FLOOR = math.log(0.2)

COMMON_WORDS = set(
    'и в не на я что с он а как это по но она они к у ты из мы за вы так же от о все всё его то только '
    'еще ещё бы уже если или для есть был было были при ни нет да ну вот там где когда чем кто надо нужно '
    'может быть даже после через без до тоже очень мне меня тебе себя себе их них нас вас сам сама само '
    'сами тут здесь потом тогда теперь можно нельзя'.split()
)

# ~500 most frequent Russian word forms: a decode with none of them is not Russian text, however good its letters look
TOP_WORDS = set((
    'и в не на я что он с а как это по но она они к у ты из мы за вы так же от о все всё его то только еще ещё бы '
    'уже если или для есть был было были при ни нет да ну вот там где когда чем кто надо нужно может быть даже после '
    'через без до тоже очень мне меня тебе тебя себя себе их них нас вас сам сама само сами тут здесь потом тогда '
    'теперь можно нельзя этот эта эти этого этом этой этим этих тот та те того том той тем тех такой такая такое '
    'такие который которая которое которые которого которой которых которым весь вся всю всего всей всем всех всеми '
    'один одна одно одни одного одной одним два две три четыре пять десять сто много мало больше меньше лучше хуже '
    'мой моя моё мое мои моего моей твой твоя твоё твое твои наш наша наше наши нашего нашей ваш ваша ваше ваши свой '
    'своя своё свое свои своего своей своих своим свою ему ей им ими него неё нее нему ней них ним '
    'человек человека человеку люди людей время времени раз года год лет день дня дни жизнь жизни рука руки руку '
    'дело дела дом дома глаза голова голову слово слова место места работа работы работу друг друга конец начало '
    'сторона стороны вопрос ответ город мир война земля вода свет ночь утро вечер неделя месяц час часа минут '
    'отец мать мама папа сын дочь жена муж дети ребёнок ребенок брат сестра семья имя лицо тело сердце душа '
    'книга книги письмо деньги денег сила страна народ история причина случай пример часть части число '
    'сказать сказал сказала сказали говорить говорит говорил говорю говорят знать знаю знает знал знаешь думать '
    'думаю думал думает хотеть хочу хочет хотел хотела хотят мочь могу может могут мог могла могли смочь '
    'идти иду идёт идет шёл шел шла шли пойти пошёл пошел видеть вижу видел видела видишь увидеть смотреть '
    'делать делаю делает делал сделать сделал сделать стать стал стала стали станет жить живу живёт живет жил '
    'взять взял дать дал дала дали даёт дает понять понял поняла понимаю понимает понимать работать работаю '
    'работает работал писать пишу пишет написать написал читать читаю читал найти нашёл нашел искать спросить '
    'спросил ответить ответил получить получил получать сидеть сидел стоять стоял стоит лежать лежит ждать жду '
    'ждал казаться кажется казалось должен должна должны значит есть будет будут буду будем будешь быть бывает '
    'можешь нужен нужна нужны пора надо хорошо плохо просто вообще именно конечно наверное точно правда '
    'очень совсем почти всегда никогда иногда часто снова опять сейчас сегодня завтра вчера скоро давно сразу '
    'вместе потому почему зачем откуда куда туда сюда оттуда везде нигде ничего никто никого ничто нечего кое '
    'что-то кто-то где-то как-то какой какая какое какие каждый каждая каждое каждые другой другая другое другие '
    'новый новая новое новые старый старая старое старые большой большая большое большие маленький маленькая '
    'хороший хорошая хорошее хорошие плохой первый первая первое первые второй последний последняя сам самый '
    'самая самое самые главный главное общий целый целом полный весь ещё более менее между около против кроме '
    'вместо ради среди перед над под про об обо во ко со из-за из-под сквозь мимо вдоль вокруг после прежде '
    'потому поэтому затем зато однако хотя чтобы пусть ведь лишь будто словно также тоже либо нибудь ли бы же '
    'спасибо пожалуйста привет пока ладно давай давайте '
    # more everyday forms: pronouns, weekdays, months, planning vocabulary
    'нам вам нём нем ней ею ею её ее эту этому этими тому этим ту ту тою кем чем чего чему чём ком кому '
    'понедельник вторник среда четверг пятница суббота воскресенье утром днём днем вечером ночью '
    'январь февраль март апрель май июнь июль август сентябрь октябрь ноябрь декабрь января февраля марта '
    'апреля мая июня июля августа сентября октября ноября декабря '
    'план планы задача задачи задачу список вопросы вариант варианты проект проекта решение решить купить '
    'сделаем делаем сделай проверить посмотреть попробовать попробуем добавить убрать найти написать позвонить '
    'отправить получить создать настроить выбрать составить придумать поехать ехать едем поедем сходить '
    'например сначала дальше далее итак итого потом затем кроме также возможно наверно реально вообще '
    'сколько столько немного чуть почти ровно равно примерно около важно нужно можно должно получается '
    'происходит кажется хочется осталось получится вроде короче общем случае поводу поэтому причём причем '
    'код файл файлы папка программа программу приложение система системы данные данных сервис метод '
    'телефон машина машину дом квартира деньги работа работу отпуск здоровье цель цели идея идеи опыт '
    'уровень порядок проблема проблемы результат ситуация способ смысл форма вид тип часть пункт шаг '
    'да нет ок окей хорошо отлично ладно точно верно правильно неправильно плохо так-то '
    # Ukrainian / Belarusian function words spelled with Russian-range letters
    'що як та це цей ця вона вони вже ще коли тому дуже може треба добре день рік час люди робота слово '
    'життя був була було були його там тут але чи за по якщо або також тільки тепер завжди сьогодні завтра '
    'вчора що-то хто що-небудь нього неї нас вас ми ви ти я вас '
    'што гэта гэты гэтая гэтае гэтыя ён яна яны ёсць быў яго яе усё усе ужо яшчэ калі дзе таму толькі '
    'вельмі можа трэба можна добра дзень год час людзі праца слова жыццё цяпер потым заўтра сёння учора'
).split())
COMMON_WORDS |= TOP_WORDS

SINGLE_COST = -4.5          # an isolated Cyrillic letter: neutral evidence under every candidate
CASE_PENALTY = -5.0         # word whose case pattern is not lower / UPPER / Title
COMMON_BONUS = 1.5
KNOWN_MIN = 2               # dictionary words needed for 'sure' ...
LOWER_MIN_WORDS = 6         # ... or one, when >= 6 words and
LOWER_RATIO = 0.70          # ... >= 70% of them are lowercase/Title-case
RUN_COST = -4.0             # 4th and further identical consecutive letters
LATIN_ADJ_COST = -3.0       # Latin letter glued to a Cyrillic one
BOX_ADJ_COST = -1.5         # box-drawing glued to a Cyrillic letter
UTF8_CHAR_BONUS = 0.5       # per decoded non-ASCII char, utf-8 candidate only

COMMON_PUNCT = set('«»—–…•“”‘’„№°±§©®· ')
RARE_PUNCT = set('‚†‡€‰‹›™¦¬­µ¶¤')
BOX_LINE = set('─│═║▀▄█▌▐░▒▓■')
BOX_EXTRA = set('■∙√≈≤≥⌠⌡÷²')
UKR_I = set('іІ')
UKR = set('їЇєЄґҐ')
BEL = set('ўЎ')
SERB = set('ђЂѓЃљЉњЊќЌћЋџЏјЈѕЅ')
BOX_COST = {                # (first, same-as-previous line char, other repeat)
    'cp866': (-4.5, -1.5, -3.5),
    'koi8_r': (-6.5, -2.5, -4.5),
    'utf-8': (-5.0, -1.5, -3.5),
    'cp1251': (-12.0, -12.0, -12.0),
}
OTHER_CHAR_COST = -12.0

T_SURE = 15.0
N_EV_MIN = 24
WORDS3_MIN = 3
FLOOR = -4.0
N_FLOOR = 32
SURE_FLOOR = -3.4          # words_LL / n_ev needed for 'sure'
SURE_MEAN_LIFT = 0.0       # mean bigram log-lift needed for 'sure'
G2_MIN_BIGRAMS = 10
G2_MEAN_LIFT = -0.3
G4_MIN_SERB = 2
UTF16_RATIO = 0.80
UTF16_TEXT_HI = {0x00, 0x04, 0x20, 0x21}
SCORE_SLICE = 1 << 20
SCORE_WINDOW = 512 << 10
VOTE_MIN_HI = 8
VOTE_MAX_LINES = 20000
VOTE_LINE_MAX = 64 << 10    # score at most this much of one line when voting
VOTE_MARGIN = 15.0
VOTE_MIN_EV = 12
VOTE_MIN_WORDS3 = 2
MAX_SIZE = 64 << 20

MAGIC = (
    (b'%PDF-', 'pdf'), (b'{\\rtf', 'rtf'), (b'PK\x03\x04', 'zip'), (b'\xd0\xcf\x11\xe0', 'ole2'),
    (b'MZ', 'exe'), (b'\x7fELF', 'elf'), (b'\x89PNG', 'png'), (b'\xff\xd8\xff', 'jpeg'), (b'GIF8', 'gif'),
    (b'Rar!', 'rar'), (b'\x1f\x8b', 'gzip'), (b'BZh', 'bzip2'), (b'7z\xbc\xaf', '7z'),
    (b'SQLite format 3', 'sqlite'),
)
SHARED_1251_1252 = frozenset(
    [0x82, 0x84, 0x85, 0x86, 0x87, 0x89, 0x8B, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x99, 0x9B,
     0xA0, 0xA4, 0xA6, 0xA7, 0xA9, 0xAB, 0xAC, 0xAD, 0xAE, 0xB0, 0xB1, 0xB5, 0xB6, 0xB7, 0xBB]
)
BACKUP_SUFFIX = '.w2n.bak'
BACKUP_RE = re.compile(r'\.w2n(\.\d+)?\.bak$')
TMP_PREFIX = '.w2n-tmp-'
VCS_DIRS = frozenset({'.git', '.svn', '.hg', '.bzr'})

CONTROL_BYTES_RE = re.compile(rb'[\x00-\x06\x0e-\x1a\x1c-\x1f\x7f]')
CONTROL_TEXT_RE = re.compile('[\x00-\x06\x0e-\x1a\x1c-\x1f\x7f]')
CYR_WORD_RE = re.compile('[А-Яа-яЁё]+')
NON_ASCII_RE = re.compile('[^\x00-\x7f]')
BOX_RUN_RE = re.compile('[─-◿∙√≈≤≥⌠⌡÷²]+')
LATIN_ADJ_RE = re.compile('[A-Za-z][А-Яа-яЁё]|[А-Яа-яЁё][A-Za-z]')
BOX_ADJ_RE = re.compile('[А-Яа-яЁё][─-◿]|[─-◿][А-Яа-яЁё]')
RAW_ADJ_RE = re.compile(rb'(?=([A-Za-z][\x80-\xff]|[\x80-\xff][A-Za-z]))')
CYRILLIC_ANY_RE = re.compile('[Ѐ-ӿ]')
MAC_CAP_RE = re.compile('[‚„…†‡€‰‹‘’“”•–—™›](?=[а-яё]{2})')      # a Mac-Cyrillic capital read as cp1251 typography
MAC_YA_RE = re.compile('[а-яё][ЯЮ](?![А-ЯЁ])')                      # Mac 'я'/'ё' read as cp1251 'Я'/'Ю' inside a word
KOI8U_IN_WORD_RE = re.compile('[А-Яа-яЁё][\u2500-\u25ff][А-Яа-яЁё]')
CP1125_IN_WORD_RE = re.compile('[А-Яа-я][ЄєЇїЎў°∙·][А-Яа-я]')
CRLF_RE = re.compile('\r+\n')
CRLF_BYTES_RE = re.compile(rb'\r+\n')


class _ReplaceCounter:
    """Error handler that counts undecodable sequences while replacing them with U+FFFD."""

    def __init__(self):
        self.count = 0

    def __call__(self, exc):
        self.count += 1
        return ('�', exc.end)


_REPLACE_COUNTER = _ReplaceCounter()
codecs.register_error('w2n_replace', _REPLACE_COUNTER)

# --------------------------------------------------------------------------- data


@dataclass
class Evidence:
    n_ev: int = 0           # letters inside Cyrillic words of >= 2 letters
    words3: int = 0         # Cyrillic words of >= 3 letters
    nbig: int = 0           # scored bigrams
    meanlift: float | None = None
    words_LL: float = 0.0   # sum of word terms
    n_chars: int = 0        # decoded non-ASCII characters
    n_words: int = 0        # Cyrillic words of >= 2 letters
    known: int = 0          # ... of them found in the built-in dictionary
    n_lower: int = 0        # ... of them lowercase or Title-case (case-swapped misreadings are ALL CAPS)


@dataclass
class Detection:
    encoding: str
    level: str                          # sure | unsure | unknown | forced
    margin: float = 0.0
    n_hi: int = 0
    scores: dict = field(default_factory=dict)
    evidence: Evidence = field(default_factory=Evidence)
    reason: str = ''
    notes: list = field(default_factory=list)
    votes: dict = field(default_factory=dict)
    first_vote_line: int | None = None


@dataclass
class Analysis:
    kind: str                           # empty | binary | text | mixed | error
    has_bom: bool = False
    wide: str | None = None             # utf-16-le / utf-16-be / utf-32-le / utf-32-be
    n_crlf: int = 0
    n_cr: int = 0
    n_lf: int = 0
    mac_file: bool = False
    ctrlz: bool = False
    detection: Detection | None = None
    binary_reason: str | None = None
    error: str | None = None
    mixed_info: tuple | None = None     # (utf8_lines, bad_lines, first_utf8_line, first_bad_line)
    notes: list = field(default_factory=list)
    decoded_text: str | None = None     # for UTF-16/32 inputs (already decoded strictly)


@dataclass
class Job:
    src: str
    display: str
    rel: str
    dest: str | None = None
    inplace: bool = True
    st: os.stat_result | None = None
    skip_reason: str | None = None
    link_target: str | None = None
    is_error: bool = False
    dest_display: str | None = None


@dataclass
class Result:
    job: Job
    status: str                         # converted | written | copied | ok | skipped | error | would
    encoding_label: str = ''
    changes: list = field(default_factory=list)
    action: str = ''
    backup: str | None = None
    out: str | None = None
    is_error: bool = False
    would_change: bool = False
    details: str = ''
    unsure: bool = False
    skip_kind: str = ''
    flags: list = field(default_factory=list)
    changed: bool = False


@dataclass
class Context:
    console: 'Console'
    temp_files: set = field(default_factory=set)
    yes_all: bool = False
    no_all: bool = False
    quit: bool = False
    chown_warned: bool = False
    results: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    subdirs_skipped: int = 0
    vcs_skipped: int = 0
    out_real: str | None = None


class UsageError(Exception):
    pass


class FileChangedError(Exception):
    pass

# --------------------------------------------------------------------------- detection helpers


def count_high_bytes(data: bytes) -> int:
    return len(data) - len(data.translate(None, bytes(range(0x80, 0x100))))


def magic_signature(data: bytes) -> str | None:
    head = data[:16]
    for sig, name in MAGIC:
        if head.startswith(sig):
            return name
    return None


def find_binary_reason(data: bytes) -> tuple[str | None, bool]:
    body = data.rstrip(b'\x1a')
    ctrlz = len(body) != len(data)
    m = CONTROL_BYTES_RE.search(body)
    if m:
        b = m.group(0)[0]
        if b == 0:
            return f'NUL at byte {m.start()}', ctrlz
        return f'control byte 0x{b:02x} at byte {m.start()}', ctrlz
    return None, ctrlz


def detect_utf32_bom(data: bytes) -> str | None:
    if data.startswith(b'\xff\xfe\x00\x00'):
        return 'utf-32-le'
    if data.startswith(b'\x00\x00\xfe\xff'):
        return 'utf-32-be'
    return None


def detect_utf16(data: bytes) -> tuple[str | None, bool]:
    """Return (codec, has_bom) for UTF-16 input, or (None, False)."""
    if data.startswith(b'\xff\xfe'):
        return 'utf-16-le', True
    if data.startswith(b'\xfe\xff'):
        return 'utf-16-be', True
    if len(data) < 4 or len(data) % 2:
        return None, False
    for codec, hi in (('utf-16-le', data[1::2]), ('utf-16-be', data[0::2])):
        if hi.count(0) < 1:
            continue
        texty = sum(hi.count(x) for x in UTF16_TEXT_HI)
        if texty < UTF16_RATIO * len(hi):
            continue
        try:
            text = data.decode(codec)
        except UnicodeDecodeError:
            continue
        if CONTROL_TEXT_RE.search(text.rstrip('\x1a')):
            continue
        return codec, False
    return None, False


def count_eol(body) -> tuple[int, int, int, bool]:
    """Return (n_crlf, n_cr, n_lf, mac_file) for bytes or str."""
    if isinstance(body, bytes):
        groups = CRLF_BYTES_RE.findall(body)
        cr_total = body.count(b'\r')
        lf_total = body.count(b'\n')
    else:
        groups = CRLF_RE.findall(body)
        cr_total = body.count('\r')
        lf_total = body.count('\n')
    n_crlf = len(groups)
    cr_in_groups = sum(len(g) - 1 for g in groups)
    n_cr = cr_total - cr_in_groups
    n_lf = lf_total - n_crlf
    mac_file = n_lf == 0 and n_crlf == 0 and n_cr > 0
    return n_crlf, n_cr, n_lf, mac_file


def _strict_utf8(line: bytes) -> str | None:
    try:
        return line.decode('utf-8')
    except UnicodeDecodeError:
        return None


def _has_cyr_word(s: str) -> bool:
    """At least one Cyrillic word of two or more letters (a single letter can be a coincidence)."""
    return any(len(m.group(0)) >= 2 for m in CYR_WORD_RE.finditer(s))


def _is_exotic(ch: str) -> bool:
    """A character a Russian user's genuine UTF-8 file is very unlikely to contain."""
    o = ord(ch)
    return o >= 0x530 and not (0x2000 <= o <= 0x27bf) and not (0x1f000 <= o <= 0x1faff) and o != 0xfe0f


def _is_benign(ch: str) -> bool:
    """Latin-1 letters/symbols, typography, box drawing, emoji: plausible in a non-Cyrillic UTF-8 file."""
    o = ord(ch)
    return o < 0x100 or ch in COMMON_PUNCT or ch in RARE_PUNCT or 0x2000 <= o <= 0x27bf or \
        0x2500 <= o <= 0x25ff or 0x1f000 <= o <= 0x1faff or o == 0xfe0f


def _line_score(text: str, enc: str) -> float:
    return PRIOR.get(enc, 0.0) + score_text(text, enc)[0]


def _keep_as_utf8(line: bytes, enc: str) -> str | None:
    """Inside a mixed file: the line's UTF-8 reading if it should be kept, else None (decode as `enc`)."""
    if line.isascii():
        return line.decode('ascii')
    s = _strict_utf8(line)
    if s is None:
        return None
    if _has_cyr_word(s):
        return s
    if CYRILLIC_ANY_RE.search(s):
        return None                              # a lone Cyrillic letter: 'С…' in cp1251 is valid UTF-8 'х'
    eight = line.decode(enc, errors='replace')
    if _has_cyr_word(eight) and _line_score(eight, enc) >= _line_score(s, 'utf-8'):
        return None
    return s


def is_mixed(body: bytes, sep: bytes = b'\n') -> tuple | None:
    utf8_lines = bad_lines = 0
    first_utf8 = first_bad = None
    for no, line in enumerate(body.split(sep), 1):
        if line.isascii():
            continue
        try:
            s = line.decode('utf-8')
        except UnicodeDecodeError:
            bad_lines += 1
            if first_bad is None:
                first_bad = no
            continue
        if _has_cyr_word(s):
            utf8_lines += 1
            if first_utf8 is None:
                first_utf8 = no
    if utf8_lines >= 1 and bad_lines >= 1:
        return utf8_lines, bad_lines, first_utf8, first_bad
    return None


def _cut_prefix(line: bytes, n: int) -> bytes:
    """First n bytes, backed off so a UTF-8 sequence is not cut in the middle."""
    cut = n
    while 0 < cut < len(line) and (line[cut] & 0xC0) == 0x80:
        cut -= 1
    return line[:cut]


def _cut_suffix(line: bytes, n: int) -> bytes:
    start = max(0, len(line) - n)
    while start < len(line) and (line[start] & 0xC0) == 0x80:
        start += 1
    return line[start:]


def make_slice(body: bytes, only_bad: bool = False) -> bytes:
    """Lines carrying non-ASCII bytes (optionally only the non-UTF-8 ones), bounded to ~1 MiB."""
    lines = [ln for ln in body.split(b'\n') if not ln.isascii()]
    if only_bad:
        lines = [ln for ln in lines if _strict_utf8(ln) is None]
    if not lines:
        return b''
    total = sum(len(ln) + 1 for ln in lines)
    if total <= SCORE_SLICE:
        return b'\n'.join(lines)
    head, size, i = [], 0, 0
    while i < len(lines) and size + len(lines[i]) + 1 <= SCORE_WINDOW:
        head.append(lines[i])
        size += len(lines[i]) + 1
        i += 1
    if i < len(lines) and not head:          # a single oversized line: take its prefix
        head.append(_cut_prefix(lines[i], SCORE_WINDOW))
        i += 1
    tail, size, j = [], 0, len(lines) - 1
    while j >= i and size + len(lines[j]) + 1 <= SCORE_WINDOW:
        tail.append(lines[j])
        size += len(lines[j]) + 1
        j -= 1
    if j >= i and not tail:
        tail.append(_cut_suffix(lines[j], SCORE_WINDOW))
    tail.reverse()
    return b'\n'.join(head + tail)


def utf8_class_cost(ch: str) -> float:
    o = ord(ch)
    if o <= 0x9f:
        return -12.0
    if o < 0x100:
        return -5.5
    if o < 0x250:
        return -7.0
    if 0x370 <= o <= 0x3ff:
        return -6.5
    if 0x400 <= o <= 0x52f:
        return -7.5
    if 0x530 <= o <= 0x7ff:          # Armenian, Hebrew, Arabic, Syriac, Thaana, NKo
        return -6.5
    if 0x900 <= o <= 0xeff or 0x10a0 <= o <= 0x11ff:   # Indic scripts, Thai, Lao, Georgian, Hangul Jamo
        return -7.0
    if 0x2000 <= o <= 0x27bf:
        return -6.0
    if 0x3040 <= o <= 0x30ff or 0x4e00 <= o <= 0x9fff or 0xac00 <= o <= 0xd7af:
        return -7.0
    if 0xff00 <= o <= 0xffef:
        return -7.0
    if 0x1f000 <= o <= 0x1faff:
        return -6.0
    return -12.0


def char_cost(ch: str, enc: str) -> float:
    if ch in COMMON_PUNCT:
        return -4.5
    if ch in RARE_PUNCT:
        return -6.5
    if ch == '�':
        return -10.0
    if ch in UKR_I:
        return -5.0
    if ch in UKR:
        return -6.5
    if ch in BEL:
        return -7.5
    if ch in SERB:
        return -8.0
    if enc == 'utf-8':
        return utf8_class_cost(ch)
    return OTHER_CHAR_COST


def _is_box(ch: str) -> bool:
    return '─' <= ch <= '◿' or ch in BOX_EXTRA


def score_text(text: str, enc: str) -> tuple[float, Evidence]:
    """Log-likelihood of `text` (a decode under candidate `enc`) under the Russian-text model."""
    ev = Evidence()
    ll = 0.0
    if not text:
        return ll, ev
    ev.n_chars = len(NON_ASCII_RE.findall(text))
    # non-ASCII characters outside Cyrillic words
    rest = CYR_WORD_RE.sub(' ', text)
    cnt = Counter(ch for ch in rest if ord(ch) > 127 and not _is_box(ch))
    for ch, n in cnt.items():
        ll += n * char_cost(ch, enc)
    box_first, box_same, box_other = BOX_COST.get(enc, BOX_COST['cp1251'])
    for m in BOX_RUN_RE.finditer(rest):
        run = m.group(0)
        ll += box_first
        prev = run[0]
        for ch in run[1:]:
            if ch == prev and ch in BOX_LINE:
                ll += box_same
            else:
                ll += box_other
            prev = ch
    # Cyrillic words
    words_ll = 0.0
    sum_lift = 0.0
    for m in CYR_WORD_RE.finditer(text):
        w = m.group(0)
        if len(w) == 1:
            ll += SINGLE_COST
            continue
        lw = w.lower()
        wl = 0.0
        prev = ''
        run = 0
        for ch in lw:
            if ch == prev:
                run += 1
            else:
                run = 1
                prev = ch
            wl += RUN_COST if run >= 4 else LOG_UNI[ch]
        for i in range(len(lw) - 1):
            bg = lw[i:i + 2]
            lift = LOG_LIFT.get(bg)
            if lift is None and 'ё' in bg:
                lift = LOG_LIFT.get(bg.replace('ё', 'е'))
            if lift is None:
                lift = LOG_LIFT_FLOOR
            wl += lift
            sum_lift += lift
        ev.nbig += len(lw) - 1
        if w.islower() or w.istitle():
            ev.n_lower += 1
        elif not w.isupper():
            wl += CASE_PENALTY
        if lw in COMMON_WORDS:
            wl += COMMON_BONUS
            ev.known += 1
        ev.n_words += 1
        ev.n_ev += len(w)
        if len(w) >= 3:
            ev.words3 += 1
        words_ll += wl
    ll += words_ll
    ev.words_LL = words_ll
    ev.meanlift = sum_lift / ev.nbig if ev.nbig else None
    ll += LATIN_ADJ_COST * len(LATIN_ADJ_RE.findall(text))
    ll += BOX_ADJ_COST * len(BOX_ADJ_RE.findall(text))
    if enc == 'utf-8':
        ll += UTF8_CHAR_BONUS * ev.n_chars
    return ll, ev


def score_candidates(slice_: bytes, allow_utf8: bool) -> tuple[dict, dict]:
    scores, evs = {}, {}
    cands = list(CANDIDATES) + (['utf-8'] if allow_utf8 else [])
    for c in cands:
        text = slice_.decode(c, errors='replace')
        ll, ev = score_text(text, c)
        scores[c] = PRIOR[c] + ll
        evs[c] = ev
    return scores, evs


def decide_level(best: str, margin: float, ev: Evidence) -> str:
    if best == 'utf-8':
        return 'sure' if margin >= T_SURE else 'unsure'
    if margin < T_SURE or ev.n_ev < N_EV_MIN or ev.words3 < WORDS3_MIN:
        return 'unsure'
    if ev.words_LL / ev.n_ev < SURE_FLOOR:
        return 'unsure'
    if ev.meanlift is not None and ev.meanlift < SURE_MEAN_LIFT:
        return 'unsure'
    # dictionary evidence: two known words, or one in a mostly lowercase/Title-case reading
    # (the dangerous cp1251<->koi8-r misreadings of ordinary text come out ALL CAPS)
    if ev.known >= KNOWN_MIN:
        return 'sure'
    if ev.known >= 1 and ev.n_words >= LOWER_MIN_WORDS and ev.n_lower >= LOWER_RATIO * ev.n_words:
        return 'sure'
    return 'unsure'


def apply_gates(best: str, slice_: bytes, text: str, ev: Evidence, level: str) -> tuple[str, str, list]:
    """Return (level, unknown_reason, notes) after the G1-G4 plausibility gates."""
    notes = []
    if best == 'utf-8':
        return level, '', notes
    # G1: Latin-script 8-bit text (accented bytes glued inside Latin words)
    n_ns = sum(1 for b in slice_ if b >= 0x80 and b not in SHARED_1251_1252)
    adj = 0
    for m in RAW_ADJ_RE.finditer(slice_):
        pair = m.group(1)
        hb = pair[0] if pair[0] >= 0x80 else pair[1]
        if hb not in SHARED_1251_1252:
            adj += 1
    if adj >= 1 and adj >= 0.5 * n_ns:
        if ev.words3 == 0:
            return 'unknown', 'looks like a Latin-script 8-bit encoding', notes
        level = 'unsure'                     # chess notation, 'в Wordе': real words exist, but check the result
        notes.append('Cyrillic letters glued to Latin ones')
    # G3: absolute floor over Cyrillic words
    if ev.n_ev >= N_FLOOR and ev.words_LL / ev.n_ev < FLOOR:
        return 'unknown', 'does not look like Russian text', notes
    # G2: implausible letter sequences
    if ev.nbig >= G2_MIN_BIGRAMS and ev.meanlift is not None and ev.meanlift < G2_MEAN_LIFT:
        level = 'unsure'
        notes.append('letter sequences look unusual for Russian')
    # G4: Mac Cyrillic / Serbian: Serbian letters, typography where a capital should be, Я/Ю inside lowercase words
    if best == 'cp1251':
        mac = sum(1 for ch in text if ch in SERB) + len(MAC_CAP_RE.findall(text)) + len(MAC_YA_RE.findall(text))
        if mac >= G4_MIN_SERB:
            level = 'unsure'
            notes.append('looks like mac-cyrillic or Serbian; if Mac, use --from mac-cyrillic')
    # G5: Ukrainian supersets of the candidates: foreign letters or box drawing inside words
    if best == 'koi8_r' and len(KOI8U_IN_WORD_RE.findall(text)) >= 2:
        level = 'unsure'
        notes.append('looks like koi8-u; use --from koi8-u')
    elif best == 'cp866' and len(CP1125_IN_WORD_RE.findall(text)) >= 2:
        level = 'unsure'
        notes.append('looks like cp1125; use --from cp1125')
    return level, '', notes


def line_votes(body: bytes, best: str) -> tuple[dict, int | None]:
    """Lines that strongly prefer another 8-bit candidate than the file as a whole."""
    lines = body.split(b'\n')
    idx = [i for i, ln in enumerate(lines) if count_high_bytes(ln) >= VOTE_MIN_HI]
    if len(idx) > VOTE_MAX_LINES:
        k = -(-len(idx) // VOTE_MAX_LINES)
        idx = idx[::k]
    votes: dict = {}
    first = None
    for i in idx:
        ln = lines[i][:VOTE_LINE_MAX]
        scores, evs = {}, {}
        for c in CANDIDATES:
            ll, ev = score_text(ln.decode(c, errors='replace'), c)
            scores[c] = PRIOR[c] + ll
            evs[c] = ev
        ranked = sorted(scores, key=scores.get, reverse=True)
        lb = ranked[0]
        if lb == best:
            continue
        margin = scores[lb] - scores[ranked[1]]
        ev = evs[lb]
        if margin >= VOTE_MARGIN and ev.n_ev >= VOTE_MIN_EV and ev.words3 >= VOTE_MIN_WORDS3:
            votes[lb] = votes.get(lb, 0) + 1
            if first is None:
                first = i + 1
    return votes, first


def detect_encoding(body: bytes, forced: str | None, has_bom: bool, mixed: tuple | None) -> Detection:
    n_hi = count_high_bytes(body)
    if forced:
        return Detection(forced, 'forced', n_hi=n_hi)
    if n_hi == 0:
        return Detection('ascii', 'sure', n_hi=0)
    utf8_ok = False
    if mixed is None:
        try:
            body.decode('utf-8')
            utf8_ok = True
        except UnicodeDecodeError:
            utf8_ok = False
    if utf8_ok and has_bom:
        return Detection('utf-8', 'sure', margin=float('inf'), n_hi=n_hi, reason='bom')
    slice_ = make_slice(body, only_bad=mixed is not None)
    scores, evs = score_candidates(slice_, allow_utf8=utf8_ok)
    ranked = sorted(scores, key=scores.get, reverse=True)
    best, second = ranked[0], ranked[1]
    margin = scores[best] - scores[second]
    ev = evs[best]
    if best in EIGHT_BIT and best != 'cp1251' and margin < 5.0 and ev.words3 == 0 and evs['cp1251'].words3 == 0:
        best, ev = 'cp1251', evs['cp1251']        # typography only, no words anywhere: the prior decides
        margin = scores['cp1251'] - max(v for c, v in scores.items() if c != 'cp1251')
    level = decide_level(best, margin, ev)
    extra_notes = []
    if best == 'utf-8':
        u_text = slice_.decode('utf-8', 'replace')
        non_ascii = [ch for ch in u_text if ord(ch) > 127]
        exotic = any(_is_exotic(ch) for ch in non_ascii)
        benign = all(_is_benign(ch) for ch in non_ascii)
        if ev.n_ev == 0 and exotic:
            # valid UTF-8 by accident?  cp866 words like 'так'/'шаг' decode to CJK/Braille code points
            eight = max(CANDIDATES, key=scores.get)
            eev = evs[eight]
            e_text = slice_.decode(eight, errors='replace')
            plausible = (eev.words3 >= 1 and eev.n_ev > 0 and eev.words_LL / eev.n_ev >= FLOOR
                         and (eev.meanlift is None or eev.meanlift >= G2_MEAN_LIFT)
                         and sum(1 for ch in e_text if ch in SERB) < G4_MIN_SERB)
            if plausible:
                best, ev = eight, eev
                others = [scores[c] for c in scores if c != eight]
                margin = scores[eight] - max(others)
                extra_notes.append('bytes are valid UTF-8 but decode to an exotic script; treated as 8-bit')
            level = 'unsure'
        elif level == 'sure' and ev.n_ev < 2 and not benign:
            # no Cyrillic word in the UTF-8 reading: only Latin/typography content may still be 'sure'
            level = 'unsure'
    text = slice_.decode(best, errors='replace')
    level, reason, notes = apply_gates(best, slice_, text, ev, level)
    notes = extra_notes + notes
    det = Detection(best, level, margin=margin, n_hi=n_hi, scores=scores, evidence=ev, reason=reason, notes=notes)
    if level == 'unknown':
        return det
    if mixed is not None:
        det.level = 'unsure'
    if has_bom and not utf8_ok:
        det.level = 'unsure'
        det.notes.append('BOM present but content is not UTF-8')
    if best in EIGHT_BIT and mixed is None:
        votes, first = line_votes(body, best)
        if votes:
            det.level = 'unsure'
            det.votes = votes
            det.first_vote_line = first
            desc = ', '.join(f'{n} lines look like {DISPLAY[c]}' for c, n in sorted(votes.items()))
            det.notes.append(f'mixed 8-bit: {desc} (first: line {first})')
    return det


def _looks_like_text(text: str) -> bool:
    """>= 80% of characters are ASCII, Cyrillic/Latin/Greek (< U+0530), typography or box drawing."""
    if not text:
        return True
    good = sum(1 for ch in text if ord(ch) < 0x530 or 0x2000 <= ord(ch) <= 0x27bf or '\u2500' <= ch <= '\u25ff')
    return good >= 0.8 * len(text)


def _decode_strict_counting(data: bytes, codec: str) -> tuple[str, int]:
    _REPLACE_COUNTER.count = 0
    text = data.decode(codec, 'w2n_replace')
    return text, _REPLACE_COUNTER.count


def analyze(data: bytes, forced: str | None = None) -> Analysis:
    """Pure analysis of a file's bytes.  `forced` is an internal codec name or None."""
    if not data:
        return Analysis(kind='empty')
    sig = magic_signature(data)
    if sig:
        return Analysis(kind='binary', binary_reason=f'{sig} signature')
    # UTF-16/32 (by BOM, by --from, or by the no-BOM heuristic) are handled on decoded text
    wide = None
    wide_bom = False
    if forced in UNICODE_WIDE:
        wide = forced
        wide_bom = data[:4] in (b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff') or data[:2] in (b'\xff\xfe', b'\xfe\xff')
    elif forced:
        wide = None                               # the user named a single-byte codec
    else:
        wide = detect_utf32_bom(data)
        if wide:
            wide_bom = True
        else:
            wide, wide_bom = detect_utf16(data)
    wide_note = None
    if wide:
        payload = data
        if wide_bom and wide in ('utf-32-le', 'utf-32-be'):
            payload = data[4:]
        elif wide_bom and wide in ('utf-16-le', 'utf-16-be'):
            payload = data[2:]
        text = None
        problem = None
        try:
            text = payload.decode(wide)
        except UnicodeDecodeError as e:
            problem = f'corrupt {DISPLAY.get(wide, wide)}: {e.reason}'
        if text is not None and not forced:
            if CONTROL_TEXT_RE.search(text.rstrip('\x1a')):
                problem = 'control characters after utf-16 decode'
            elif not _looks_like_text(text):
                problem = f'{DISPLAY.get(wide, wide)} BOM but the text does not look like Cyrillic or Latin'
        if problem and not forced:
            if b'\x00' in data:
                if wide_bom and text is not None:
                    return Analysis(kind='text', detection=Detection(wide, 'unknown', reason=problem + '; try --from ' + DISPLAY.get(wide, wide)))
                return Analysis(kind='error' if wide_bom else 'binary', error=problem if wide_bom else None,
                                binary_reason=None if wide_bom else problem)
            # an 8-bit file that merely starts with FF FE / FE FF: fall through to 8-bit detection
            wide_note = f'starts with a UTF-16 BOM but is not UTF-16 ({problem})'
            wide = None
        elif problem:
            return Analysis(kind='error', error=problem)
    if wide:
        n_crlf, n_cr, n_lf, mac = count_eol(text)
        level = 'forced' if forced else ('sure' if wide_bom else 'unsure')
        det = Detection(wide, level, n_hi=count_high_bytes(data))
        a = Analysis(kind='text', has_bom=wide_bom, wide=wide, n_crlf=n_crlf, n_cr=n_cr, n_lf=n_lf,
                     mac_file=mac, ctrlz=text.endswith('\x1a'), detection=det, decoded_text=text)
        if not wide_bom and not forced:
            a.notes.append('utf-16 without BOM (heuristic)')
        return a
    reason, ctrlz = find_binary_reason(data)
    if reason:
        return Analysis(kind='binary', binary_reason=reason, ctrlz=ctrlz)
    has_bom = data.startswith(b'\xef\xbb\xbf')
    body = data[3:] if has_bom else data
    n_crlf, n_cr, n_lf, mac = count_eol(body)
    mixed = None
    if not body.isascii():
        mixed = is_mixed(body, b'\r' if mac else b'\n')
    det = detect_encoding(body, forced, has_bom, mixed)
    kind = 'mixed' if mixed else 'text'
    a = Analysis(kind=kind, has_bom=has_bom, n_crlf=n_crlf, n_cr=n_cr, n_lf=n_lf, mac_file=mac,
                 ctrlz=ctrlz, detection=det, mixed_info=mixed)
    if wide_note:
        a.notes.append(wide_note)
    if mixed:
        a.notes.append(f'mixed: {mixed[0]} utf-8 lines (first: line {mixed[2]}), '
                       f'{mixed[1]} 8-bit lines (first: line {mixed[3]})')
    return a

# --------------------------------------------------------------------------- transformation


def decode_body(data: bytes, a: Analysis) -> tuple[str, int]:
    if a.kind == 'empty':
        return '', 0
    if a.decoded_text is not None:
        return a.decoded_text, 0
    det = a.detection
    body = data[3:] if a.has_bom else data
    enc = det.encoding
    if enc == 'ascii':
        return body.decode('ascii', 'w2n_replace'), 0
    if a.kind == 'mixed':
        parts = []
        replaced = 0
        sep = b'\r' if a.mac_file else b'\n'
        for line in body.split(sep):
            kept = _keep_as_utf8(line, enc)
            if kept is not None:
                parts.append(kept)
                continue
            s, n = _decode_strict_counting(line, enc)
            if _strict_utf8(line) is None:
                # a damaged UTF-8 line?  keep the UTF-8 reading when it explains the bytes better
                u, un = _decode_strict_counting(line, 'utf-8')
                if _has_cyr_word(u) and _line_score(u, 'utf-8') > _line_score(s, enc):
                    s, n = u, un
            parts.append(s)
            replaced += n
        return sep.decode('ascii').join(parts), replaced
    if enc == 'utf-8' and det.level != 'forced':
        return body.decode('utf-8'), 0
    return _decode_strict_counting(body, enc)


def transform(text: str, a: Analysis) -> tuple[str, list[str]]:
    changes: list[str] = []
    if text.endswith('\x1a'):
        text = text.rstrip('\x1a')
        changes.append('ctrlz')
    if a.has_bom and a.wide is None:
        changes.append('bom')
    if text.startswith('﻿'):
        text = text[1:]
        if 'bom' not in changes:
            changes.append('bom')
    if '\r' in text:
        new = CRLF_RE.sub('\n', text)
        if new != text:
            changes.append('crlf\u2192lf')
            text = new
        if a.mac_file and '\r' in text:
            text = text.replace('\r', '\n')
            changes.append('cr\u2192lf')
    det = a.detection
    if det is not None and det.encoding not in ('ascii', 'utf-8'):
        changes.append(f'{DISPLAY.get(det.encoding, det.encoding)}→utf-8')
    return text, changes


def convert_bytes(data: bytes, forced: str | None = None) -> tuple[bytes | None, Analysis, list[str], int]:
    """Analyze + convert in memory.  Returns (output or None, analysis, changes, replaced)."""
    a = analyze(data, forced)
    if a.kind in ('binary', 'error') or (a.detection is not None and a.detection.level == 'unknown'):
        return None, a, [], 0
    text, replaced = decode_body(data, a)
    new_text, changes = transform(text, a)
    return new_text.encode('utf-8'), a, changes, replaced

# --------------------------------------------------------------------------- file layer


def resolve_codec(name: str) -> str:
    key = name.strip().lower()
    if key in ENC_ALIASES:
        return ENC_ALIASES[key]
    try:
        info = codecs.lookup(key)
    except LookupError:
        raise UsageError(f'unknown encoding: {name}')
    canon = {'koi8-r': 'koi8_r', 'koi8-u': 'koi8_u', 'utf-8-sig': 'utf-8', 'utf-16': 'utf-16',
             'mac-cyrillic': 'mac_cyrillic', 'iso8859-5': 'iso8859_5'}.get(info.name, info.name)
    try:
        if not getattr(info, '_is_text_encoding', True):
            raise LookupError
        b'ab'.decode(canon, 'w2n_replace')
    except (LookupError, UnicodeError, TypeError, ValueError):
        raise UsageError(f'{name}: not a text encoding')
    return canon


def fmt_path(p: str) -> str:
    try:
        return p.encode('utf-8', 'surrogateescape').decode('utf-8', 'backslashreplace')
    except Exception:
        return repr(p)


def is_backup_name(name: str) -> bool:
    return bool(BACKUP_RE.search(name)) or name.startswith(TMP_PREFIX)


def resolve_output(target: str, inputs: list[str]) -> tuple[str, str]:
    """Return ('dir'|'file', absolute path)."""
    if os.path.isdir(target):
        return 'dir', os.path.abspath(target)
    if target.endswith('/'):
        if os.path.lexists(target.rstrip('/') or '/'):
            raise UsageError(f"{fmt_path(target)}: exists and is not a directory")
        return 'dir', os.path.abspath(target)
    if len(inputs) != 1:
        raise UsageError(f"-o {fmt_path(target)} names a file but {len(inputs)} inputs were given; "
                         "append / to TARGET to make it a directory")
    src = inputs[0]
    try:
        st = os.lstat(src)
    except OSError as e:
        raise UsageError(f'{fmt_path(src)}: {e.strerror}')
    if stat.S_ISLNK(st.st_mode):
        raise UsageError(f'{fmt_path(src)}: is a symlink; pass the target path instead')
    if stat.S_ISDIR(st.st_mode):
        raise UsageError(f"-o {fmt_path(target)} names a file but {fmt_path(src)} is a directory; "
                         "append / to TARGET")
    if not stat.S_ISREG(st.st_mode):
        raise UsageError(f'{fmt_path(src)}: not a regular file')
    parent = os.path.dirname(os.path.abspath(target))
    if not os.path.isdir(parent):
        raise UsageError(f'{fmt_path(os.path.dirname(target) or ".")}: output directory does not exist')
    return 'file', os.path.abspath(target)


def collect_jobs(paths: list[str], recursive: bool, out_mode: str | None, out_path: str | None,
                 ctx: 'Context', out_display: str | None = None) -> list[Job]:
    jobs: list[Job] = []
    seen: set = set()
    out_real = os.path.realpath(out_path) if out_path else None
    pruned_note = False

    def add_file(src_abs: str, display: str, rel: str, st: os.stat_result, inplace_root: bool):
        key = os.path.realpath(src_abs)
        if key in seen:
            ctx.notes.append(f'{fmt_path(display)}: duplicate of an earlier input, skipped')
            return
        seen.add(key)
        name = os.path.basename(src_abs)
        job = Job(src=src_abs, display=display, rel=rel, st=st)
        if is_backup_name(name):
            job.skip_reason = 'stale temp file (safe to delete)' if name.startswith(TMP_PREFIX) \
                else 'backup file (restore with mv)'
        if out_mode and not inplace_root:
            job.dest = out_path if out_mode == 'file' else os.path.join(out_path, rel)
            shown_target = out_display if out_display is not None else out_path
            job.dest_display = shown_target if out_mode == 'file' else os.path.join(shown_target, rel)
            job.inplace = False
            if os.path.realpath(job.dest) == key:
                job.inplace = True
                ctx.notes.append(f'{fmt_path(display)}: output is the input; converting in place')
        jobs.append(job)

    def add_symlink(src_abs: str, display: str, rel: str):
        try:
            target = os.readlink(src_abs)
        except OSError:
            target = '?'
        jobs.append(Job(src=src_abs, display=display, rel=rel, skip_reason=f'symlink -> {fmt_path(target)}',
                        link_target=target))

    def walk_dir(root: str, root_display: str):
        nonlocal pruned_note
        root_abs = os.path.abspath(root)
        root_real = os.path.realpath(root_abs)
        inplace_root = bool(out_mode == 'dir' and out_real == root_real)
        if inplace_root:
            ctx.notes.append(f'{fmt_path(root_display)}: output is the input directory; converting in place')
        def unreadable(path: str, err: OSError):
            rel = os.path.relpath(path, root_abs)
            display = root_display if rel == '.' else (os.path.join(root_display, rel) if root_display not in ('', '.') else rel)
            jobs.append(Job(src=path, display=display, rel=rel, is_error=True,
                            skip_reason=f'unreadable directory ({err.strerror})'))

        if recursive:
            walker = os.walk(root_abs, followlinks=False, onerror=lambda e: unreadable(e.filename or root_abs, e))
        else:
            walker = [(root_abs, None, None)]
        for dirpath, dirnames, filenames in walker:
            if dirnames is None:
                try:
                    entries = sorted(os.scandir(dirpath), key=lambda e: e.name)
                except OSError as e:
                    unreadable(dirpath, e)
                    return
                filenames = []
                for e in entries:
                    if e.is_dir(follow_symlinks=False):
                        if e.name in VCS_DIRS:
                            ctx.vcs_skipped += 1
                        else:
                            ctx.subdirs_skipped += 1
                    else:
                        filenames.append(e.name)
            else:
                keep = []
                for d in sorted(dirnames):
                    full = os.path.join(dirpath, d)
                    if d in VCS_DIRS:
                        ctx.vcs_skipped += 1
                        continue
                    if os.path.islink(full):
                        rel = os.path.relpath(full, root_abs)
                        display = os.path.join(root_display, rel) if root_display not in ('', '.') else rel
                        add_symlink(full, display, rel)
                        continue
                    if out_real and out_mode == 'dir' and os.path.realpath(full) == out_real and out_real != root_real:
                        if not pruned_note:
                            ctx.notes.append(f'output directory {fmt_path(out_path)} lies inside the input tree; excluded from scan')
                            pruned_note = True
                        continue
                    keep.append(d)
                dirnames[:] = keep
                filenames = sorted(filenames)
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root_abs)
                display = os.path.join(root_display, rel) if root_display not in ('', '.') else rel
                try:
                    st = os.lstat(full)
                except OSError as e:
                    jobs.append(Job(src=full, display=display, rel=rel, skip_reason=f'unreadable ({e.strerror})'))
                    continue
                if stat.S_ISLNK(st.st_mode):
                    add_symlink(full, display, rel)
                elif stat.S_ISREG(st.st_mode):
                    add_file(full, display, rel, st, inplace_root)
                else:
                    jobs.append(Job(src=full, display=display, rel=rel, skip_reason='not a regular file'))

    for p in paths:
        p_stat = p.rstrip('/') or p              # 'linkdir/' must not silently follow the symlink
        try:
            st = os.lstat(p_stat)
        except OSError as e:
            raise UsageError(f'{fmt_path(p)}: {e.strerror}')
        p_abs = os.path.abspath(p_stat)
        if stat.S_ISLNK(st.st_mode):
            add_symlink(p_abs, p, os.path.basename(p_abs))
        elif stat.S_ISDIR(st.st_mode):
            walk_dir(p, p)
        elif stat.S_ISREG(st.st_mode):
            add_file(p_abs, p, os.path.basename(p_abs), st, False)
        else:
            jobs.append(Job(src=p_abs, display=p, rel=os.path.basename(p_abs), skip_reason='not a regular file'))

    if out_mode:
        by_dest: dict = {}
        for job in jobs:
            if job.skip_reason:
                continue
            key = os.path.realpath(job.src) if job.inplace else os.path.realpath(job.dest)
            other = by_dest.get(key)
            if other is not None:
                raise UsageError(f'{fmt_path(job.display)} and {fmt_path(other.display)} would both end up at '
                                 f'{fmt_path(key)}; use -o DIR/ with a directory argument or rename')
            by_dest[key] = job
        sources = {os.path.realpath(j.src): j for j in jobs if not j.skip_reason}
        for job in jobs:
            if job.skip_reason or job.inplace:
                continue
            victim = sources.get(os.path.realpath(job.dest))
            if victim is not None and victim is not job:
                raise UsageError(f'{fmt_path(job.display)} would be written over the input {fmt_path(victim.display)}; '
                                 'outputs may not overwrite inputs (choose another -o TARGET)')
    return jobs


class Console:
    """Interactive prompts through /dev/tty (independent of stdin redirection)."""

    def __init__(self):
        self.tty = None

    def open(self):
        try:
            raw = open('/dev/tty', 'r+b', buffering=0)   # a tty is not seekable: no BufferedRandom
            self.tty = io.TextIOWrapper(raw, encoding='utf-8', errors='replace', write_through=True)
        except (OSError, ValueError):
            self.tty = None

    def close(self):
        if self.tty is not None:
            close = getattr(self.tty, 'close', None)
            if close is not None:
                try:
                    close()
                except Exception:
                    pass
            self.tty = None

    @property
    def interactive(self) -> bool:
        return self.tty is not None

    def confirm_overwrite(self, path: str, ctx: 'Context') -> bool:
        if ctx.yes_all:
            return True
        if ctx.no_all or ctx.quit:
            return False
        for _ in range(3):
            self.tty.write(f"overwrite '{fmt_path(path)}'? [y/N/a/q] ")
            self.tty.flush()
            line = self.tty.readline()
            if line == '':
                ctx.no_all = True
                return False
            ans = line.strip().lower()
            if ans in ('y', 'yes', 'д', 'да'):
                return True
            if ans in ('', 'n', 'no', 'н', 'нет'):
                return False
            if ans in ('a', 'all', 'в', 'все'):
                ctx.yes_all = True
                return True
            if ans in ('q', 'quit', 'й'):
                ctx.quit = True
                return False
            self.tty.write("please answer y (yes), n (no), a (all) or q (quit)\n")
        return False


def _emit(stream_name: str, text: str) -> None:
    """Write to sys.stdout/sys.stderr; a closed or dead stream never aborts the run (EPIPE on stdout does)."""
    stream = getattr(sys, stream_name, None)
    if stream is None:
        return
    try:
        stream.write(text)
        stream.flush()
    except BrokenPipeError:
        if stream_name == 'stdout':
            raise
    except (OSError, ValueError, AttributeError):
        pass


def warn(msg: str):
    _emit('stderr', f'win2nix: warning: {msg}\n')


def _backup_base(src: str) -> str:
    """<src> shortened (if needed) so that '<base>.w2n.NN.bak' fits the file-name limit."""
    d, name = os.path.split(src)
    try:
        limit = os.pathconf(d or '.', 'PC_NAME_MAX')
    except (OSError, ValueError, AttributeError):
        limit = 255
    room = limit - len('.w2n.99.bak')
    enc = os.fsencode(name)
    while len(enc) > room and name:
        name = name[:-1]
        enc = os.fsencode(name)
    return os.path.join(d, name)


def make_backup(src: str, data: bytes) -> str:
    base = _backup_base(src)
    candidates = [base + BACKUP_SUFFIX] + [f'{base}.w2n.{i}.bak' for i in range(1, 100)]
    d = os.path.dirname(src) or '.'
    for path in candidates:
        if os.path.lexists(path):
            try:
                if os.path.isfile(path) and not os.path.islink(path) and os.path.getsize(path) == len(data):
                    with open(path, 'rb') as f:
                        if f.read() == data:
                            return path
            except OSError:
                pass
            continue
        fd, tmp = tempfile.mkstemp(prefix=TMP_PREFIX, dir=d)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            try:
                shutil.copystat(src, tmp)
            except OSError:
                pass
            try:
                os.link(tmp, path)               # exclusive, atomic: the final name never holds a partial file
            except FileExistsError:
                os.unlink(tmp)
                continue
            except OSError:                      # no hard links here (vfat/exFAT, some network mounts)
                os.unlink(tmp)
                try:
                    fd2 = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    continue
                try:
                    with os.fdopen(fd2, 'wb') as f2:
                        f2.write(data)
                        f2.flush()
                        os.fsync(f2.fileno())
                    try:
                        shutil.copystat(src, path)
                    except OSError:
                        pass
                except BaseException:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                    raise
                return path
            os.unlink(tmp)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return path
    raise OSError('too many backups already exist')


def write_atomic(dst: str, out: bytes, src: str, st: os.stat_result | None, opts, ctx: Context,
                 guard_src: bool) -> None:
    d = os.path.dirname(dst) or '.'
    fd, tmp = tempfile.mkstemp(prefix=TMP_PREFIX, dir=d)
    ctx.temp_files.add(tmp)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(out)
            f.flush()
            os.fsync(f.fileno())
        if st is not None:
            try:
                shutil.copystat(src, tmp)
            except OSError:
                pass
            if opts.touch:
                os.utime(tmp, None)
            tst = os.stat(tmp)
            if (tst.st_uid, tst.st_gid) != (st.st_uid, st.st_gid):
                try:
                    os.chown(tmp, st.st_uid, st.st_gid)
                except PermissionError:
                    if not ctx.chown_warned:
                        warn('cannot preserve file owner/group (not root); continuing')
                        ctx.chown_warned = True
            if guard_src:
                cur = os.lstat(src)
                if stat.S_ISLNK(cur.st_mode) or (cur.st_ino, cur.st_size, cur.st_mtime_ns) != \
                        (st.st_ino, st.st_size, st.st_mtime_ns):
                    raise FileChangedError('file changed during conversion')
        os.replace(tmp, dst)
        ctx.temp_files.discard(tmp)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        ctx.temp_files.discard(tmp)
        raise


def backup_required(a: Analysis, replaced: int, opts) -> bool:
    if opts.no_backup:
        return False
    if opts.backup:
        return True
    det = a.detection
    if a.kind == 'mixed':
        return True
    if det is None:
        return False
    if det.level == 'unsure' and det.encoding not in ('ascii', 'utf-8'):
        return True
    if replaced > 0:
        return True
    if a.has_bom and a.wide is None and det.encoding not in ('ascii', 'utf-8') and det.encoding not in UNICODE_WIDE:
        return True
    return False


def _label(a: Analysis) -> str:
    det = a.detection
    if a.kind == 'empty':
        return 'empty'
    if a.kind == 'binary':
        return 'binary'
    if a.kind == 'error':
        return ''
    enc = DISPLAY.get(det.encoding, det.encoding)
    if a.kind == 'mixed' and a.mixed_info:
        enc = f'mixed({a.mixed_info[0]} utf-8 + {a.mixed_info[1]} {enc} lines)'
    if det.level == 'unsure':
        enc += '?'
    if det.level == 'unknown':
        return 'unknown'
    return enc


def _flags(a: Analysis) -> list[str]:
    flags = []
    if a.has_bom:
        flags.append('bom')
    if a.n_crlf:
        flags.append(f'crlf={a.n_crlf}')
    if a.n_cr and not a.mac_file:
        flags.append(f'cr={a.n_cr} kept')
    if a.mac_file:
        flags.append('mac')
    if a.ctrlz:
        flags.append('ctrlz')
    return flags


def _inplace_write(job: Job, data: bytes, out: bytes, a: Analysis, replaced: int, opts, ctx: Context,
                   res: Result) -> Result:
    backup = None
    if backup_required(a, replaced, opts):
        try:
            backup = make_backup(job.src, data)
        except OSError as e:
            raise OSError(f'cannot create backup: {e.strerror or e}') from e
    write_atomic(job.src, out, job.src, job.st, opts, ctx, guard_src=True)
    res.status = 'converted'
    res.backup = backup
    shown = None
    if backup:
        shown = os.path.join(os.path.dirname(job.display), os.path.basename(backup))
    res.action = 'converted' + (f', backup: {fmt_path(shown)}' if backup else '')
    if job.st is not None and job.st.st_nlink > 1:
        res.action += f'; hard links: {job.st.st_nlink - 1} other name(s) keep the old content'
    return res


def write_output(job: Job, data: bytes, out: bytes, a: Analysis, replaced: int, opts, ctx: Context,
                 res: Result, changed: bool) -> Result:
    dest = job.dest
    shown = fmt_path(job.dest_display or dest)
    verb = 'write' if changed else 'copy'
    if ctx.out_real and not job.inplace:
        parent_real = os.path.realpath(os.path.dirname(dest) or '.')
        if parent_real != ctx.out_real and not parent_real.startswith(ctx.out_real + os.sep):
            res.status, res.action, res.is_error = \
                'error', f'error: output path {shown} leaves {fmt_path(ctx.out_real)} through a symlink', True
            return res
    if os.path.lexists(dest):
        dst_st = os.lstat(dest)
        if not stat.S_ISREG(dst_st.st_mode):
            res.status, res.action, res.is_error = 'error', f'error: output {shown} is not a regular file', True
            return res
        same = os.path.realpath(dest) == os.path.realpath(job.src)
        if same:
            if not changed:
                res.status, res.action = 'ok', 'ok'
                return res
            if opts.check:
                res.status, res.would_change = 'would', True
                res.action = _would_convert(res, a, backup_required(a, replaced, opts))
                return res
            return _inplace_write(job, data, out, a, replaced, opts, ctx, res)
        try:
            with open(dest, 'rb') as f:
                existing = f.read()
        except OSError as e:
            res.status, res.action, res.is_error = 'error', f'error: cannot read {shown}: {e.strerror}', True
            return res
        if existing == out:
            res.status, res.action = 'ok', 'ok'
            return res
        if opts.check:
            res.status, res.action, res.would_change = 'would', f'would overwrite: {shown}', True
            return res
        if opts.yes or ctx.yes_all:
            allowed = True
        elif opts.no or ctx.no_all:
            why = '(-n)' if opts.no else '(no to all)'
            res.status, res.action, res.is_error, res.skip_kind = 'skipped', f'skipped: exists {why}', True, 'exists'
            return res
        elif ctx.console.interactive:
            allowed = ctx.console.confirm_overwrite(dest, ctx)
            if not allowed:
                res.status, res.action, res.is_error, res.skip_kind = 'skipped', 'skipped: not overwritten', True, 'exists'
                return res
        else:
            res.status, res.action, res.is_error, res.skip_kind = \
                'skipped', 'skipped: exists (no terminal; use -y or -n)', True, 'exists'
            return res
        verb = 'overwrite'
    if opts.check:
        res.status, res.action, res.would_change = 'would', f'would {verb}: {shown}', True
        return res
    try:
        os.makedirs(os.path.dirname(dest) or '.', exist_ok=True)
    except OSError as e:
        res.status, res.is_error = 'error', True
        res.action = f'error: cannot create directory {fmt_path(os.path.dirname(job.dest_display or dest))}: {e.strerror}'
        return res
    write_atomic(dest, out, job.src, job.st, opts, ctx, guard_src=False)
    res.out = dest
    if verb == 'overwrite':
        res.status, res.action = 'written', f'overwritten: {shown}'
    else:
        res.status = 'written' if changed else 'copied'
        res.action = f'{res.status}: {shown}'
    return res


def _would_convert(res: Result, a: Analysis, will_backup: bool) -> str:
    det = a.detection
    s = 'would convert [' + ', '.join(res.changes) + ']'
    unsure = (det is not None and det.level == 'unsure') or a.kind == 'mixed'
    if unsure and will_backup:
        s += ' (unsure, backup)'
    elif unsure:
        s += ' (unsure)'
    elif will_backup:
        s += ' (backup)'
    return s


def process_job(job: Job, opts, forced: str | None, ctx: Context) -> Result:
    res = Result(job=job, status='skipped')
    try:
        if job.skip_reason:
            res.action = f'skipped: {job.skip_reason}'
            if job.skip_reason.startswith('symlink'):
                res.skip_kind = 'symlink'
            elif job.skip_reason.startswith('stale temp'):
                res.skip_kind = 'temp'
            elif job.skip_reason.startswith('backup'):
                res.skip_kind = 'backup'
            else:
                res.skip_kind = 'other'
            res.is_error = job.is_error
            return res
        st = job.st
        if st is None or not stat.S_ISREG(st.st_mode):
            res.action, res.skip_kind = 'skipped: not a regular file', 'other'
            return res
        if st.st_size > MAX_SIZE:
            res.status, res.action, res.is_error = 'error', 'error: too large (use iconv/dos2unix)', True
            return res
        with open(job.src, 'rb') as f:
            data = f.read()
            job.st = os.fstat(f.fileno())        # the race guard compares against what was actually read
        a = analyze(data, forced)
        res.encoding_label = _label(a)
        res.details = _details(a, opts)
        res.flags = _flags(a)
        if a.kind == 'binary':
            res.action, res.skip_kind = f'skipped: binary ({a.binary_reason})', 'binary'
            return res
        if a.kind == 'error':
            res.status, res.action, res.is_error = 'error', f'error: {a.error}', True
            return res
        det = a.detection
        if det is not None and det.level == 'unknown':
            hint = '' if 'try --from' in det.reason else '; try --from ENC'
            res.action, res.is_error, res.skip_kind = \
                f'skipped: unknown encoding ({det.reason}{hint})', True, 'unknown'
            return res
        res.unsure = det is not None and (det.level == 'unsure' or a.kind == 'mixed')
        text, replaced = decode_body(data, a)
        if replaced:
            warn(f'{fmt_path(job.display)}: {replaced} undecodable byte(s) replaced with U+FFFD')
            res.unsure = True
            if det is not None and det.level == 'sure':
                det.level = 'unsure'
                det.notes.append(f'{replaced} undecodable byte(s)')
                res.encoding_label = _label(a)
                res.details = _details(a, opts)
        new_text, changes = transform(text, a)
        out = new_text.encode('utf-8')
        res.changes = changes
        changed = out != data
        res.changed = changed
        if job.inplace:
            if not changed:
                res.status, res.action = 'ok', 'ok'
                return res
            if opts.check:
                res.status, res.would_change = 'would', True
                res.action = _would_convert(res, a, backup_required(a, replaced, opts))
                return res
            return _inplace_write(job, data, out, a, replaced, opts, ctx, res)
        return write_output(job, data, out, a, replaced, opts, ctx, res, changed)
    except FileChangedError as e:
        res.status, res.action, res.is_error = 'error', f'error: {e}', True
        return res
    except KeyboardInterrupt:
        raise
    except OSError as e:
        res.status, res.action, res.is_error = 'error', f'error: {e.strerror or e}', True
        return res
    except Exception as e:  # never abort the whole run because of one file
        res.status, res.action, res.is_error = 'error', f'error: {type(e).__name__}: {e}', True
        return res

# --------------------------------------------------------------------------- report / CLI


def _details(a: Analysis, opts) -> str:
    if not opts.verbose or a.detection is None:
        return ''
    det = a.detection
    ev = det.evidence
    parts = [f'level={det.level}']
    if det.scores:
        parts.append(f'margin={det.margin:.1f}')
        parts.append(f'n_ev={ev.n_ev} words3={ev.words3}')
    s = '[' + ' '.join(parts) + ']'
    if det.scores:
        s += ' scores ' + ' '.join(f'{DISPLAY.get(c, c)}={v:.1f}' for c, v in
                                  sorted(det.scores.items(), key=lambda kv: -kv[1]))
    notes = list(det.notes) + list(a.notes)
    if notes:
        s += ' // ' + '; '.join(notes)
    return s


def format_result(r: Result, opts) -> str | None:
    if opts.quiet and not r.is_error:
        return None
    if r.status in ('ok', 'copied') and not opts.verbose:
        return None
    label = r.encoding_label
    parts = [fmt_path(r.job.display) + ':']
    if label:
        parts.append(label)
    parts.extend(r.flags)
    parts.append('->')
    parts.append(r.action)
    line = ' '.join(parts)
    if r.details:
        line += '  ' + r.details
    return line


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f'{n} {word if n == 1 else (plural or word + "s")}'


def summarize(results: list[Result], opts, ctx: Context) -> str:
    n = len(results)
    conv = [r for r in results if r.status == 'converted']
    with_bak = sum(1 for r in conv if r.backup)
    written = sum(1 for r in results if r.status == 'written')
    copied = sum(1 for r in results if r.status == 'copied')
    ok = sum(1 for r in results if r.status == 'ok')
    would = [r for r in results if r.status == 'would']
    errors = sum(1 for r in results if r.status == 'error')
    skipped = [r for r in results if r.status == 'skipped']
    kinds = Counter(r.skip_kind for r in skipped)
    parts = []
    if opts.check:
        w_inplace = [r for r in would if r.changed and r.job.inplace]
        w_written = [r for r in would if r.changed and not r.job.inplace]
        w_copy = [r for r in would if not r.changed]
        for group, verb in ((w_inplace, 'would be converted'), (w_written, 'would be written')):
            if group:
                unsure = sum(1 for r in group if r.unsure)
                parts.append(f'{len(group)} {verb}' + (f' ({unsure} unsure)' if unsure else ''))
        if w_copy:
            parts.append(f'{len(w_copy)} would be copied')
    else:
        if conv:
            parts.append(f'{len(conv)} converted' + (f' ({with_bak} with backup)' if with_bak else ''))
        if written:
            parts.append(f'{written} written')
        if copied:
            parts.append(f'{copied} copied')
    if ok:
        parts.append(f'{ok} ok')
    if kinds['binary']:
        parts.append(f"{kinds['binary']} binary")
    if kinds['unknown']:
        parts.append(f"{kinds['unknown']} unknown encoding")
    if kinds['exists']:
        parts.append(f"{kinds['exists']} not overwritten")
    if kinds['symlink']:
        parts.append(_plural(kinds['symlink'], 'symlink') + ' skipped')
    if kinds['backup']:
        parts.append(_plural(kinds['backup'], 'backup file') + ' skipped')
    if kinds['temp']:
        parts.append(_plural(kinds['temp'], 'stale temp file') + ' skipped')
    other = len(skipped) - sum(kinds[k] for k in ('binary', 'unknown', 'exists', 'symlink', 'backup', 'temp'))
    if other:
        parts.append(f'{other} skipped')
    if errors:
        parts.append(_plural(errors, 'error'))
    if opts.output and (kinds['binary'] or kinds['unknown']):
        parts.append(_plural(kinds['binary'] + kinds['unknown'], 'non-text file') + ' not copied')
    s = f'win2nix: {_plural(n, "file")}: ' + (', '.join(parts) if parts else 'nothing to do')
    extra = []
    if ctx.vcs_skipped:
        extra.append(_plural(ctx.vcs_skipped, 'VCS directory', 'VCS directories') + ' skipped')
    if ctx.subdirs_skipped:
        extra.append(_plural(ctx.subdirs_skipped, 'subdirectory', 'subdirectories') + ' skipped (use -r)')
    if extra:
        s += '; ' + ', '.join(extra)
    return s


def exit_code(results: list[Result], opts, interrupted: int) -> int:
    if interrupted:
        return interrupted
    if any(r.is_error for r in results):
        return 3
    if opts.check and any(r.would_change for r in results):
        return 1
    return 0


def cleanup_temp(ctx: Context):
    for tmp in list(ctx.temp_files):
        try:
            os.unlink(tmp)
        except OSError:
            pass
        ctx.temp_files.discard(tmp)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='win2nix',
        description='Convert Windows-era text files (CP1251/CP866/KOI8-R, CRLF, BOM) to Linux form: '
                    'UTF-8, LF, no BOM.  Confident decisions are written in place; unsure ones get a '
                    '<name>.w2n.bak backup first.',
        epilog='Exit codes: 0 ok, 1 (--check) something would change, 2 usage error, 3 some files not processed, '
               '130/143 interrupted (Ctrl-C/SIGTERM), 141 stdout closed.')
    p.add_argument('paths', nargs='+', metavar='PATH', help='files and/or directories')
    p.add_argument('-r', '--recursive', action='store_true', help='descend into subdirectories')
    p.add_argument('-o', '--output', metavar='TARGET',
                   help='write results to TARGET: a directory (existing or ending with /) or a new file '
                        '(exactly one input); originals are left untouched')
    p.add_argument('-c', '--check', '--dry-run', action='store_true',
                   help='report what would be done; change nothing')
    p.add_argument('-f', '--from', dest='from_enc', metavar='ENC',
                   help='force the source encoding (cp1251, cp866, koi8-r, utf-8, utf-16le, ...)')
    g = p.add_mutually_exclusive_group()
    g.add_argument('-b', '--backup', action='store_true', help='always keep a backup when writing in place')
    g.add_argument('-B', '--no-backup', action='store_true', help='never keep a backup')
    g2 = p.add_mutually_exclusive_group()
    g2.add_argument('-y', '--yes', action='store_true', help='overwrite existing -o outputs without asking')
    g2.add_argument('-n', '--no', action='store_true', help='never overwrite existing -o outputs')
    p.add_argument('--touch', action='store_true', help='set mtime of results to now (default: preserve)')
    p.add_argument('-q', '--quiet', action='store_true', help='print only errors and warnings')
    p.add_argument('-v', '--verbose', action='store_true', help='also print unchanged files and detection details')
    p.add_argument('--version', action='version', version=f'win2nix {__version__}')
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    opts = parser.parse_args(argv)
    try:
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, 'reconfigure'):
                stream.reconfigure(errors='replace')
    except Exception:
        pass
    console = Console()
    ctx = Context(console=console)
    forced = None
    try:
        if opts.from_enc:
            forced = resolve_codec(opts.from_enc)
        out_mode = out_path = None
        if opts.output is not None:
            out_mode, out_path = resolve_output(opts.output, opts.paths)
        jobs = collect_jobs(opts.paths, opts.recursive, out_mode, out_path, ctx, opts.output)
        if out_mode == 'dir':
            ctx.out_real = os.path.realpath(out_path)
    except UsageError as e:
        _emit('stderr', f'win2nix: error: {e}\n')
        return 2
    if not opts.check:
        console.open()
    atexit.register(cleanup_temp, ctx)
    interrupted = 0

    def on_term(signum, frame):
        raise KeyboardInterrupt(signum)

    for sig in (signal.SIGTERM, getattr(signal, 'SIGHUP', None)):
        if sig is not None:
            try:
                signal.signal(sig, on_term)
            except (ValueError, OSError):
                pass
    if not opts.quiet:
        for note in ctx.notes:
            _emit('stderr', f'win2nix: note: {note}\n')
    try:
        for job in jobs:
            if ctx.quit:
                r = Result(job=job, status='skipped', action='skipped: not processed (quit)', is_error=True,
                           skip_kind='other')
            else:
                r = process_job(job, opts, forced, ctx)
            ctx.results.append(r)
            line = format_result(r, opts)
            if line:
                _emit('stderr' if opts.quiet else 'stdout', line + '\n')
    except KeyboardInterrupt as e:
        cleanup_temp(ctx)
        sig = e.args[0] if e.args else None
        interrupted = {signal.SIGTERM: 143, getattr(signal, 'SIGHUP', -1): 129}.get(sig, 130)
        _emit('stderr', 'win2nix: interrupted\n')
    except BrokenPipeError:
        cleanup_temp(ctx)
        _silence_stdout()
        return 141
    finally:
        console.close()
    if not opts.quiet:
        try:
            _emit('stdout', summarize(ctx.results, opts, ctx) + '\n')
        except BrokenPipeError:
            _silence_stdout()
            return 141
    return exit_code(ctx.results, opts, interrupted)


def _silence_stdout():
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except OSError:
        pass


if __name__ == '__main__':
    sys.exit(main())
