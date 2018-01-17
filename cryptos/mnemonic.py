import random
from pbkdf2 import PBKDF2
import hmac
from .py2specials import *
from .py3specials import *
from .wallet_utils import is_new_seed
from bisect import bisect_left
import unicodedata

wordlist_english=[word.strip() for word in list(open(os.path.join(os.path.dirname(os.path.realpath(__file__)),'english.txt'),'r'))]

ELECTRUM_VERSION = '3.0.5'   # version of the client package
PROTOCOL_VERSION = '1.1'     # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet
SEED_PREFIX_2FA  = '101'     # Two-factor authentication
SEED_PREFIX_SW   = '100'     # Segwit wallet

whitespace = ' \t\n\r\v\f'

# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F , 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]
def is_CJK(c):
    n = ord(c)
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False

def normalize_text(seed):
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed


def eint_to_bytes(entint,entbits):
    a=hex(entint)[2:].rstrip('L').zfill(32)
    print(a)
    return binascii.unhexlify(a)

def mnemonic_int_to_words(mint,mint_num_words,wordlist=wordlist_english):
    backwords=[wordlist[(mint >> (11*x)) & 0x7FF].strip() for x in range(mint_num_words)]
    return ' '.join((backwords[::-1]))

def entropy_cs(entbytes):
    entropy_size=8*len(entbytes)
    checksum_size=entropy_size//32
    hd=hashlib.sha256(entbytes).hexdigest()
    csint=int(hd,16) >> (256-checksum_size)
    return csint,checksum_size

def entropy_to_words(entbytes,wordlist=wordlist_english):
    if(len(entbytes) < 4 or len(entbytes) % 4 != 0):
        raise ValueError("The size of the entropy must be a multiple of 4 bytes (multiple of 32 bits)")
    entropy_size=8*len(entbytes)
    csint,checksum_size = entropy_cs(entbytes)
    entint=int(binascii.hexlify(entbytes),16)
    mint=(entint << checksum_size) | csint
    mint_num_words=(entropy_size+checksum_size)//11

    return mnemonic_int_to_words(mint,mint_num_words,wordlist)

def words_bisect(word,wordlist=wordlist_english):
    lo=bisect_left(wordlist,word)
    hi=len(wordlist)-bisect_left(wordlist[:lo:-1],word)

    return lo,hi

def words_split(wordstr,wordlist=wordlist_english):
    def popword(wordstr,wordlist):
        for fwl in range(1,9):
            w=wordstr[:fwl].strip()
            lo,hi=words_bisect(w,wordlist)
            if (hi-lo == 1):
                return w,wordstr[fwl:].lstrip()
            wordlist=wordlist[lo:hi]
        raise Exception("Wordstr %s not found in list" %(w))

    words=[]
    tail=wordstr
    while(len(tail)):
        head,tail=popword(tail,wordlist)
        words.append(head)
    return words

def words_to_mnemonic_int(words,wordlist=wordlist_english):
    if(isinstance(words,str)):
        words = words.split()
    return sum([wordlist.index(w) << (11*x) for x,w in enumerate(words[::-1])])

def words_verify(words,wordlist=wordlist_english):
    if(isinstance(words,str)):
        words=words_split(words,wordlist)

    mint = words_to_mnemonic_int(words,wordlist)
    mint_bits=len(words)*11
    cs_bits=mint_bits//32
    entropy_bits=mint_bits-cs_bits
    eint=mint >> cs_bits
    csint=mint & ((1 << cs_bits)-1)
    ebytes = eint_to_bytes(eint,entropy_bits)
    return csint == entropy_cs(ebytes)

def bip39_normalize_passphrase(passphrase):
    return unicodedata.normalize('NFKD', passphrase or '')

# returns tuple (is_checksum_valid, is_wordlist_valid)
def bip39_is_checksum_valid(mnemonic):
    words = [ unicodedata.normalize('NFKD', word) for word in mnemonic.split() ]
    words_len = len(words)
    n = len(wordlist_english)
    checksum_length = 11*words_len//33
    entropy_length = 32*checksum_length
    i = 0
    words.reverse()
    while words:
        w = words.pop()
        try:
            k = wordlist_english.index(w)
        except ValueError:
            return False, False
        i = i*n + k
    if words_len not in [12, 15, 18, 21, 24]:
        return False, True
    entropy = i >> checksum_length
    checksum = i % 2**checksum_length
    h = '{:x}'.format(entropy)
    while len(h) < entropy_length/4:
        h = '0'+h
    b = bytearray.fromhex(h)
    hashed = int(safe_hexlify(hashlib.sha256(b).digest()), 16)
    calculated_checksum = hashed >> (256 - checksum_length)
    return checksum == calculated_checksum, True

def mnemonic_to_seed(mnemonic_phrase, passphrase='', passphrase_prefix=b"mnemonic"):
    passphrase = bip39_normalize_passphrase(passphrase)
    passphrase = from_string_to_bytes(passphrase)
    if isinstance(mnemonic_phrase, (list, tuple)):
        mnemonic_phrase = ' '.join(mnemonic_phrase)
    mnemonic = unicodedata.normalize('NFKD', ' '.join(mnemonic_phrase.split()))
    mnemonic = from_string_to_bytes(mnemonic)
    return PBKDF2(mnemonic, passphrase_prefix + passphrase, iterations=2048, macmodule=hmac, digestmodule=hashlib.sha512).read(64)

def bip39_mnemonic_to_seed(mnemonic_phrase, passphrase=''):
    if not bip39_is_checksum_valid(mnemonic_phrase)[1]:
        raise Exception("BIP39 Checksum is invalid for this mnemonic")
    return mnemonic_to_seed(mnemonic_phrase, passphrase=passphrase, passphrase_prefix=b"mnemonic")

def electrum_mnemonic_to_seed(mnemonic_phrase, passphrase='', ):
    return mnemonic_to_seed(mnemonic_phrase, passphrase=passphrase, passphrase_prefix=b"electrum")

def is_old_seed(seed):
    return False

def seed_prefix(seed_type):
    if seed_type == 'standard':
        return SEED_PREFIX
    elif seed_type == 'segwit':
        return SEED_PREFIX_SW
    elif seed_type == '2fa':
        return SEED_PREFIX_2FA

def seed_type(x):
    if is_old_seed(x):
        return 'old'
    elif is_new_seed(x):
        return 'standard'
    elif is_new_seed(x, SEED_PREFIX_SW):
        return 'segwit'
    elif is_new_seed(x, SEED_PREFIX_2FA):
        return '2fa'
    return ''

is_seed = lambda x: bool(seed_type(x))



def words_mine(prefix,entbits,satisfunction,wordlist=wordlist_english,randombits=random.getrandbits):
    prefix_bits=len(prefix)*11
    mine_bits=entbits-prefix_bits
    pint=words_to_mnemonic_int(prefix,wordlist)
    pint<<=mine_bits
    dint=randombits(mine_bits)
    count=0
    while(not satisfunction(entropy_to_words(eint_to_bytes(pint+dint,entbits)))):
        dint=randombits(mine_bits)
        if((count & 0xFFFF) == 0):
            print("Searched %f percent of the space" % (float(count)/float(1 << mine_bits)))

    return entropy_to_words(eint_to_bytes(pint+dint,entbits))

