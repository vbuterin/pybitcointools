import hashlib
import os.path
import binascii
from os import urandom as secure_random_bytes
from bisect import bisect_left
import re
import collections
import json
import bz2
import codecs

#this type has list semantics but is optimized for O(1) search using a hashtable for speed
class Wordlist(list):
    def __init__(self,*collection,**kwargs):
        list.__init__(self,*collection,**kwargs)
        self.lookup=dict((value,index) for index,value in enumerate(self))
        
    def index(self,x):
        try:
            return self.lookup[x]
        except KeyError as ke:
            raise IndexError("'%s' is not in list" % (ke.args))

    def __contains__(self,x):
        return x in self.lookup

reader = codecs.getreader("utf-8")
_wordlists_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'wordlists.json.bz2')
wordlists = dict([(k,Wordlist(v)) for k,v in json.load(reader(bz2.BZ2File(_wordlists_path,'r'))).items()])

def eint_to_bytes(entint, entbits):
    a = hex(entint)[2:].rstrip('L').zfill(entbits // 4)
    return binascii.unhexlify(a)


def mnemonic_int_to_words(mint, mint_num_words, wordlist=wordlists["english"]):
    backwords = [wordlist[(mint >> (11 * x)) & 0x7FF].strip() for x in range(mint_num_words)]
    return backwords[::-1]


def entropy_cs(entbytes):
    entropy_size = 8 * len(entbytes)
    checksum_size = entropy_size // 32
    hd = hashlib.sha256(entbytes).hexdigest()
    csint = int(hd, 16) >> (256 - checksum_size)
    return csint, checksum_size


def entropy_to_words(entbytes, wordlist=wordlists["english"]):
    if(len(entbytes) < 4 or len(entbytes) % 4 != 0):
        raise ValueError("The size of the entropy must be a multiple of 4 bytes (multiple of 32 bits)")
    entropy_size = 8 * len(entbytes)
    csint, checksum_size = entropy_cs(entbytes)
    entint = int(binascii.hexlify(entbytes), 16)
    mint = (entint << checksum_size) | csint
    mint_num_words = (entropy_size + checksum_size) // 11

    return mnemonic_int_to_words(mint, mint_num_words, wordlist)


def words_split(wordstr, wordlist=wordlists["english"]):
    words = wordstr.split()
    for w in words:
        if(w not in wordlist):
            raise Exception("Word %s not in wordlist" % (w))
    return words


def words_to_mnemonic_int(words, wordlist=wordlists["english"]):
    if(isinstance(words, basestring)):
        words = words_split(words, wordlist)
    return sum([wordlist.index(w) << (11 * x) for x, w in enumerate(words[::-1])])


def mnemonic_int_verify(mint, mint_bits):
    cs_bits = mint_bits // 32
    entropy_bits = mint_bits - cs_bits
    eint = mint >> cs_bits
    csint = mint & ((1 << cs_bits) - 1)
    ebytes = eint_to_bytes(eint, entropy_bits)
    ecsint, ecsint_size = entropy_cs(ebytes)
    return csint == ecsint


def words_verify(words, wordlist=wordlists["english"]):
    if(isinstance(words, basestring)):
        words = words_split(words, wordlist)
    
    mint=words_to_mnemonic_int(words, wordlist)
    mint_bits=len(words)*11
    return mnemonic_int_verify(mint,mint_bits)

def mnemonic_to_seed(mnemonic_phrase,passphrase=u''):
    try:
        from hashlib import pbkdf2_hmac
        def pbkdf2_hmac_sha256(password,salt,iters=2048):
            return pbkdf2_hmac(hash_name='sha512',password=password,salt=salt,iterations=iters)
    except:
        try:
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA512,HMAC
        
            def pbkdf2_hmac_sha256(password,salt,iters=2048):
                return PBKDF2(password=password,salt=salt,dkLen=64,count=iters,prf=lambda p,s: HMAC.new(p,s,SHA512).digest())
        except:
            try:
            
                from pbkdf2 import PBKDF2
                import hmac
                def pbkdf2_hmac_sha256(password,salt,iters=2048):
                    return PBKDF2(password,salt, iterations=iters, macmodule=hmac, digestmodule=hashlib.sha512).read(64)
            except:
                raise RuntimeError("No implementation of pbkdf2 was found!")

    return pbkdf2_hmac_sha256(password=mnemonic_phrase,salt='mnemonic'+passphrase)

def _getrandbits(num_bits):
    bytes=(num_bits >> 3) + (1 if (num_bits & 0x7) else 0)
    rint=int(binascii.hexlify(secure_random_bytes(bytes)),16)
    return rint & ((1 << num_bits)-1)

def words_generate(num_bits_entropy=128,num_words=None,randombits=_getrandbits,wordlist=wordlists["english"]):
    if(num_words is not None and num_words % 3 == 0):
        num_bits_entropy=(32*11*num_words) // 33
    rint=randombits(num_bits_entropy)
    return entropy_to_words(eint_to_bytes(rint,num_bits_entropy),wordlist)
    
    
#pattern syntax: a word is (\w*)(?::(\w*))?...but split it first
def words_mine(pattern,valid=lambda x : True ,wordlist=wordlists["english"],randombits=_getrandbits):
    if(isinstance(pattern,basestring)):
        pattern=pattern.split()
    if(len(pattern) % 3 != 0):
        raise RuntimeError("The number of words in the pattern must be a multiple of 3")
    
    rec=re.compile(r'(\w*)(?::(\w*))?')
    ranges=[]

    for word in pattern:
        m=rec.match(word)
        if(not m):
            raise RuntimeError("Could not parse pattern word %s" % (word))
        lower=0
        upper=1 << 11
        lw,uw=m.group(1,2)
        if(lw):
            if(lw != ""):
                try:
                    lower=int(lw) & 0x7FF
                except:
                    lower=next((index for index,value in enumerate(wordlist) if lw <= value))
        if(uw):
            if(uw != ""):
                try:
                    upper=int(uw) & 0x7FF
                except:
                    upper=next((index for index,value in enumerate(wordlist) if uw <= value))
        elif(lw):
            upper=next((index for index,value in enumerate(wordlist[::-1]) if lw >= value[:len(lw)]))
            upper=2048-upper
        
        ranges.append((lower,upper))
                    
    total_randomness=reduce(lambda a,b: a*(b[1]-b[0]),ranges,1)
    
    mint_bits=len(pattern)*11
    def gen_mint(rangess,randombitss):
        mint=0
        for r in rangess:
            mint<<=11
            mint|=r[0] + randombitss(11) % (r[1]-r[0])
            return mint
        
    tint=gen_mint(ranges,randombits)
    count=0
 
    while(not mnemonic_int_verify(tint,mint_bits) or not valid(mnemonic_int_to_words(tint,len(pattern),wordlist))):
        tint=gen_mint(ranges,randombits)

        count+=1
        if((count & 0xFFFF) == 0):
            print("Searched %f percent of the space" % (100.0*float(count)/float(total_randomness)))

    return mnemonic_int_to_words(tint,len(pattern),wordlist)
    
        
def _build_mnemonic_file():
    import urllib2
    mnemonic_languages=["english","japanese","spanish","french","chinese_simplified","chinese_traditional"]
    wordlists={}
    for la in mnemonic_languages:
        wordlists[la]=urllib2.urlopen("https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/%s.txt" % (la)).read().split()
    json.dump(wordlists,bz2.BZ2File('wordlists.json.bz2','w'))

if __name__=="__main__":
    import json
    testvectors=json.load(open('vectors.json','r'))
    passed=True
    for v in testvectors['english']:
        ebytes=binascii.unhexlify(v[0])
        w=' '.join(entropy_to_words(ebytes))
        passed=words_verify(w)
        seed=mnemonic_to_seed(w,passphrase='TREZOR')
        passed = passed and w==v[1]
        passed = passed and binascii.hexlify(seed)==v[2]
    print("Tests %s." % ("Passed" if passed else "Failed"))
        

