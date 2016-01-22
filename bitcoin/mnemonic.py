import hashlib
import os.path
import binascii
from os import urandom as secure_random_bytes
from bisect import bisect_left

wordlist_english=[w.strip() for w in open(os.path.join(os.path.dirname(os.path.realpath(__file__)),'english.txt'),'r')]

def eint_to_bytes(entint,entbits):
	a=hex(entint)[2:].rstrip('L').zfill(entbits//4)
	return binascii.unhexlify(a)

def mnemonic_int_to_words(mint,mint_num_words,wordlist=wordlist_english):
	backwords=[wordlist[(mint >> (11*x)) & 0x7FF].strip() for x in range(mint_num_words)]	
	return backwords[::-1]
	
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

def words_split(wordstr,wordlist=wordlist_english):
	words=wordstr.split()	
	for w in words:
		if(w not in wordlist):
			raise Exception("Word %s not in wordlist" % (w))
	return words

def words_to_mnemonic_int(words,wordlist=wordlist_english):
	if(isinstance(words,str)):
		words=words_split(words,wordlist)
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
	ebytes=eint_to_bytes(eint,entropy_bits)
	ecsint,ecsint_size=entropy_cs(ebytes)
	return csint == ecsint

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

def words_generate(num_bits_entropy=128,num_words=None,randombits=_getrandbits,wordlist=wordlist_english):
    if(num_words is not None and num_words % 3 == 0):
        num_bits_entropy=(32*11*num_words) // 33
    rint=randombits(num_bits_entropy)
    return entropy_to_words(eint_to_bytes(rint,num_bits_entropy),wordlist)
    
def words_mine(prefix,entbits,satisfunction,wordlist=wordlist_english,randombits=_getrandbits):
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
		

