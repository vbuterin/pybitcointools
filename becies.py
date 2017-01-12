import bitcoin
import hashlib,hmac
from binascii import hexlify,unhexlify
from os import urandom as secure_random_bytes
import base64

try:
	from hashlib import pbkdf2_hmac
except:
	from backports.pbkdf2 import pbkdf2_hmac

def _secure_privkey():
	return int(hexlify(secure_random_bytes(32)),16) % bitcoin.N

from Crypto.Cipher import AES

#http://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb

class AESCipher(object):
	def __init__(self, key): 
		self.bs = 16
		self.key = key

	def encrypt(self, raw):
		#iv should probably be a hash of the message to ensure uniformity
		raw = self.pad(raw)
		iv = secure_random_bytes(AES.block_size)	#iv should actually be assumed to be 0 and not transmitted. This is actually fine because the ephemeral_key must be random every time.
								#http://www.secg.org/sec1-v2.pdf page 36
								#https://github.com/ethereum/go-ethereum/issues/473
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return iv + cipher.encrypt(raw)

	def decrypt(self, enc):
		iv = enc[:AES.block_size]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(enc[AES.block_size:]))

	def pad(self,s):
		return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

	def unpad(self,s):
		return s[:-ord(s[len(s)-1:])]

def _int2bin32b(v):
	return unhexlify("%064x" % (v))

_becies_hashname='sha512'
_becies_hmachash=hashlib.sha256

def becies_shared_secret(private_key,public_key,optional_shared_info0=''):	#we do NOT use http://www.secg.org/sec1-v2.pdf ANSI KDF function, we use pkcs5_pbkdf2_hmac_sha512.  It's got more hardening and it's more common and already a part of bitcoin
	shared_secret_point=bitcoin.multiply(public_key,private_key)
	shared_secret=bitcoin.decode_pubkey(shared_secret_point)[1] #todo: check point at infinity? todo: compressed pubkey?
	shared_secret_bin=_int2bin32b(shared_secret)

	salt='becies'
	key=shared_secret_bin+optional_shared_info0
	hmac_result=pbkdf2_hmac(_becies_hashname,key,salt=salt+key,iterations=2048) #https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
	symmetric_key=hmac_result[:(len(hmac_result)//2)]
	mac_key=hmac_result[(len(hmac_result)//2):]
	return symmetric_key,mac_key

def becies_tag(mac_key,encrypted_string,optional_shared_info1=''):
	tag=hmac.new(key=mac_key,msg=encrypted_string+optional_shared_info1,digestmod=_becies_hmachash)
	return tag.digest()

def becies_encrypt(plaintext,pubkey,ephemeral_key=_secure_privkey(),optional_shared_info=('','')):
	ephemeral_pubkey=bitcoin.privtopub(ephemeral_key)

	symmetric_key,mac_key=becies_shared_secret(ephemeral_key,pubkey,optional_shared_info0=optional_shared_info[0])
	
	aes=AESCipher(symmetric_key)
	encrypted_string=aes.encrypt(plaintext)
	
	tag=becies_tag(mac_key=mac_key,encrypted_string=encrypted_string,optional_shared_info1=optional_shared_info[1])
	return ephemeral_pubkey,encrypted_string,tag

def becies_decrypt(ciphertuple,privkey,optional_shared_info=('','')):
	ephemeral_pubkey=ciphertuple[0]
	encrypted_string=ciphertuple[1]
	msgtag=ciphertuple[2]

	symmetric_key,mac_key=becies_shared_secret(privkey,ephemeral_pubkey,optional_shared_info0=optional_shared_info[0])

	tag=ecies_compute_tag(mac_key=mac_key,encrypted_string=encrypted_string,optional_shared_info1=optional_shared_info[1])
	if(not hmac.compare_tag(tag,msgtag)):
		raise "Decryption Failure...tag mismatch. The message may have been tampered with"
	
	aes=AESCipher(symmetric_key)
	return aes.decrypt(encrypted_string)


def lagrange_gen_points(coeffs,n):
	k=len(coeffs)
	return [sum([(coeffs[p]*(x**p)) % n for p in range(k)]) for x in range(1,k+1)]
		
def lagrange_interpolate(x,y,n):
	k=len(y)
	constant=0
	for j in range(k):
		numerator,denominator=1,1
		for m in range(k):
			if(j != m):
				numerator = (numerator * x[m]) % n
				denominator = (denominator * (x[m]-x[j])) % n
		lsum = (y[j] * numerator * bitcoin.inv(denominator,n)) % n
		constant=(constant+lsum) % n
	return constant
	
def becies_multi_encrypt(plaintext,k,public_keys,ephemeral_privkey=None,new_privkey_func=_secure_privkey):
	if(ephemeral_privkey==None):
		ephemeral_privkey=new_privkey_func()

	m=len(public_keys)
	coeffs=[new_privkey_func() for _ in range(k)]
	points=gen_points(coeffs,bitcoin.N)

	r=new_privkey_func()
	group_pubkey=bitcoin.privtopub(coeffs[0])
	becies_tuple=becies_encrypt(plaintext,group_pubkey,ephemeral_privkey=ephemeral_privkey)
	
	shared_secrets=[becies_shared_secret(r,B) for B in public_keys]
	offsets=[(p-s) % bitcoin.N for p,s in zip(points,shared_secrets)]
	
	return becies_tuple,offsets

#each wallet provides the result of 
#becies_shared_secret(b,R) given R, where b is the private key of the address. DOES THIS HAVE weaknesses? Probably not because of hash
#in reality, this should accept an array of shared secrets secret(b[...]*r), not the actual private keys.

def becies_multi_decrypt(becies_tuple,shared_secrets,indices,offsets):
	R=becies_tuple[0]
	points=[(o+p) % bitcoin.N for o,p in zip(offsets,shared_secrets)]
	group_privkey=lagrange_interpolate(indices,points,bitcoin.N)
	return becies_decrypt(becies,group_privkey)
	
#https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
#Variable length integer

def _to_vli(v):
	if(v > 0xFFFFFFFF):
		return chr(0xFF)+unhexlify("%016X" % v)
	if(v > 0xFFFF):
		return chr(0xFE)+unhexlify("%08X" % v)
	if(v > 0xFC):
		return chr(0xFD)+unhexlify("%04X" % v)
	return chr(v)

def _from_vli(nine_bytestring):
	c=ord(nine_bytestring[0])
	if(c == 0xFF):
		return int(hexlify(nine_bytestring[1:8])),9
	if(c == 0xFE):
		return int(hexlify(nine_bytestring[1:4])),5
	if(c == 0xFD):
		return int(hexlify(nine_bytestring[1:2])),3
	return c,1

#maybe this should take a file like object for the encoding for streaming?  A coroutine? Hmm.
BECIES_ADDRESSES_FLAG=1
BECIES_GROUP_FLAG=2
BECIES_MAGIC_BYTES='\xc6\x6b\x20'
def becies_encode(ephemeral_pubkey,ciphertext,tag,pubkeys=[],num_to_activate=None,offsets=None):
	bout=BECIES_MAGIC_BYTES#0xc66b20 3-byte prefix?  (encodes to xmsg in base64)

	isaddresses=bool(pubkeys)
	isgroup=bool(offsets)
	#a vli indicating the header contents flags.
	#offsets,and addresses are first two bits, rest are unused
	bout+=_to_vli(int(isgroup)*BECIES_GROUP_FLAG + int(isaddresses)*BECIES_ADDRESSES_FLAG)
	if(isaddresses):
		bout+=_to_vli(len(pubkeys))
		bout+=''.join([bitcoin.b58check_to_bin(bitcoin.pubtoaddr(p)) for p in pubkeys])
	if(isgroup):
		bout+=_to_vli(num_to_activate)		  #todo, num_to_activate must be strictly positive
		bout+=_to_vli(len(offsets))
		bout+=''.join([bitcoin.encode_privkey(priv) for priv in offsets])

	bout+=bitcoin.encode_pubkey(ephemeral_pubkey,'bin_compressed')
	bout+=_to_vli(len(ciphertext))
	bout+=ciphertext
	bout+=tag		#this has to come last for streaming mode too
	return bout

#serialization, base64 (dynamic length byte streams)
#0xc66b20 3-byte prefix?  (encodes to xmsg)
def becies_decode(encodedstr):
	if(encodedstr[:3] != BECIES_MAGIC_BYTES):
		raise "BECIES magic header not found"
	encodedstr=encodedstr[3:]
	
	flags,o=_from_vli(encodedstr)
	encodedstr=encodedstr[o:]
	
	isaddresses=flags & BECIES_ADDRESSES_FLAG
	isgroup=flags & BECIES_GROUP_FLAG
	addresses=[]
	offsets=[]
	num_to_activate=None
	if(isaddresses):
		num_addresses,o=_from_vli(encodedstr)
		encodedstr=encodedstr[o:]
		addresses=[encodedstr[i:i+20] for i in range(0, num_addresses, 20)]
		encodedstr=encodedstr[(num_addresses*20):]
	if(isgroup):
		num_to_activate,o=_from_vli(encodedstr)
		encodedstr=encodedstr[o:]
		num_offsets,o=_from_vli(encodedstr)
		offsets=[encodedstr[i:i+n] for i in range(0, num_addresses, 32)]
		encodedstr=encodedstr[(num_offsets*32):]
	ephemeral_pubkey=encodedstr[:33]
	encodedstr=encodedstr[33:]
	ephemeral_pubkey=bitcoin.decode_pubkey(ephemeral_pubkey)
	lcipher,o=_from_vli(encodedstr)
	encodedstr=encodedstr[o:]
	ciphertext=encodedstr[:lcipher]
	encodedstr=encodedstr[o:]
	tag=encodedstr
	return ephemeral_pubkey,ciphertext,tag,addresses,num_to_activate,offsets
	
if __name__=='__main__':
	k1=_secure_privkey()
	K1=bitcoin.privtopub(k1)
	k2=_secure_privkey()
	K2=bitcoin.privtopub(k2)
	R,c,t=becies_encrypt("Hello, World",K2)
	msg=becies_encode(R,c,t,pubkeys=[K2])
	output_expected=(R,c,t,[bitcoin.b58check_to_bin(bitcoin.pubtoaddr(K2))],None,[])
	output=becies_decode(msg)
	print(output)
	print(output_expected)
	print(str(output)==str(output_expected))
