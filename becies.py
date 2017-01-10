import bitcoin
from binascii import hexlify,unhexlify
from os import urandom as secure_random_bytes
import hashlib

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
		iv = secure_random_bytes(AES.block_size)
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

def becies_shared_secret(private_key,public_key,optional_shared_info0=''):
	shared_secret_point=bitcoin.multiply(private_key,public_key)
	shared_secret=bitcoin.decode_pubkey(bitcoin.multiply(private_key,public_key))[1] #todo: check point at infinity
	shared_secret_bin=_int2bin32b(shared_secret)

	salt='becies'
	key=shared_secret+optional_shared_info0
	hmac_result=pbkdf2_hmac(_becies_hashname,key,salt=salt+key,iterations=2048) #https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
	symmetric_key=hmac_result[:(len(hmac_result)//2)]
	mac_key=hmac_result[(len(hmac_result)//2):]
	return symmetric_key,mac_key

def becies_tag(mac_key,encrypted_string,optional_shared_info1=''):
	tag=hmac.new(key=mac_key,msg=encrypted_string+optional_shared_info1,digestmod=hmachash)
	return tag

def becies_encrypt(plaintext,pubkey,ephemeral_key=_secure_privkey(),optional_shared_info=('','')):
	shared_secret=bitcoin.decode_pubkey(bitcoin.multiply(pubkey,ephemeral_key))[1]
	shared_secret_bin=_int2bin32b(shared_secret)

	ephemeral_pubkey=bitcoin.privtopub(ephemeral_key)

	symmetric_key,mac_key=ecies_derive_keys(shared_secret_bin,optional_shared_info0=optional_shared_info[0])
	
	aes=AESCipher(symmetric_key)
	encrypted_string=aes.encrypt(plaintext)
	
	tag=ecies_compute_tag(mac_key=mac_key,encrypted_string=encrypted_string,optional_shared_info1=optional_shared_info[1])
	return ephemeral_pubkey,encrypted_string,tag

def becies_decrypt(ciphertuple,privkey,optional_shared_info=('','')):
	ephemeral_pubkey=ciphertuple[0]
	encrypted_string=ciphertuple[1]
	msgtag=ciphertuple[2]

	shared_secret=bitcoin.decode_pubkey(bitcoin.multiply(privkey,ephemeral_pubkey))[1] #todo: check point at infinity
	shared_secret_bin=_int2bin32b(shared_secret)

	symmetric_key,mac_key=ecies_derive_keys(shared_secret_bin,optional_shared_info0=optional_shared_info[0])

	tag=ecies_compute_tag(mac_key=mac_key,encrypted_string=encrypted_string,optional_shared_info1=optional_shared_info[1])
	if(tag != msgtag):
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
	
	shared_secrets=[becies_shared_secret(r,B)) for B in public_keys]
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
	

