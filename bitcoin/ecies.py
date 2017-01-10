import bitcoin
from binascii import hexlify,unhexlify
from os import urandom as secure_random_bytes
import hashlib

try:
	from hashlib import pbkdf2_hmac
except:
	from backports.pbkdf2 import pbkdf2_hmac

def _secure_ephemeral():
	return hexlify(secure_random_bytes(32)).zfill(64)

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


hashname='sha256'	#should this be hmac-sha512...yes, works with bip39 hmac and creates a 256 bit key for the symmetric key for the shamir case modulo prime.
hmachash=hashlib.sha256

def ecies_derive_keys(shared_secret,optional_shared_info0=''):
	salt='becies'
	key=shared_secret+optional_shared_info0
	hmac_result=pbkdf2_hmac(hashname,key,salt=salt+key,iterations=2048) #https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
	symmetric_key=hmac_result[:(len(hmac_result)//2)]
	mac_key=hmac_result[(len(hmac_result)//2):]
	return symmetric_key,mac_key

def ecies_compute_tag(mac_key,encrypted_string,optional_shared_info1=''):
	tag=hmac.new(key=mac_key,msg=encrypted_string+optional_shared_info1,digestmod=hmachash)
	return tag

def _int2bin32b(v):
	return unhexlify("%064x" % (v))
	

def encrypt(plaintext,pubkey,ephemeral_key=_secure_ephemeral()):
	optional_shared_info=('','')
	shared_secret=bitcoin.decode_pubkey(bitcoin.multiply(pubkey,ephemeral_key))[1]
	shared_secret_bin=_int2bin32b(shared_secret)

	ephemeral_pubkey=bitcoin.privtopub(ephemeral_key)

	symmetric_key,mac_key=ecies_derive_keys(shared_secret_bin,optional_shared_info0=optional_shared_info[0])
	
	aes=AESCipher(symmetric_key)
	encrypted_string=aes.encrypt(plaintext)
	
	tag=ecies_compute_tag(mac_key=mac_key,encrypted_string=encrypted_string,optional_shared_info1=optional_shared_info[1])
	return ephemeral_pubkey,encrypted_string,tag

def decrypt(ciphertuple,privkey):
	optional_shared_info=('','')
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
	


k=_secure_ephemeral()
pk=bitcoin.privtopub(k)
print(pk)
print(encrypt("hi",pk))
