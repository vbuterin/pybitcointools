import bitcoin
import os
from binascii import hexlify

def _secure_random(nbytes):
	return int(hexlify(os.urandom(nbytes)),16)
def _secure_privkey():
	return _secure_random(32) % bitcoin.N

def gen_points(coeffs,n):
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
	
yl=gen_points([5,10],bitcoin.N)
print yl
print lagrange_interpolate(range(1,len(yl)+1),yl,bitcoin.N)

#r,R = sender's ephemeral private key and pubkey
#o[0..d] = offsets 
#s[0...d] = shared_secrets
#b[0...d],B = recievers private and public key


def becies_multi_encrypt(plaintext,k,public_keys,new_privkey_func=_secure_privkey):
	m=len(public_keys)
	coeffs=[new_privkey_func() for _ in range(k)]
	points=gen_points(coeffs,bitcoin.N)

	r=new_privkey_func()
	group_pubkey=bitcoin.privtopub(coeffs[0])
	becies=becies_encrypt(plaintext,r,group_pubkey)
	
	shared_secrets=[becies_shared_secret(r,B) for B in public_keys]
	offsets=[(p-s) % bitcoin.N for p,s in zip(points,shared_secrets)]
	
	return becies,offsets

#each wallet provides the result of 
#becies_shared_secret(b,R) given R, where b is the private key of the address. DOES THIS HAVE weaknesses? Probably not because of hash

#in reality, this should accept an array of shared secrets secret(b[...]*r), not the actual private keys.
def becies_multi_decrypt(ciphertext,becies,shared_secrets,indices,offsets):
	R=becies.R
	points=[(o+p) % bitcoin.N for o,p in zip(offsets,shared_secrets)]
	group_privkey=lagrange_interpolate(indices,points,bitcoin.N)
	return becies_decrypt(ciphertext,becies,group_privkey)
	
#encoding:
#first, the public keys are given as a list of addresses,If it's a multisig address then it is interpreted as the set of ALL public keys in the multisig address (the n of m data is IGNORED)
#then M offsets, where M is the number of addresses found in the address list. (only if M>1)
#then k, then 
#first, R,c,d as becies string.

#authentication r MUST NOT be the private key of the address
#r MUST 

