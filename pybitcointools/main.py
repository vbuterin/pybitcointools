#!/usr/bin/python
import hashlib, re, sys, os, base64, time, random, hmac

### Elliptic curve parameters

P = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = 0
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx,Gy)

### Extended Euclidean Algorithm

def inv(a,n):
  lm, hm = 1,0
  low, high = a%n,n
  while low > 1:
    r = high/low
    nm, new = hm-lm*r, high-low*r
    lm, low, hm, high = nm, new, lm, low
  return lm % n

### Base switching

def get_code_string(base):
   if base == 2: return '01'
   elif base == 10: return '0123456789'
   elif base == 16: return "0123456789abcdef"
   elif base == 58: return "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   elif base == 256: return ''.join([chr(x) for x in range(256)])
   else: raise ValueError("Invalid base!")

def encode(val,base,minlen=0):
   base, minlen = int(base), int(minlen)
   code_string = get_code_string(base)
   result = ""   
   while val > 0:
      result = code_string[val % base] + result
      val /= base
   if len(result) < minlen:
      result = code_string[0]*(minlen-len(result))+result
   return result

def decode(string,base):
   base = int(base)
   code_string = get_code_string(base)
   result = 0
   if base == 16: string = string.lower()
   while len(string) > 0:
      result *= base
      result += code_string.find(string[0])
      string = string[1:]
   return result

def changebase(string,frm,to,minlen=0):
   return encode(decode(string,frm),to,minlen)

### Elliptic Curve functions

def isinf(p): return p[0] == 0 and p[1] == 0

def base10_add(a,b):
  if isinf(a): return b[0],b[1]
  if isinf(b): return a[0],a[1]
  if a[0] == b[0]: 
    if a[1] == b[1]: return base10_double(a[0],a[1])
    else: return (0,0)
  m = ((b[1]-a[1]) * inv(b[0]-a[0],P)) % P
  x = (m*m-a[0]-b[0]) % P
  y = (m*(a[0]-x)-a[1]) % P
  return (x,y)
  
def base10_double(a):
  if isinf(a): return (0,0)
  m = ((3*a[0]*a[0]+A)*inv(2*a[1],P)) % P
  x = (m*m-2*a[0]) % P
  y = (m*(a[0]-x)-a[1]) % P
  return (x,y)

def base10_multiply(a,n):
  if isinf(a) or n == 0: return (0,0)
  if n == 1: return a
  if n < 0 or n >= N: return base10_multiply(a,n%N)
  if (n%2) == 0: return base10_double(base10_multiply(a,n/2))
  if (n%2) == 1: return base10_add(base10_double(base10_multiply(a,n/2)),a)

def hex_to_point(h): return (decode(h[2:66],16),decode(h[66:],16))
def point_to_hex(p): return '04'+encode(p[0],16,64)+encode(p[1],16,64)

def bin_to_point(h): return (decode(h[1:33],256),decode(h[33:],256))
def point_to_bin(p): return '\x04'+encode(p[0],256,32)+encode(p[1],256,32)

def pub_to_point(p):
    if len(p) > 66: return hex_to_point(p) # pubkey hex
    elif len(p) > 2: return bin_to_point(p) # pubkey bin
    else: return p

# Warning: this method removes compression information
def priv_to_int(p):
    if isinstance(p,(int,long)): return p
    if len(p) >= 64: return decode(p[:64],16) # sha256 hex
    elif len(p) > 45: return decode(b58check_to_bin(p)[:32],256) # sha256 b58
    elif len(p) >= 32: return decode(p[:32],256) #sha256 bin
    else: raise Exception("priv_to_int: what did you throw at me?")

hash_to_int = priv_to_int

def multiply(pubkey,privkey):
  if isinstance(privkey,str): 
      privkey = decode(privkey,16)
  if isinstance(pubkey,str):
      return point_to_hex(multiply(hex_to_point(pubkey),privkey))
  return base10_multiply(pubkey,privkey)

def privkey_to_pubkey(privkey):
  if isinstance(privkey,(int,long)):
      return base10_multiply(G,privkey)
  if len(privkey) == 64: 
      return point_to_hex(base10_multiply(G,decode(privkey,16)))
  elif len(privkey) == 66:
      return compress(base10_multiply(G,decode(privkey[:-2],16)),'hex')
  elif len(privkey) == 32:
      return point_to_bin(base10_multiply(G,decode(privkey,256)))
  elif len(privkey) == 33:
      return compress(base10_multiply(G,decode(privkey[:-1],256)),'bin')
  else:
      return privkey_to_pubkey(b58check_to_hex(privkey))

privtopub = privkey_to_pubkey

def privkey_to_address(priv):
    return pubkey_to_address(privkey_to_pubkey(priv))
privtoaddr = privkey_to_address

# Addition is mod N, use for private and public keys only, NOT coordinates!
def add(p1,p2):
  if isinstance(p1,(int,long)):
    return (p1+p2) % N
  elif len(p1) == 64:
    return encode((decode(p1,16) + decode(p2,16)) % N,16,64)
  elif len(p1) == 32:
    return encode((decode(p1,256) + decode(p2,256)) % N,256,32)
  elif isinstance(p1,(tuple,list)):
    return base10_add(p1,p2)
  elif len(p1) == 65:
    return point_to_bin(base10_add(bin_to_point(p1),bin_to_point(p2)))
  elif len(p1) == 130:
    return point_to_hex(base10_add(hex_to_point(p1),hex_to_point(p2)))
  else:
    raise Exception("What in the world are you feeding me??")

def neg(pubkey): 
    if isinstance(pubkey,(list,tuple)): return (pubkey[0],P-pubkey[1])
    else: return point_to_hex(neg(hex_to_point(pubkey)))

### Hashes

def bin_hash160(string):
   intermed = hashlib.sha256(string).digest()
   return hashlib.new('ripemd160',intermed).digest()
def hash160(string):
    return bin_hash160(string).encode('hex')

def bin_sha256(string):
    return hashlib.sha256(string).digest()
def sha256(string):
    return bin_sha256(string).encode('hex')

def bin_dbl_sha256(string):
   return hashlib.sha256(hashlib.sha256(string).digest()).digest()
def dbl_sha256(string):
   return bin_dbl_sha256(string).encode('hex')

def bin_slowsha(string):
    orig_input = string
    for i in range(100000):
        string = hashlib.sha256(string + orig_input).digest()
    return string
def slowsha(string):
    return bin_slowsha(string).encode('hex')

def num_to_var_int(x):
    x = int(x)
    if x < 253: return chr(x)
    elif x < 65536: return chr(253) + encode(x,256,2)[::-1]
    elif x < 4294967296: return chr(254) + encode(x,256,4)[::-1]
    else: return chr(255) + encode(x,256,8)[::-1]

# WTF, Electrum?
def electrum_sig_hash(message):
    padded = "\x18Bitcoin Signed Message:\n" + num_to_var_int( len(message) ) + message
    return bin_dbl_sha256(padded)

def random_key():
    # Gotta be secure after that java.SecureRandom fiasco...
    entropy = os.urandom(32)+str(random.randrange(2**256))+str(int(time.time())**7)
    return sha256(entropy)

def random_electrum_seed():
    entropy = os.urandom(32)+str(random.randrange(2**256))+str(int(time.time())**7)
    return sha256(entropy)[:32]

### Encodings
  
def bin_to_b58check(inp,magicbyte=0):
    inp_fmtd = chr(int(magicbyte)) + inp
    leadingzbytes = len(re.match('^\x00*',inp_fmtd).group(0))
    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return '1' * leadingzbytes + changebase(inp_fmtd+checksum,256,58)

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*',inp).group(0))
    data = '\x00' * leadingzbytes + changebase(inp,58,256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

def hex_to_b58check(inp,magicbyte=0):
    return bin_to_b58check(inp.decode('hex'),magicbyte)

def b58check_to_hex(inp): return b58check_to_bin(inp).encode('hex')

def pubkey_to_address(pubkey,magicbyte=0):
   if isinstance(pubkey,(list,tuple)):
       return pubkey_to_address(point_to_bin(pubkey),magicbyte)
   if len(pubkey) in [66,130]:
       return bin_to_b58check(bin_hash160(pubkey.decode('hex')),magicbyte)
   return bin_to_b58check(bin_hash160(pubkey),magicbyte)

pubtoaddr = pubkey_to_address

def compress(pubkey,out=None):
    if len(pubkey) == 33 or len(pubkey) == 66: return pubkey
    if len(pubkey) == 65 and not out: return compress(bin_to_point(pubkey),'bin')
    if len(pubkey) == 130 and not out: return compress(hex_to_point(pubkey),'hex')
    if out == 'bin': return chr(2+(pubkey[1]%2))+encode(pubkey[0],256,32)
    return '0'+str(2+(pubkey[1]%2))+encode(pubkey[0],16,64)

def decompress(pubkey):
    if len(pubkey) == 65 or len(pubkey) == 130: return pubkey
    if len(pubkey) == 33: x,ymod2 = decode(pubkey[1:],256),ord(pubkey[0])-2
    else: x,ymod2 = decode(pubkey[2:],16),int(pubkey[1])-2
    beta = pow(x*x*x+7,(P+1)/4,P)
    y = (P-beta) if (beta%2) ^ ymod2 else beta
    if len(pubkey) == 33: return '\x04'+pubkey[1:]+encode(y,256,32)
    else: return '04'+pubkey[2:]+encode(y,16,64)


### EDCSA

def encode_sig(v,r,s):
    vb, rb, sb = chr(v), encode(r,256), encode(s,256)
    return base64.b64encode(vb+'\x00'*(32-len(rb))+rb+'\x00'*(32-len(sb))+sb)

def decode_sig(sig):
    bytez = base64.b64decode(sig)
    return ord(bytez[0]), decode(bytez[1:33],256), decode(bytez[33:],256)

# https://tools.ietf.org/html/rfc6979#section-3.2
def deterministic_generate_k(msghash,priv):
    v = '\x01' * 32
    k = '\x00' * 32
    priv = encode(priv_to_int(priv),256,32)
    msghash = encode(hash_to_int(msghash),256,32)
    k = hmac.new(k, v+'\x00'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v+'\x01'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    return decode(hmac.new(k, v, hashlib.sha256).digest(),256)

def ecdsa_raw_sign(msghash,priv):

    z = hash_to_int(msghash)
    k = deterministic_generate_k(msghash,priv)

    r,y = base10_multiply(G,k)
    s = inv(k,N) * (z + r*priv_to_int(priv)) % N

    return 27+(y%2),r,s

def ecdsa_sign(msg,priv):
    return encode_sig(*ecdsa_raw_sign(electrum_sig_hash(msg),priv))

def ecdsa_raw_verify(msghash,vrs,pub):
    v,r,s = vrs

    w = inv(s,N)
    z = hash_to_int(msghash)
    
    u1, u2 = z*w % N, r*w % N
    x,y = base10_add(base10_multiply(G,u1), base10_multiply(pub_to_point(pub),u2))

    return r == x

def ecdsa_verify(msg,sig,pub):
    return ecdsa_raw_verify(electrum_sig_hash(msg),decode_sig(sig),pub)

def ecdsa_raw_recover(msghash,vrs):
    v,r,s = vrs

    x = r
    beta = pow(x*x*x+7,(P+1)/4,P)
    y = beta if v%2 ^ beta%2 else (P - beta)
    z = hash_to_int(msghash)

    Qr = base10_add(neg(base10_multiply(G,z)),base10_multiply((x,y),s))
    Q = base10_multiply(Qr,inv(r,N))

    if ecdsa_raw_verify(msghash,vrs,point_to_hex(Q)): return point_to_hex(Q)
    return False

def ecdsa_recover(msg,sig):
    return ecdsa_raw_recover(electrum_sig_hash(msg),decode_sig(sig))
