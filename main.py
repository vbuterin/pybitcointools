import hashlib, re, sys, functools, os, base64

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

### http://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python/

def modular_sqrt(a, p):
    if legendre_symbol(a, p) != 1: return 0
    elif a == 0: return 0
    elif p == 2: return p
    elif p % 4 == 3: return pow(a, (p + 1) / 4, p)

    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) / 2, p)
    return -1 if ls == p - 1 else ls

### Base switching

def get_code_string(base):
   if base == 2: return '01'
   elif base == 10: return '0123456789'
   elif base == 16: return "0123456789abcdef"
   elif base == 58: return "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   elif base == 256: return ''.join([chr(x) for x in range(256)])
   else: raise ValueError("Invalid base!")

def encode(val,base,minlen=0):
   code_string = get_code_string(base)
   result = ""   
   while val > 0:
      result = code_string[val % base] + result
      val /= base
   if len(result) < minlen:
      result = code_string[0]*(minlen-len(result))+result
   return result

def decode(string,base):
   code_string = get_code_string(base)
   result = 0
   if base == 16: string = string.lower()
   while len(string) > 0:
      result *= base
      result += code_string.find(string[0])
      string = string[1:]
   return result

def changebase(string,frm,to):
   return encode(decode(string,frm),to)

### Elliptic Curve functions

def base10_add(a,b):
  if a == None: return b[0],b[1]
  if b == None: return a[0],a[1]
  if a[0] == b[0]: 
    if a[1] == b[1]: return base10_double(a[0],a[1])
    else: return None
  m = ((b[1]-a[1]) * inv(b[0]-a[0],P)) % P
  x = (m*m-a[0]-b[0]) % P
  y = (m*(a[0]-x)-a[1]) % P
  return (x,y)
  
def base10_double(a):
  if a == None: return None
  m = ((3*a[0]*a[0]+A)*inv(2*a[1],P)) % P
  x = (m*m-2*a[0]) % P
  y = (m*(a[0]-x)-a[1]) % P
  return (x,y)

def base10_multiply(a,n):
  if n == 0: return G
  if n == 1: return a
  if (n%2) == 0: return base10_double(base10_multiply(a,n/2))
  if (n%2) == 1: return base10_add(base10_double(base10_multiply(a,n/2)),a)

def hex_to_point(h): return (decode(h[2:66],16),decode(h[66:],16))

def point_to_hex(p): return '04'+encode(p[0],16,64)+encode(p[1],16,64)

def multiply(privkey,pubkey):
  return point_to_hex(base10_multiply(hex_to_point(pubkey),decode(privkey,16)))

def privtopub(privkey):
  return point_to_hex(base10_multiply(G,decode(privkey,16)))

def add(p1,p2):
  if (len(p1)==32):
    return encode(decode(p1,16) + decode(p2,16) % P,16,32)
  else:
    return point_to_hex(base10_add(hex_to_point(p1),hex_to_point(p2)))

def neg(key): return (key[0],P-key[1])

### Hashes

def evenlen(hs): return ('0' * (len(hs)%2) + hs)

def hexify(f):
    return lambda x: evenlen(changebase(f(x),256,16))

def bin_hash160(string):
   intermed = hashlib.sha256(string).digest()
   h = hashlib.new('ripemd160')
   h.update(intermed)
   return h.digest()
hash160 = hexify(bin_hash160)

def bin_sha1(string): return hashlib.sha1(string).digest()
sha1 = hexify(bin_sha1)

def bin_sha256(string): return hashlib.sha256(string).digest()
sha256 = hexify(bin_sha256)

def bin_dbl_sha256(string):
   return hashlib.sha256(hashlib.sha256(string).digest()).digest()
dbl_sha256 = hexify(bin_dbl_sha256)

### Encodings
  
def bin_to_b58check(inp,magicbyte=0):
   if isinstance(magicbyte,str): magicbyte = int(magicbyte)
   inp_fmtd = chr(magicbyte) + inp
   leadingzbytes = len(re.match('^\x00*',inp_fmtd).group(0))
   checksum = bin_dbl_sha256(inp_fmtd)[:4]
   return '1' * leadingzbytes + changebase(inp_fmtd+checksum,256,58)

def b58check_to_bin(inp):
   leadingzbytes = len(re.match('^1*',inp).group(0))
   data = '\x00' * leadingzbytes + changebase(inp,58,256)
   assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
   return data[1:-4]

def hex_to_b58check(inp,magicbyte=0):
    return bin_to_b58check(changebase(inp,16,256),magicbyte)

def b58check_to_hex(inp): return evenlen(changebase(b58check_to_bin(inp),256,16))

def pubkey_to_address(pubkey,magicbyte=0):
   return bin_to_b58check(bin_hash160(changebase(pubkey,16,256)),magicbyte)

### EDCSA (experimental)

def yfromx(x,even):
    ans = modular_sqrt(x*x*x+7 % P,P) 
    if ans%2 ^ even: return P-ans
    return ans

# WTF, Electrum?
def electrum_sig_hash(message):
    padded = "\x18Bitcoin Signed Message:\n" + chr( len(message) ) + message
    return decode(bin_dbl_sha256(padded),256)

def ecdsa_sign(msg,priv):

    z = electrum_sig_hash(msg)
    k = decode(os.urandom(32),256)

    r,y = base10_multiply(G,k)
    s = inv(k,N) * (z + r*decode(priv,16)) % N

    vb, rb, sb = chr(27+(y%2)), encode(r,256), encode(s,256)

    return base64.b64encode(vb+'\x00'*(32-len(rb))+rb+'\x00'*(32-len(sb))+sb)

def ecdsa_verify(msg,sig,pub):

    sig256 = base64.b64decode(sig)
    r,s = decode(sig256[1:33],256),decode(sig256[33:],256)

    z = electrum_sig_hash(msg)
    w = inv(s,N)
    
    u1, u2 = z*w % N, r*w % N
    x,y = base10_add(base10_multiply(G,u1), base10_multiply(hex_to_point(pub),u2))

    return r == x

def ecdsa_recover(msg,sig):

    bytez = base64.b64decode(sig)

    v,r,s = ord(bytez[0]), decode(bytez[1:33],256), decode(bytez[33:],256)

    y = yfromx(r,1-(v%2))
    z = electrum_sig_hash(msg)

    Qr = base10_add(neg(base10_multiply(G,z)),base10_multiply((r,y),s))
    Q = base10_multiply(Qr,inv(r,N))

    if ecdsa_verify(msg,sig,point_to_hex(Q)): return point_to_hex(Q)
    return False

def ecdsa_recover_to_address(msg,sig,magicbytes=0):
    return pubkey_to_address(ecdsa_recover(msg,sig),magicbytes)

def ecdsa_verify_with_address(msg,sig,addr,magicbytes=0):
    return addr = pubkey_to_address(ecdsa_recover(msg,sig),magicbytes)
    

funs = {
    "pubkey_to_address": pubkey_to_address,
    "privtopub": privtopub,
    "add": add,
    "bin_to_b58check": bin_to_b58check,
    "b58check_to_bin": b58check_to_bin,
    "hex_to_b58check": hex_to_b58check,
    "b58check_to_hex": b58check_to_hex,
    "sha256": sha256,
    "sign": ecdsa_sign,
    "verifypub": ecdsa_verify,
    "sigpubkey": ecdsa_recover,
    "sigaddr": ecdsa_recover_to_address,
    "verify": ecdsa_verify_with_address
}
if len(sys.argv) > 1:
    f = funs.get(sys.argv[1],None)
    if not f: sys.stderr.write( "Invalid argument" )
    else: print f(*sys.argv[2:])
