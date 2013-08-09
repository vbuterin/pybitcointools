import hashlib, re, sys, functools

### Elliptic curve parameters

P = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
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

def hex_to_point(h): return (decode(h[2:34],16),decode(h[34:],16))

def point_to_hex(p): return '04'+encode(p[0],16,32)+encode(p[1],16,32)

def multiply(privkey,pubkey):
  return point_to_hex(base10_multiply(hex_to_point(pubkey),decode(privkey,16)))

def privtopub(privkey):
  return point_to_hex(base10_multiply(G,decode(privkey,16)))

def add(p1,p2):
  if (len(p1)==32):
    return encode(decode(p1,16) + decode(p2,16) % P,16,32)
  else:
    return point_to_hex(base10_add(hex_to_point(p1),hex_to_point(p2)))

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

def pubkey_to_address(pubkey,magicbyte='\x00'):
   return bin_to_b58check(bin_hash160(changebase(pubkey,16,256)),magicbyte)

funs = {
    "pubkey_to_address": pubkey_to_address,
    "privtopub": privtopub,
    "add": add,
    "bin_to_b58check": bin_to_b58check,
    "b58check_to_bin": b58check_to_bin,
    "hex_to_b58check": hex_to_b58check,
    "b58check_to_hex": b58check_to_hex,
    "sha256": sha256
}
if len(sys.argv) > 1:
    f = funs.get(sys.argv[1],None)
    if not f: sys.stderr.write( "Invalid argument" )
    else: print f(*sys.argv[2:])
