from main import *
import hmac, hashlib

### Electrum wallets

def electrum_stretch(seed): return slowsha(seed)

# Accepts seed or stretched seed, returns master public key
def electrum_mpk(seed):
    if len(seed) == 32: seed = electrum_stretch(seed)
    return privkey_to_pubkey(seed)[2:]

# Accepts (seed or stretched seed) and index, returns privkey
def electrum_privkey(seed,n,for_change=0):
    if len(seed) == 32: seed = electrum_stretch(seed)
    mpk = electrum_mpk(seed)
    offset = decode(bin_dbl_sha256(str(n)+':'+str(for_change)+':'+mpk.decode('hex')),256)
    return encode((decode(seed,16) + offset) % N,16,64)

# Accepts (seed or stretched seed or master public key) and index, returns pubkey
def electrum_pubkey(masterkey,n,for_change=0):
    if len(masterkey) == 32: mpk = electrum_mpk(electrum_stretch(masterkey))
    elif len(masterkey) == 64: mpk = electrum_mpk(masterkey)
    else: mpk = masterkey
    offset = decode(bin_dbl_sha256(str(n)+':'+str(for_change)+':'+mpk.decode('hex')),256)
    return add('04'+mpk,point_to_hex(multiply(G,offset)))

# Below code ASSUMES binary inputs and compressed pubkeys
PRIVDERIV = '\x04\x88\xAD\xE4'
PUBDERIV = '\x04\x88\xB2\x1E'

def raw_bip32_ckd(rawtuple, i):
    vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
    i = int(i)

    if vbytes == PRIVDERIV:
        priv = key
        pub = compress(privtopub(key))
    else:
        pub = key

    if i >= 2**31:
        if vbytes == PUBDERIV:
            raise Exception("Can't do private derivation on public key!")
        I = hmac.new(chaincode,'\x00'+priv+encode(i,256,4),hashlib.sha512).digest()
    else:
        I = hmac.new(chaincode,pub+encode(i,256,4),hashlib.sha512).digest()

    if vbytes == PRIVDERIV:
        newkey = add(I[:32],priv)
        fingerprint = bin_hash160(compress(privtopub(key)))[:4]
    if vbytes == PUBDERIV:
        newkey = compress(add(privtopub(I[:32]),decompress(key)))
        fingerprint = bin_hash160(key)[:4]

    return (vbytes, depth + 1, fingerprint, i, I[32:], newkey)

def bip32_serialize(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    depth = chr(depth % 256)
    i = encode(i,256,4)
    chaincode = encode(hash_to_int(chaincode),256,32)
    keydata = '\x00'+key if vbytes == PRIVDERIV else key
    bindata = vbytes + depth + fingerprint + i + chaincode + keydata
    return changebase(bindata+bin_dbl_sha256(bindata)[:4],256,58)

def bip32_deserialize(data):
    dbin = changebase(data,58,256)
    if bin_dbl_sha256(dbin[:-4])[:4] != dbin[-4:]:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    depth = ord(dbin[4])
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13],256)
    chaincode = dbin[13:45]
    key = dbin[46:78] if vbytes == PRIVDERIV else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)

def raw_bip32_privtopub(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    return (PUBDERIV, depth, fingerprint, i, chaincode, compress(privtopub(key)))

def bip32_privtopub(data):
    return bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data)))

def bip32_ckd(data,i):
    return bip32_serialize(raw_bip32_ckd(bip32_deserialize(data),i))

def bip32_master_key(seed):
    I = hmac.new("Bitcoin seed",seed,hashlib.sha512).digest()
    return bip32_serialize((PRIVDERIV, 0, '\x00'*4, 0, I[32:], I[:32]))

def bip32_bin_extract_key(data):
    k = bip32_deserialize(data)[-1]
    return k[1:] if k[0] == '\x00' else k

def bip32_extract_key(data):
    k = bip32_deserialize(data)[-1]
    return (k[1:] if k[0] == '\x00' else k).encode('hex')
