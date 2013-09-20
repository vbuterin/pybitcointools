import random, os, json, sys

from main import *
from transaction import *

argv = sys.argv + ['y']*4

if argv[1] == 'y':
    print "Starting ECC arithmetic tests"
for i in range(8 if argv[1] == 'y' else 0):
    print "### Round %d" % (i+1)
    x,y = random.randrange(2**512) - 2**511, random.randrange(2**512) - 2**511
    print multiply(multiply(G,x),y)[0] == multiply(multiply(G,y),x)[0]
    print add(multiply(G,x),multiply(G,y))[0] == multiply(G,add(x,y))[0]
    hx, hy = encode(x%N,16,64), encode(y%N,16,64)
    print multiply(multiply(G,hx),hy)[0] == multiply(multiply(G,hy),hx)[0]
    print add(multiply(G,hx),multiply(G,hy))[0] == multiply(G,add(hx,hy))[0]
    h1601 = b58check_to_hex(pubkey_to_address(privtopub(x)))
    h1602 = b58check_to_hex(pubkey_to_address(multiply(G,hx),23))
    print h1601 == h1602
    p = privtopub(sha256(str(x)))
    if i%2 == 1: p = changebase(p,16,256)
    print decompress(compress(p)) == p

if argv[2] == 'y':
    print "Starting Electrum tests"
for i in range(3 if argv[2] == 'y' else 0):
    seed = sha256(str(random.randrange(2**40)))[:32]
    mpk = electrum_mpk(seed)
    print 'seed: ',seed
    print 'mpk: ',mpk
    for i in range(5):
        pk = electrum_privkey(seed,i)
        pub = electrum_pubkey((mpk,seed)[i%2],i)
        pub2 = privtopub(pk)
        print 'priv: ',pk
        print 'pub: ',pub
        print pub == pub2
        if pub != pub2: print 'DOES NOT MATCH!!!!\npub2: '+pub2

if argv[3] == 'y':
    wallet = "/tmp/tempwallet_"+str(random.randrange(2**40))
    print "Starting wallet tests with: "+wallet
    os.popen('echo "\n\n\n\n\n\n" | electrum -w %s create' % wallet).read()
    addies = json.loads(os.popen("electrum -w %s listaddresses" % wallet).read())

for i in range(8 if argv[3] == 'y' else 0):
    alphabet = "1234567890qwertyuiopasdfghjklzxcvbnm"
    msg = ''.join([random.choice(alphabet) for i in range(random.randrange(20,200))])
    addy = random.choice(addies)
    wif = os.popen('electrum -w %s dumpprivkey %s' % (wallet, addy)).readlines()[-1].strip()
    priv = b58check_to_hex(wif)
    pub = privtopub(priv)

    sig = os.popen('electrum -w %s signmessage %s %s' % (wallet, addy, msg)).readlines()[-1].strip()
    verified = ecdsa_verify(msg,sig,pub)
    print "Verified" if verified else "Verification error"
    rec = ecdsa_recover(msg,sig)
    if pub == rec: print "Recovery successful"
    if pub != rec or not verified:
        print "msg: "+msg
        print "sig: "+sig
        print "priv: "+priv
        print "addy: "+addy
    if pub != rec:
        print "Recovery error"
        print "original  pub: "+pub, hex_to_point(pub)[1]
        print "recovered pub: "+rec

    mysig = ecdsa_sign(msg,priv)
    v = os.popen('electrum -w %s verifymessage %s %s %s' % (wallet,addy, sig, msg)).read()
    print v

for i in range(10 if argv[4] == 'y' else 0):
    alphabet = "1234567890qwertyuiopasdfghjklzxcvbnm"
    msg = ''.join([random.choice(alphabet) for i in range(random.randrange(20,200))])
    priv = sha256(str(random.randrange(2**256)))
    pub = privtopub(priv)
    sig = ecdsa_der_sign(msg,priv)
    v = ecdsa_der_verify(msg,sig,pub)
    print "Verified" if v else "Verification error"
    rec = ecdsa_der_recover(msg,sig)
    print "Recovered" if pub in rec else "Recovery failed"
