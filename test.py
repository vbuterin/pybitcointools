import random, os, json

from main import *

for i in range(10):
    x,y = random.randrange(2**512) - 2**511, random.randrange(2**512) - 2**511
    print multiply(multiply(G,x),y)[0] == multiply(multiply(G,y),x)[0]
    print add(multiply(G,x),multiply(G,y))[0] == multiply(G,add(x,y))[0]
    hx, hy = encode(x%N,16,64), encode(y%N,16,64)
    print multiply(multiply(G,hx),hy)[0] == multiply(multiply(G,hy),hx)[0]
    print add(multiply(G,hx),multiply(G,hy))[0] == multiply(G,add(hx,hy))[0]
    h1601 = b58check_to_hex(pubkey_to_address(privtopub(x)))
    h1602 = b58check_to_hex(pubkey_to_address(multiply(G,hx),23))
    print h1601 == h1602

wallet = "/tmp/tempwallet_"+str(random.randrange(2**40))
print "Starting wallet tests with: "+wallet
os.popen('echo "\n\n\n\n\n\n" | electrum -w %s create' % wallet).read()
addies = json.loads(os.popen("electrum -w %s listaddresses" % wallet).read())

for i in range(10):
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
