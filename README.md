# Pybitcointools, Python library for Bitcoin signatures and transactions

This is a fork of Vitalik Buterin's original pybitcointools which is no longer maintained.

Still in a very early development stage...some stuff not working.

Done:
* Better Python3 support
* Replace bci.py with other explorers
* Class-based api for different coins, making it easier to add new coins with a common interface
* Unspents and broadcast transaction tested for live Bitcoin and for the following testnets: Bitcoin, Litecoin and Dash (Dogecoin does not seem to have a working testnet explorer)

Needs to be tested:
* Live network transactions for Litecoin, Dash and Dogecoin

If anyone can help with getting the Bitcoin Cash replay protection signatures working, that would be a big help.

Short term roadmap:
* Possible renaming (pycryptotools?)
* Release on pip


Longer-term roadmap:
* Integrate pull requests from pybitcointools, e.g. Segwit support
* Read the docs page
* E-commerce tools (exchange rates, short-time invoices)
* Easily gather unspents and broadcast transactions based on a mnemonic
* Desktop GUI for easy creation, signing and broadcasting of raw transactions
* Seed-based multi-crypto wallet

The rest of this readme is pretty much taken directly from the original pybitcointools library and needs to be updated.
### Advantages:

* Functions have a simple interface, inputting and outputting in standard formats
* Classes for different coins with a common interface
* Many functions can be taken out and used individually
* Supports binary, hex and base58
* Transaction deserialization format almost compatible with BitcoinJS
* Electrum and BIP0032 support
* Make and publish a transaction all in a single command line instruction with full control
* Includes non-bitcoin-specific conversion and JSON utilities

### Disadvantages:

* Not a full node, has no idea what blocks are
* Relies on centralized explorers for blockchain operations

### Example usage (best way to learn :) ):

    > from bitcoin import *
    > c = Bitcoin(testnet=True)
    > priv = sha256('a big long brainwallet password')
    > priv
    '89d8d898b95addf569b458fbbd25620e9c9b19c9f730d5d60102abbabcb72678'
    > pub = c.privtopub(priv)
    > pub
    '041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f'
    > addr = c.pubtoaddr(pub)
    > addr
    'mwJUQbdhamwemrsR17oy7z9upFh4JtNxm1'
    > inputs = c.unspent(addr)
    > inputs
    [{'output': '350c0292939bf581c847b95b3f864c8c50d51bda68201530b4c23c0e91818988:0', 'value': 55000000, 'time': 'Thu Dec 21 09:43:34 2017'}, {'output': '93b1fe01f0f581d06fce2206c4e0ac0420f5ebc262af31a467ed11ad2b8d884c:0', 'value': 27500000, 'time': 'Thu Dec 21 09:43:34 2017'}]  #Time not needed for use as input
    > outs = [{'value': 82211600, 'address': '2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF'}, {'value': 90000, 'address': 'mrvHv6ggk5gFMatuJtBKAzktTU1N3MYdu2'}]
    > tx = c.mktx(inputs,outs)
    > tx
    '0100000002888981910e3cc2b430152068da1bd5508c4c863f5bb947c881f59b9392020c350000000000ffffffff4c888d2bad11ed67a431af62c2ebf52004ace0c40622ce6fd081f5f001feb1930000000000ffffffff021073e6040000000017a914a9974100aeee974a20cda9a2f545704a0ab54fdc87905f0100000000001976a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac00000000'
    > tx2 = c.sign(tx,0,priv)
    > tx2
    '0100000002888981910e3cc2b430152068da1bd5508c4c863f5bb947c881f59b9392020c35000000008a47304402201ed9652b392b6e6418d94fbacb730c36d65052fc358d6f25d633e0de9687734502207081ad4008cf173bd463733961f2f0ee2b3ce33251d5059f35b651fd97142ed10141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764fffffffff4c888d2bad11ed67a431af62c2ebf52004ace0c40622ce6fd081f5f001feb1930000000000ffffffff021073e6040000000017a914a9974100aeee974a20cda9a2f545704a0ab54fdc87905f0100000000001976a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac00000000'
    > tx3 = c.sign(tx2,1,priv)
    > tx3
    '0100000002888981910e3cc2b430152068da1bd5508c4c863f5bb947c881f59b9392020c35000000008a47304402201ed9652b392b6e6418d94fbacb730c36d65052fc358d6f25d633e0de9687734502207081ad4008cf173bd463733961f2f0ee2b3ce33251d5059f35b651fd97142ed10141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764fffffffff4c888d2bad11ed67a431af62c2ebf52004ace0c40622ce6fd081f5f001feb193000000008a473044022062c5bc96ba01b7e178d19df6bf5731ad03f61055367a0d598c97d3d359cee8c202202f274d806dc9b3b35142b63a10a52795de69e22cc7671b737422abb3a2418a4f0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764fffffffff021073e6040000000017a914a9974100aeee974a20cda9a2f545704a0ab54fdc87905f0100000000001976a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac00000000'
    > deserialize(tx)
    {'ins': [{'outpoint': {'hash': '350c0292939bf581c847b95b3f864c8c50d51bda68201530b4c23c0e91818988', 'index': 0}, 'script': '', 'sequence': 4294967295}, {'outpoint': {'hash': '93b1fe01f0f581d06fce2206c4e0ac0420f5ebc262af31a467ed11ad2b8d884c', 'index': 0}, 'script': '', 'sequence': 4294967295}], 'outs': [{'value': 82211600, 'script': 'a914a9974100aeee974a20cda9a2f545704a0ab54fdc87'}, {'value': 90000, 'script': '76a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac'}], 'version': 1, 'locktime': 0}
    > c.pushtx(tx3)
    {'status': 'success', 'data': {'network': 'BTCTEST', 'txid': '99d88509d5f0e298bdb6883161c64c7f54444519ce28a0ef3d5942ff4ff7a924'}}

Or using the pybtctool command line interface:

    pybtctool random_electrum_seed
    484ccb566edb66c65dd0fd2e4d90ef65

    pybtctool electrum_privkey 484ccb566edb66c65dd0fd2e4d90ef65 0 0
    593240c2205e7b7b5d7c13393b7c9553497854b75c7470b76aeca50cd4a894d7

    pybtctool electrum_mpk 484ccb566edb66c65dd0fd2e4d90ef65
    484e42865b8e9a6ea8262fd1cde666b557393258ed598d842e563ad9e5e6c70a97e387eefdef123c1b8b4eb21fe210c6216ad7cc1e4186fbbba70f0e2c062c25

    pybtctool bip32_master_key 21456t243rhgtucyadh3wgyrcubw3grydfbng
    xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT

    pybtctool bip32_ckd xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT 0
    xprv9vfzYrpwo7QHFdtrcvsSCTrBESFPUf1g7NRvayy1QkEfUekpDKLfqvHjgypF5w3nAvnwPjtQUNkyywWNkLbiUS95khfHCzJXFkLEdwRepbw 

    pybtctool bip32_privtopub xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT
    xpub661MyMwAqRbcFGfHrgLHpC5R4odnyasAZdefbDkHBcWarJcXh6SzTzbUkWuhnP142ZFdKdAJSuTSaiGDYjvm7bCLmA8DZqksYjJbYmcgrYF

The -s option lets you read arguments from the command line

    pybtctool sha256 'some big long brainwallet password' | pybtctool -s privtoaddr | pybtctool -s history
    [{'output': u'97f7c7d8ac85e40c255f8a763b6cd9a68f3a94d2e93e8bfa08f977b92e55465e:0', 'value': 50000, 'address': u'1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'}, {'output': u'4cc806bb04f730c445c60b3e0f4f44b54769a1c196ca37d8d4002135e4abd171:1', 'value': 50000, 'address': u'1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'}]
    pybtctool random_electrum_seed | pybtctool -s electrum_privkey 0 0
    593240c2205e7b7b5d7c13393b7c9553497854b75c7470b76aeca50cd4a894d7

The -b option lets you read binary data as an argument

    pybtctool sha256 123 | pybtctool -s changebase 16 256 | pybtctool -b changebase 256 16
    a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae30a

The -j option lets you read json from the command line (-J to split a json list into multiple arguments)

    pybtctool unspent 1FxkfJQLJTXpW6QmxGT6oF43ZH959ns8Cq | pybtctool -j select 200000001 | pybtctool -j mksend 1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P:20000 1FxkfJQLJTXpW6QmxGT6oF43ZH959ns8Cq 1000 | pybtctool -s signall 805cd74ca322633372b9bfb857f3be41db0b8de43a3c44353b238c0acff9d523
    0100000003d5001aae8358ae98cb02c1b6f9859dc1ac3dbc1e9cc88632afeb7b7e3c510a49000000008b4830450221009e03bb6122437767e2ca785535824f4ed13d2ebbb9fa4f9becc6d6f4e1e217dc022064577353c08d8d974250143d920d3b963b463e43bbb90f3371060645c49266b90141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff1529d655dff6a0f6c9815ee835312fb3ca4df622fde21b6b9097666e9284087d010000008a473044022035dd67d18b575ebd339d05ca6ffa1d27d7549bd993aeaf430985795459fc139402201aaa162cc50181cee493870c9479b1148243a33923cb77be44a73ca554a4e5d60141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff23d5f9cf0a8c233b35443c3ae48d0bdb41bef357b8bfb972336322a34cd75c80010000008b483045022014daa5c5bbe9b3e5f2539a5cd8e22ce55bc84788f946c5b3643ecac85b4591a9022100a4062074a1df3fa0aea5ef67368d0b1f0eaac520bee6e417c682d83cd04330450141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff02204e0000000000001976a914946cb2e08075bcbaf157e47bcb67eb2b2339d24288ac5b3c4411000000001976a914a41d15ae657ad3bfd0846771a34d7584c37d54a288ac00000000

Fun stuff with json:

    pybtctool unspent 1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P | pybtctool -j multiaccess value | pybtctool -j sum
    625216206372

    pybtctool unspent 1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P | pybtctool -j count
    6198

To use the testnet you can add --testnet:

    python pybtctool unspent 2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF --testnet
    [{"output": "209e5caf8997a3caed4dce0399804ad7fa50c70f866bb7118a42c79de1b76efc:1", "value": 120000000, "time": "Thu Dec 21 08:33:05 2017"}, {"output": "79f38b3e730eea0e44b5a2e645f0979
    2d9f8732a823079ba4778110657cbe7b2:0", "value": 100000000, "time": "Thu Dec 21 09:31:55 2017"}, {"output": "99d88509d5f0e298bdb6883161c64c7f54444519ce28a0ef3d5942ff4ff7a924:0", "value
    ": 82211600, "time": "Thu Dec 21 09:52:00 2017"}, {"output": "80acca12cf4b3b562b583f1dc7e43fff936e432a7ed4b16ac3cd10024820d027:0", "value": 192470000, "time": "Thu Dec 21 09:52:00 20
    17"}, {"output": "3e5a3fa342c767d524b653aec51f3efe2122644c57340fbf5f79c75d1911ad35:0", "value": 10000000, "time": "Thu Dec 21 10:18:48 2017"}]

Or the --coin option to use coin other than bitcoin (bch, btc, dash, doge or ltc)

    python pybtctool unspent LV3VLesnCi3p3zf26Y86kH2FZxfQq2RjrA --coin ltc
    [{"output": "42bfe7376410696e260b2198f484f5df4aa6c744465940f9922ac9f8589670a4:0", "value": 14282660, "time": "Thu Dec 21 10:36:08 2017"}]

    python pybtctool unspent myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW --coin ltc --testnet
    [{"output": "f27a53b9433eeb9d011a8c77439edb7a582a01166756e00ea1076699bfa58371:0", "value": 1993472, "time": "Wed Dec 20 14:38:07 2017"}, {"output": "2a288547460ebe410e98fe63a1900b645
    2d95ec318efb0d58a5584ac67f27d93:1", "value": 177961076, "time": "Wed Dec 20 17:01:32 2017"}, {"output": "da0e900e4ed8e3661bef6f6fa5beed78fec3f7b9e4cc87c7120108eba66f270f:0", "value":
     1971905, "time": "Wed Dec 20 17:01:32 2017"}]

Make and broadcast a transaction on the Dash testnet:

    python pybtctool send cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz 44907516684 --fee 20000 --coin dash --testnet
    {"status": "success", "data": {"txid": "725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0", "network": "DASHTEST"}}

The arguments are the private key of the sender, the receiver and fee. Change will be returned to the sender. 
### Listing of main coin-specific commands:

* privkey_to_pubkey    : (privkey) -> pubkey
* privtopub            : (privkey) -> pubkey
* pubkey_to_address    : (pubkey) -> address
* pubtoaddr            : (pubkey) -> address
* privkey_to_address   : (privkey) -> address
* privtoaddr           : (privkey) -> address
* sign                 : (tx, i, privkey) -> create digital signature of tx with privkey and add to input i
* signall              : (tx, privkey) -> create digital signature of tx with privkey for all inputs
* history              : (address) -> tx history of an address
* unspent              : (address, etc) -> unspent outputs for an addresses
* pushtx               : (hex or bin tx) -> push a transaction to the blockchain
* send                 : (privkey, to, value, fee) -> create and a push a simple transaction to send coins to an address and return change to the sender

### Listing of main non-coin specific commands:

* add                  : (key1, key2) -> key1 + key2 (works on privkeys or pubkeys)
* multiply             : (pubkey, privkey) -> returns pubkey * privkey

* ecdsa_sign           : (message, privkey) -> sig
* ecdsa_verify         : (message, sig, pubkey) -> True/False
* ecdsa_recover        : (message, sig) -> pubkey

* random_key           : () -> privkey
* random_electrum_seed : () -> electrum seed

* electrum_stretch     : (seed) -> secret exponent
* electrum_privkey     : (seed or secret exponent, i, type) -> privkey
* electrum_mpk         : (seed or secret exponent) -> master public key
* electrum_pubkey      : (seed or secexp or mpk) -> pubkey

* bip32_master_key     : (seed) -> bip32 master key
* bip32_ckd            : (private or public bip32 key, i) -> child key
* bip32_privtopub      : (private bip32 key) -> public bip32 key
* bip32_extract_key    : (private or public bip32_key) -> privkey or pubkey

* deserialize          : (hex or bin transaction) -> JSON tx
* serialize            : (JSON tx) -> hex or bin tx
* mktx                 : (inputs, outputs) -> tx
* mksend               : (inputs, outputs, change_addr, fee) -> tx
* multisign            : (tx, i, script, privkey) -> signature
* apply_multisignatures: (tx, i, script, sigs) -> tx with index i signed with sigs
* scriptaddr           : (script) -> P2SH address
* mk_multisig_script   : (pubkeys, k, n) -> k-of-n multisig script from pubkeys
* verify_tx_input      : (tx, i, script, sig, pub) -> True/False
* tx_hash              : (hex or bin tx) -> hash

* access               : (json list/object, prop) -> desired property of that json object
* multiaccess          : (json list, prop) -> like access, but mapped across each list element
* slice                : (json list, start, end) -> given slice of the list
* count                : (json list) -> number of elements
* sum                  : (json list) -> sum of all values
