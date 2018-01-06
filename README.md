# Pycryptotools, Python library for Bitcoin signatures and transactions

This is a fork of Vitalik Buterin's original [pybitcointools](https://github.com/vbuterin/pybitcointools) library.

Library now supports:

* Bitcoin mainnet
* Bitcoin testnet 
* Bitcoin cash mainnet**
* Bitcoin cash testnet 
* Litecoin mainnet**
* Litecoin testnet
* Dash mainnet**
* Dash testnet
* Dogecoin mainnet**

** Transaction broadcast not tested

A simple, class-based API makes switching between mainnet and testnet very easy.

Longer-term roadmap:
* Integrate pull requests from pybitcointools, e.g. Segwit support
* Read the docs page
* E-commerce tools (exchange rates, short-time invoices)
* Easily gather unspents and broadcast transactions based on a mnemonic
* Desktop GUI for easy creation, signing and broadcasting of raw transactions
* Seed-based multi-crypto wallet

Contributions:
* Needs to be tested: Live network transactions for Bitcoin Cash, Litecoin, Dash and Dogecoin
* Anyone know a working Dogecoin testnet explorer?

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
    [{'output': '3be10a0aaff108766371fd4f4efeabc5b848c61d4aac60db6001464879f07508:0', 'value': 180000000, 'time': 'Sat Jan  6 22:43:15 2018'}, {'output': '51ce9804e1a4fd3067416eb5052b9930fed7fdd9857067b47d935d69f41faa38:0', 'value': 90000000, 'time': 'Sat Jan  6 22:43:15 2018'}]
    > outs = [{'value': 269845600, 'address': '2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF'}, {'value': 100000, 'address': 'mrvHv6ggk5gFMatuJtBKAzktTU1N3MYdu2'}]
    > tx = mktx(inputs,outs)
    > tx
    {'locktime': 0, 'version': 1, 'ins': [{'outpoint': {'hash': '3be10a0aaff108766371fd4f4efeabc5b848c61d4aac60db6001464879f07508', 'index': 0}, 'amount': 180000000, 'script': '483045022100fccd16f619c5f8b8198f5a00f557f6542afaae10b2992733963c5b9c4042544c022041521e7ab2f4b58856e8554c651664af92f6abd58328c41bc652aea460a9a6a30141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}, {'outpoint': {'hash': '51ce9804e1a4fd3067416eb5052b9930fed7fdd9857067b47d935d69f41faa38', 'index': 0}, 'amount': 90000000, 'script': '483045022100a9f056be75da4167c2cae9f037e04f6efd20caf97e05052406c127d72e7f236c02206638c10ad6975b44c26633e7c40547405dd4e6184fa3afd0ec98260369fadb0d0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}], 'outs': [{'script': 'a914a9974100aeee974a20cda9a2f545704a0ab54fdc87', 'value': 269845600}, {'script': '76a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac', 'value': 100000}]}
    > tx2 = c.sign(tx,0,priv)
    > tx2
    {'locktime': 0, 'version': 1, 'ins': [{'outpoint': {'hash': '3be10a0aaff108766371fd4f4efeabc5b848c61d4aac60db6001464879f07508', 'index': 0}, 'amount': 180000000, 'script': '483045022100fccd16f619c5f8b8198f5a00f557f6542afaae10b2992733963c5b9c4042544c022041521e7ab2f4b58856e8554c651664af92f6abd58328c41bc652aea460a9a6a30141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}, {'outpoint': {'hash': '51ce9804e1a4fd3067416eb5052b9930fed7fdd9857067b47d935d69f41faa38', 'index': 0}, 'amount': 90000000, 'script': '483045022100a9f056be75da4167c2cae9f037e04f6efd20caf97e05052406c127d72e7f236c02206638c10ad6975b44c26633e7c40547405dd4e6184fa3afd0ec98260369fadb0d0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}], 'outs': [{'script': 'a914a9974100aeee974a20cda9a2f545704a0ab54fdc87', 'value': 269845600}, {'script': '76a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac', 'value': 100000}]}
    > tx3 = c.sign(tx2,1,priv)
    > tx3
    {'locktime': 0, 'version': 1, 'ins': [{'outpoint': {'hash': '3be10a0aaff108766371fd4f4efeabc5b848c61d4aac60db6001464879f07508', 'index': 0}, 'amount': 180000000, 'script': '483045022100fccd16f619c5f8b8198f5a00f557f6542afaae10b2992733963c5b9c4042544c022041521e7ab2f4b58856e8554c651664af92f6abd58328c41bc652aea460a9a6a30141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}, {'outpoint': {'hash': '51ce9804e1a4fd3067416eb5052b9930fed7fdd9857067b47d935d69f41faa38', 'index': 0}, 'amount': 90000000, 'script': '483045022100a9f056be75da4167c2cae9f037e04f6efd20caf97e05052406c127d72e7f236c02206638c10ad6975b44c26633e7c40547405dd4e6184fa3afd0ec98260369fadb0d0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}], 'outs': [{'script': 'a914a9974100aeee974a20cda9a2f545704a0ab54fdc87', 'value': 269845600}, {'script': '76a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac', 'value': 100000}]}
    > tx4 = serialize(tx)
    > tx4
    '01000000020875f07948460160db60ac4a1dc648b8c5abfe4e4ffd71637608f1af0a0ae13b000000008b483045022100fccd16f619c5f8b8198f5a00f557f6542afaae10b2992733963c5b9c4042544c022041521e7ab2f4b58856e8554c651664af92f6abd58328c41bc652aea460a9a6a30141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764fffffffff38aa1ff4695d937db4677085d9fdd7fe30992b05b56e416730fda4e10498ce51000000008b483045022100a9f056be75da4167c2cae9f037e04f6efd20caf97e05052406c127d72e7f236c02206638c10ad6975b44c26633e7c40547405dd4e6184fa3afd0ec98260369fadb0d0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764fffffffff02608415100000000017a914a9974100aeee974a20cda9a2f545704a0ab54fdc87a0860100000000001976a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac00000000'
    > c.pushtx(tx4)
    {'status': 'success', 'data': {'network': 'BTCTEST', 'txid': '00af7b794355aa4ea5851a792713934b524b820cf7f20e2a0e01ab61910b5299'}}

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

    pybtctool unspent 2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF --testnet
    [{"output": "209e5caf8997a3caed4dce0399804ad7fa50c70f866bb7118a42c79de1b76efc:1", "value": 120000000, "time": "Thu Dec 21 08:33:05 2017"}, {"output": "79f38b3e730eea0e44b5a2e645f0979
    2d9f8732a823079ba4778110657cbe7b2:0", "value": 100000000, "time": "Thu Dec 21 09:31:55 2017"}, {"output": "99d88509d5f0e298bdb6883161c64c7f54444519ce28a0ef3d5942ff4ff7a924:0", "value
    ": 82211600, "time": "Thu Dec 21 09:52:00 2017"}, {"output": "80acca12cf4b3b562b583f1dc7e43fff936e432a7ed4b16ac3cd10024820d027:0", "value": 192470000, "time": "Thu Dec 21 09:52:00 20
    17"}, {"output": "3e5a3fa342c767d524b653aec51f3efe2122644c57340fbf5f79c75d1911ad35:0", "value": 10000000, "time": "Thu Dec 21 10:18:48 2017"}]

Or the --coin option to use a coin other than bitcoin (bch, btc, dash, doge or ltc)

    pybtctool unspent LV3VLesnCi3p3zf26Y86kH2FZxfQq2RjrA --coin ltc
    [{"output": "42bfe7376410696e260b2198f484f5df4aa6c744465940f9922ac9f8589670a4:0", "value": 14282660, "time": "Thu Dec 21 10:36:08 2017"}]

    pybtctool unspent myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW --coin ltc --testnet
    [{"output": "f27a53b9433eeb9d011a8c77439edb7a582a01166756e00ea1076699bfa58371:0", "value": 1993472, "time": "Wed Dec 20 14:38:07 2017"}, {"output": "2a288547460ebe410e98fe63a1900b645
    2d95ec318efb0d58a5584ac67f27d93:1", "value": 177961076, "time": "Wed Dec 20 17:01:32 2017"}, {"output": "da0e900e4ed8e3661bef6f6fa5beed78fec3f7b9e4cc87c7120108eba66f270f:0", "value":
     1971905, "time": "Wed Dec 20 17:01:32 2017"}]

Make and broadcast a transaction on the Dash testnet:

    pybtctool send cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz 44907516684 --fee 20000 --coin dash --testnet
    {"status": "success", "data": {"txid": "725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0", "network": "DASHTEST"}}

The arguments are the private key of the sender, the receiver's address and the fee (default 10000). Change will be returned to the sender. 
### Listing of main coin-specific commands:

* privkey_to_pubkey    : (privkey) -> pubkey
* privtopub            : (privkey) -> pubkey
* pubkey_to_address    : (pubkey) -> address
* pubtoaddr            : (pubkey) -> address
* privkey_to_address   : (privkey) -> address
* privtoaddr           : (privkey) -> address
* sign                 : (txobj, i, privkey) -> create digital signature of tx with privkey and add to input i
* signall              : (txobj, privkey) -> create digital signature of tx with privkey for all inputs
* history              : (address) -> tx history of an address
* unspent              : (address, etc) -> unspent outputs for an addresses
* pushtx               : (hex or bin tx) -> push a transaction to the blockchain
* fetchtx              : (txhash) -> fetch a tx from the blockchain
* txinputs             : (txhash) -> fetch inputs from a previous transaction in a format to be re-used as unspents             
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
* mktx                 : (inputs, outputs) -> txobj
* mksend               : (inputs, outputs, change_addr, fee) -> txobj
* multisign            : (txobj, i, script, privkey) -> signature
* apply_multisignatures: (txobj, i, script, sigs) -> tx with index i signed with sigs
* scriptaddr           : (script) -> P2SH address
* mk_multisig_script   : (pubkeys, k, n) -> k-of-n multisig script from pubkeys
* verify_tx_input      : (tx, i, script, sig, pub) -> True/False
* tx_hash              : (hex or bin tx) -> hash

* access               : (json list/object, prop) -> desired property of that json object
* multiaccess          : (json list, prop) -> like access, but mapped across each list element
* slice                : (json list, start, end) -> given slice of the list
* count                : (json list) -> number of elements
* sum                  : (json list) -> sum of all values
