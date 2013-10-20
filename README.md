# Pybitcointools, Python library for Bitcoin signatures and transactions

### Advantages:

* Functions have a simple interface, inputting and outputting in standard formats
* No classes
* Many functions can be taken out and used individually
* Supports binary, hex and base58
* Transaction deserialization format almost compatible with BitcoinJS
* Electrum and BIP0032 support

### Disadvantages:

* Not a full node, has no idea what blocks are
* Relies on centralized service (blockchain.info) for blockchain operations

### Example usage (best way to learn :) ):

    > from pybitcointools import *
    > priv = sha256('some big long brainwallet password')
    > priv
    '57c617d9b4e1f7af6ec97ca2ff57e94a28279a7eedd4d12a99fa11170e94f5a4'
    > pub = privtopub(priv)
    > pub
    '0420f34c2786b4bae593e22596631b025f3ff46e200fc1d4b52ef49bbdc2ed00b26c584b7e32523fb01be2294a1f8a5eb0cf71a203cc034ced46ea92a8df16c6e9'
    > addr = pubtoaddr(pub)
    > addr
    '1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'
    > h = history(addr)
    > h
    [{'output': u'97f7c7d8ac85e40c255f8a763b6cd9a68f3a94d2e93e8bfa08f977b92e55465e:0', 'value': 50000, 'address': u'1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'}, {'output': u'4cc806bb04f730c445c60b3e0f4f44b54769a1c196ca37d8d4002135e4abd171:1', 'value': 50000, 'address': u'1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'}]
    > outs = [{'value': 90000, 'address': '16iw1MQ1sy1DtRPYw3ao1bCamoyBJtRB4t'}]
    > tx = mktx(h,outs)
    > tx
    '01000000025e46552eb977f908fa8b3ee9d2943a8fa6d96c3b768a5f250ce485acd8c7f7970000000000ffffffff71d1abe4352100d4d837ca96c1a16947b5444f0f3e0bc645c430f704bb06c84c0100000000ffffffff01905f0100000000001976a9143ec6c3ed8dfc3ceabcc1cbdb0c5aef4e2d02873c88ac00000000'
    > tx2 = sign(tx,0,priv)
    > tx2
    '01000000025e46552eb977f908fa8b3ee9d2943a8fa6d96c3b768a5f250ce485acd8c7f797000000008b483045022100fc9ec3f6c66f630604e76309092ae00b48d39a83f8683bbf9d6310084e70eabd022058333d7a1d2158529ce39f9b48dea23dedefbe85028cdceab34e1ee9b1518c3201410420f34c2786b4bae593e22596631b025f3ff46e200fc1d4b52ef49bbdc2ed00b26c584b7e32523fb01be2294a1f8a5eb0cf71a203cc034ced46ea92a8df16c6e9ffffffff71d1abe4352100d4d837ca96c1a16947b5444f0f3e0bc645c430f704bb06c84c0100000000ffffffff01905f0100000000001976a9143ec6c3ed8dfc3ceabcc1cbdb0c5aef4e2d02873c88ac00000000'
    > tx3 = sign(tx2,1,priv)
    > tx3
    '01000000025e46552eb977f908fa8b3ee9d2943a8fa6d96c3b768a5f250ce485acd8c7f797000000008b483045022100fc9ec3f6c66f630604e76309092ae00b48d39a83f8683bbf9d6310084e70eabd022058333d7a1d2158529ce39f9b48dea23dedefbe85028cdceab34e1ee9b1518c3201410420f34c2786b4bae593e22596631b025f3ff46e200fc1d4b52ef49bbdc2ed00b26c584b7e32523fb01be2294a1f8a5eb0cf71a203cc034ced46ea92a8df16c6e9ffffffff71d1abe4352100d4d837ca96c1a16947b5444f0f3e0bc645c430f704bb06c84c010000008c493046022100da7fa563ce34af5a4c8167a2978cb5517ded494e52a29ea4103ff2c67bce77c102210094a18bda1109591a82d5cf5e4446b12b3c399401c0f668755ac7f614eb3baa7701410420f34c2786b4bae593e22596631b025f3ff46e200fc1d4b52ef49bbdc2ed00b26c584b7e32523fb01be2294a1f8a5eb0cf71a203cc034ced46ea92a8df16c6e9ffffffff01905f0100000000001976a9143ec6c3ed8dfc3ceabcc1cbdb0c5aef4e2d02873c88ac00000000'
    > pushtx(tx3)
    'Transaction Submitted'

Or using the pybtctool command line interface:

    @vub: pybtctool random_electrum_seed
    484ccb566edb66c65dd0fd2e4d90ef65

    @vub: pybtctool electrum_privkey 484ccb566edb66c65dd0fd2e4d90ef65 0 0
    593240c2205e7b7b5d7c13393b7c9553497854b75c7470b76aeca50cd4a894d7

    @vub: pybtctool electrum_mpk 484ccb566edb66c65dd0fd2e4d90ef65
    484e42865b8e9a6ea8262fd1cde666b557393258ed598d842e563ad9e5e6c70a97e387eefdef123c1b8b4eb21fe210c6216ad7cc1e4186fbbba70f0e2c062c25

    @vub: pybtctool bip32_master_key 21456t243rhgtucyadh3wgyrcubw3grydfbng
    xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT

    @vub: pybtctool bip32_ckd xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT 0
    xprv9vfzYrpwo7QHFdtrcvsSCTrBESFPUf1g7NRvayy1QkEfUekpDKLfqvHjgypF5w3nAvnwPjtQUNkyywWNkLbiUS95khfHCzJXFkLEdwRepbw 

    @vub: pybtctool bip32_privtopub xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT
    xpub661MyMwAqRbcFGfHrgLHpC5R4odnyasAZdefbDkHBcWarJcXh6SzTzbUkWuhnP142ZFdKdAJSuTSaiGDYjvm7bCLmA8DZqksYjJbYmcgrYF

### Listing of main commands:

* privkey_to_pubkey    : (privkey) -> pubkey
* privtopub            : (privkey) -> pubkey
* pubkey_to_address    : (pubkey) -> address
* pubtoaddr            : (pubkey) -> address
* privkey_to_address   : (privkey) -> address
* privtoaddr           : (privkey) -> address

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
* sign                 : (tx, i, privkey) -> tx with index i signed with privkey
* multisign            : (tx, i, script, privkey) -> signature
* apply_multisignatures: (tx, i, script, sigs) -> tx with index i signed with sigs
* scriptaddr           : (script) -> P2SH address
* mk_multisig_script   : (pubkeys, k, n) -> k-of-n multisig script from pubkeys
* verify_tx_input      : (tx, i, script, sig, pub) -> True/False
* tx_hash              : (hex or bin tx) -> hash

* history              : (address1, address2, etc) -> outputs to those addresses
* pushtx               : (hex or bin tx) -> tries to push to blockchain.info/pushtx
