REPOSITORY HAS BEEN ARCHIVED AND IS NO LONGER MAINTAINED FOR NOW

# Pycryptotools, Python library for Crypto coins signatures and transactions

This is a fork of Vitalik Buterin's original [pybitcointools](https://github.com/vbuterin/pybitcointools) library.

Installation:

```bash
pip install cryptos
```

Library now supports making and pushing raw transactions for:

* Bitcoin mainnet
* Bitcoin testnet 
* Bitcoin Cash mainnet (with replay protection)
* Bitcoin Cash testnet (with replay protection)
* Litecoin mainnet
* Litecoin testnet
* Dash mainnet
* Dash testnet
* Dogecoin mainnet
* Bitcoin Gold mainnet (with replay protection)

Transaction broadcast has been tested for all of these.

For the following, local operations such as making and signing transactions are supported but explorer dependant
operations (unspent, pushtx, etc.) are not yet supported.:

* Bitcoin Gold testnet

Segregrated Witness transactions also supported for:
* Bitcoin mainnet
* Bitcoin testnet
* Litecoin mainnet
* Litecoin testnet

Here are the first mainnet segwit transactions made with this library:

Bitcoin: https://blockchain.info/tx/9f3bd4fa14e424abd5623ba98877e33cfee3e7bd6f9f71d7a39e402501458c81

Litecoin: https://live.blockcypher.com/ltc/tx/b16ad0332ca3114f0dc773fda643c49e41308df4204940539bea5806cfee0989/
https://live.blockcypher.com/ltc/tx/3b936180daf05adcd7e9f04b60e1ba9a4a6db486c0ad91cb795b29ca46313000/

Aim is to provide a simple, class-based API which makes switching between different coins and mainnet and testnet, and adding new coins, all very easy.

Roadmap:
* Replaceable transactions
* Change from explorers to electrumx servers
* Correct fee detection algorithm
* Extend wallets to make transactions
* Read the docs page
* E-commerce tools (exchange rates, short-time invoices)
* Desktop GUI for easy creation, signing and broadcasting of raw transactions
* Multi-crypto wallet GUI

### Advantages:

* Methods have a simple interface, inputting and outputting in standard formats
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

### Example usage - the long way (best way to learn :) ):

WARNING: While it's fun to mess around with this on the testnet, do not do the following procedure on the mainnet 
unless you really know what you are doing. Any value in the inputs not included in the ouputs will be lost.
So if the total inputs value is 1 BTC, and the total outputs amount to 0.6 BTC, 0.4 BTC will be given to the 
miners as a fee. The faster way, listed later in the README, ensures the difference between
inputs and outputs is sent as change back to the sender (except for a small fee).
If in doubt, before broadcasting a transaction, visit https://live.blockcypher.com/btc/decodetx/ and decode the raw tx
and make sure it looks right. If you aren't familiar with how Bitcoin transactions work, you should run through
 this procedure a few times on the testnet before developing for mainnet.

OTHER WARNING: Default fees for Bitcoin mainnet are probably too low throughout this library. 
This can cause coins to be lost for a period of time until they are finally confirmed by a miner. Hopefully, some kind
of "correct fee" detection algorithm will be implemented soon but for now it is recommended to think about and set an 
appropriate fee when making transactions. There are many different ways of making a transaction. Whichever method you
choose, make sure you understand how to set the correct fee. Here's a link about for information about the current recommended fees:

https://bitcoinfees.earn.com/

    > from cryptos import *
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
    [{'output': '3be10a0aaff108766371fd4f4efeabc5b848c61d4aac60db6001464879f07508:0', 'value': 180000000}, {'output': '51ce9804e1a4fd3067416eb5052b9930fed7fdd9857067b47d935d69f41faa38:0', 'value': 90000000}]
    > outs = [{'value': 269845600, 'address': '2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF'}, {'value': 100000, 'address': 'mrvHv6ggk5gFMatuJtBKAzktTU1N3MYdu2'}]
    > tx = c.mktx(inputs,outs)
    > tx
    {'locktime': 0, 'version': 1, 'ins': [{'outpoint': {'hash': '3be10a0aaff108766371fd4f4efeabc5b848c61d4aac60db6001464879f07508', 'index': 0}, 'amount': 180000000, 'script': '483045022100fccd16f619c5f8b8198f5a00f557f6542afaae10b2992733963c5b9c4042544c022041521e7ab2f4b58856e8554c651664af92f6abd58328c41bc652aea460a9a6a30141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}, {'outpoint': {'hash': '51ce9804e1a4fd3067416eb5052b9930fed7fdd9857067b47d935d69f41faa38', 'index': 0}, 'amount': 90000000, 'script': '483045022100a9f056be75da4167c2cae9f037e04f6efd20caf97e05052406c127d72e7f236c02206638c10ad6975b44c26633e7c40547405dd4e6184fa3afd0ec98260369fadb0d0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}], 'outs': [{'script': 'a914a9974100aeee974a20cda9a2f545704a0ab54fdc87', 'value': 269845600}, {'script': '76a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac', 'value': 100000}]}
    > tx2 = c.sign(tx,0,priv)
    > tx2
    {'locktime': 0, 'version': 1, 'ins': [{'outpoint': {'hash': '3be10a0aaff108766371fd4f4efeabc5b848c61d4aac60db6001464879f07508', 'index': 0}, 'amount': 180000000, 'script': '483045022100fccd16f619c5f8b8198f5a00f557f6542afaae10b2992733963c5b9c4042544c022041521e7ab2f4b58856e8554c651664af92f6abd58328c41bc652aea460a9a6a30141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}, {'outpoint': {'hash': '51ce9804e1a4fd3067416eb5052b9930fed7fdd9857067b47d935d69f41faa38', 'index': 0}, 'amount': 90000000, 'script': '483045022100a9f056be75da4167c2cae9f037e04f6efd20caf97e05052406c127d72e7f236c02206638c10ad6975b44c26633e7c40547405dd4e6184fa3afd0ec98260369fadb0d0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}], 'outs': [{'script': 'a914a9974100aeee974a20cda9a2f545704a0ab54fdc87', 'value': 269845600}, {'script': '76a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac', 'value': 100000}]}
    > tx3 = c.sign(tx2,1,priv)
    > tx3
    {'locktime': 0, 'version': 1, 'ins': [{'outpoint': {'hash': '3be10a0aaff108766371fd4f4efeabc5b848c61d4aac60db6001464879f07508', 'index': 0}, 'amount': 180000000, 'script': '483045022100fccd16f619c5f8b8198f5a00f557f6542afaae10b2992733963c5b9c4042544c022041521e7ab2f4b58856e8554c651664af92f6abd58328c41bc652aea460a9a6a30141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}, {'outpoint': {'hash': '51ce9804e1a4fd3067416eb5052b9930fed7fdd9857067b47d935d69f41faa38', 'index': 0}, 'amount': 90000000, 'script': '483045022100a9f056be75da4167c2cae9f037e04f6efd20caf97e05052406c127d72e7f236c02206638c10ad6975b44c26633e7c40547405dd4e6184fa3afd0ec98260369fadb0d0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764f', 'sequence': 4294967295}], 'outs': [{'script': 'a914a9974100aeee974a20cda9a2f545704a0ab54fdc87', 'value': 269845600}, {'script': '76a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac', 'value': 100000}]}
    > tx4 = c.serialize(tx)
    > tx4
    '01000000020875f07948460160db60ac4a1dc648b8c5abfe4e4ffd71637608f1af0a0ae13b000000008b483045022100fccd16f619c5f8b8198f5a00f557f6542afaae10b2992733963c5b9c4042544c022041521e7ab2f4b58856e8554c651664af92f6abd58328c41bc652aea460a9a6a30141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764fffffffff38aa1ff4695d937db4677085d9fdd7fe30992b05b56e416730fda4e10498ce51000000008b483045022100a9f056be75da4167c2cae9f037e04f6efd20caf97e05052406c127d72e7f236c02206638c10ad6975b44c26633e7c40547405dd4e6184fa3afd0ec98260369fadb0d0141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764fffffffff02608415100000000017a914a9974100aeee974a20cda9a2f545704a0ab54fdc87a0860100000000001976a9147d13547544ecc1f28eda0c0766ef4eb214de104588ac00000000'
    > c.pushtx(tx4)
    {'status': 'success', 'data': {'network': 'BTCTEST', 'txid': '00af7b794355aa4ea5851a792713934b524b820cf7f20e2a0e01ab61910b5299'}}

### Faster way

To send 12 DASH from addr belonging to privkey 89d8d898b95addf569b458fbbd25620e9c9b19c9f730d5d60102abbabcb72678 
to address yd8Q7MwTDe9yJdeMx1YSSYS4wdxQ2HDqTg, with change returned to the sender address:

    > from cryptos import *
    > dash = Dash(testnet=True)
    > dash.send("89d8d898b95addf569b458fbbd25620e9c9b19c9f730d5d60102abbabcb72678", "yd8Q7MwTDe9yJdeMx1YSSYS4wdxQ2HDqTg", 1200000000)
    {'status': 'success', 'data': {'txid': '6a510a129bf1e229e99c3eede516d3bde8bdccf859199937a98eaab2ce1cd7ab', 'network': 'DASHTEST'}}

Or if you prefer to verify the tx (for example, with Blockcypher) you can break it into two steps:

    > from cryptos import *
    > dash = Dash()
    > tx = dash.preparesignedtx(priv, "Xhcmzs5wKECBiWwSEsTZu8wNonguH5poaz", 9800000-20000, fee=20000)
    > tx
    '010000000194f2f955627dfd549f213a70d65dcd5550c0b14a484d38b6ae47fe7a8896ca41000000008b483045022100b125b1f4848c145193f70b915b0074539d90fd74c2e75492169f06927acafa39022025a009711a354a7d84e19f234dfb5d20e155b64acad40941670e634c1100101a01410437b81f8f1376a87556380ad9f3a6b7f642754b3497ce42518f8dbd39bfedea24d897ae5d8d1dd41c04f55700ed6f3b7cee99df5aed74f98a54cbc576d75c0b9fffffffff01203b9500000000001976a9144c0404140e6ad8d04bdf625888bf6dfcc20fa12d88ac00000000'
    > dash.pushtx(tx)
    {'status': 'success', 'data': {'txid': '0d889f6a268340c8fd30cdc6567eb588765e911fdd1fb0aac870dc3125ffde76', 'network': 'DASH'}}

Another example with Bitcoin Cash testnet:

    > from cryptos import *
    > crypto = BitcoinCash(testnet=True)
    > tx = crypto.preparesignedtx("89d8d898b95addf569b458fbbd25620e9c9b19c9f730d5d60102abbabcb72678", "mgRoeWs2CeCEuqQmNfhJjnpX8YvtPACmCX", 967916800)
    > tx
    '010000000144ea7b41df09cee54c43f817dc11fd4d88c9b721b4c13b588f6a764eab78f692000000008b4830450221008efa819db89f714dbe0a19a7eb605d03259f4755a0f12876e9dddf477e1867b8022072bc76d120e92668f4765b5d694aee4a3cafd6cd4aaa8d5ebf88c3f821c81d9c4141041f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc724ab2737afd66e4aacdc0e4f48550cd783c1a73edb3dbd0750e1bd0cb03764fffffffff02003db139000000001976a91409fed3e08e624b23dbbacc77f7b2a39998351a6888acf046df07000000001976a914ad25bdf0fdfd21ca91a82449538dce47f8dc213d88ac00000000'
    > crypto.pushtx(tx)
    {'status': 'success', 'data': {'txid': 'd8b130183824d0001d3bc669b31e798e2654868a7fda743aaf35d757d89db0eb', 'network': 'tbcc'}}
    
### Segregated Witness - the long way
The same warnings about testnet practice and fees as discussed earlier applies here.

To create a segwit transaction, generate a pay to witness script hash (P2WPKH) 
address and mark all the Segwit UTXOs with segwit=True.

    > from cryptos import *
    > c = Litecoin(testnet=True)
    > priv = sha256('a big long brainwallet password')
    > priv
    '89d8d898b95addf569b458fbbd25620e9c9b19c9f730d5d60102abbabcb72678'
    > addr = c.privtop2w(priv)
    > addr
    '2Mtj1R5qSfGowwJkJf7CYufFVNk5BRyAYZh'
    > inputs = c.unspent(addr)
    > inputs
    [{'output': '63189d6354b1e7d3a5a16076b0722f84b80b94d5f4958c3697191503cccbe88a:0', 'value': 100000000}]
    > inputs[0]['segwit']=True
    > inputs
    [{'output': '63189d6354b1e7d3a5a16076b0722f84b80b94d5f4958c3697191503cccbe88a:0', 'value': 100000000, 'segwit': True}]
    > outs = [{'value': 79956800, 'address': 'mxYcACPJWAMMkXu7S9SM8npicFWehpYCWx'}, {'value': 19989200, 'address': '2Mtj1R5qSfGowwJkJf7CYufFVNk5BRyAYZh'}]
    > tx = c.mktx(inputs,outs)
    > tx
    {'locktime': 0, 'version': 1, 'ins': [{'script': '', 'sequence': 4294967295, 'outpoint': {'hash': '63189d6354b1e7d3a5a16076b0722f84b80b94d5f4958c3697191503cccbe88a', 'index': 0}, 'amount': 100000000, 'segwit': True}], 'outs': [{'script': '76a914baca2979689786ba311edcfc04d9ad95d393679488ac', 'value': 79956800}, {'script': 'a9141039471d8d44f3693cd34d1b9d69fd957799cf3087', 'value': 19989200}], 'marker': 0, 'flag': 1, 'witness': []}
    > tx2 = c.sign(tx,0,priv)
    > tx2
    {'locktime': 0, 'version': 1, 'ins': [{'script': '160014804aff26594cc36c0ac89e95895ab9bdd0c540ef', 'sequence': 4294967295, 'outpoint': {'hash': '63189d6354b1e7d3a5a16076b0722f84b80b94d5f4958c3697191503cccbe88a', 'index': 0}, 'amount': 100000000, 'segwit': True}], 'outs': [{'script': '76a914baca2979689786ba311edcfc04d9ad95d393679488ac', 'value': 79956800}, {'script': 'a9141039471d8d44f3693cd34d1b9d69fd957799cf3087', 'value': 19989200}], 'marker': 0, 'flag': 1, 'witness': [{'number': 2, 'scriptCode': '47304402201632cb84a0aed4934df83fbc3cd2682f920eef37f76aa64d477702dd59633c900220198cfe15c28b26247c8e49974b4fda825ae16441112f13e754322964a9f24ec80121031f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc'}]}
    > tx3 = serialize(tx)
    > tx3
    '010000000001018ae8cbcc03151997368c95f4d5940bb8842f72b07660a1a5d3e7b154639d18630000000017160014804aff26594cc36c0ac89e95895ab9bdd0c540efffffffff02400bc404000000001976a914baca2979689786ba311edcfc04d9ad95d393679488acd00231010000000017a9141039471d8d44f3693cd34d1b9d69fd957799cf30870247304402201632cb84a0aed4934df83fbc3cd2682f920eef37f76aa64d477702dd59633c900220198cfe15c28b26247c8e49974b4fda825ae16441112f13e754322964a9f24ec80121031f763d81010db8ba3026fef4ac3dc1ad7ccc2543148041c61a29e883ee4499dc00000000'
    > c.pushtx(tx3)
    {'status': 'success', 'data': {'network': 'LTCTEST', 'txid': '51d5be05d0a35ef5a8ff5f43855ea59e8361874aff1039d6cf5d9a1f93ae1042'}}


It's also possible to mix segwit inputs with non-segwit inputs. Only one input needs to be marked as segwit 
to create a segwit transaction.

### Segregated Witness - Faster Way:

Send 0.23486583 LTC to LPZd11JyAd6fJh5ZBMcmu6qczV14CZnz55 from segwit address 3P1bEPk5v4CUhvX9VqDuxqJGnTutt9czZb, 
returning change to LchaMS51XFYmks3fJLAyuSeYSbiyByPLUD:
 
    >from cryptos import *
    >l = Litecoin()
    l.send("<privkey>", "LNM9Hpc6EFd7SsKkPU6ATLJNdXSNPnNdqs", 23486583, fee=20000, change_addr="LchaMS51XFYmks3fJLAyuSeYSbiyByPLUD", segwit=True)
    {'status': 'success', 'data': {'network': 'LTC', 'txid': '3b936180daf05adcd7e9f04b60e1ba9a4a6db486c0ad91cb795b29ca46313000'}}

It's also possible to provide the send address in addition to the private key in which case segwit will be 
auto-detected, so no need to know in advance if the address is segwit or not:
    
    >from cryptos import *
    >c = Bitcoin()
    >c.send('<privkey>', '1CBFPfNotcVcWg26WdhfnoDDvZqzuBxKDb', 88036480, addr="3AGe5CkW5CKFAgKpQE82VSWkEjoxfDxMxQ")
    {'status': 'success', 'data': {'network': 'LTC', 'txid': 'b16ad0332ca3114f0dc773fda643c49e41308df4204940539bea5806cfee0989'}}

It's also possible to provide the send address in addition to the private key in which case segwit will be 
auto-detected, so no need to know in advance if the address is segwit or not:
    
    >from cryptos import *
    >c = Bitcoin()
    >c.send('<privkey>', '1CBFPfNotcVcWg26WdhfnoDDvZqzuBxKDb', 88036480, addr="3AGe5CkW5CKFAgKpQE82VSWkEjoxfDxMxQ")
    {'status': 'success', 'data': {'network': 'LTC', 'txid': 'b16ad0332ca3114f0dc773fda643c49e41308df4204940539bea5806cfee0989'}}
    
### 2-of-3 MultiSig Transaction example:
    > from cryptos import *
    > coin = Bitcoin(testnet=True)
    > publickeys = ['02e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609', '0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0', '0415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41eb']
    > script, address = coin.mk_multsig_address(publickeys, 2)
    > script
    '522102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41eb53ae'
    > address
    '2ND6ptW19yaFEmBa5LtEDzjKc2rSsYyUvqA'
    > tx = coin.preparetx(address, "myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", 1100000, 50000)
    > for i in range(0, len(tx['ins'])):
        sig1 = coin.multisign(tx, i, script, "cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk")
        sig3 = coin.multisign(tx, i, script, "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f")
        tx = apply_multisignatures(tx, i, script, sig1, sig3)
    > tx
    '0100000001e62c0b5434108607f52856bfbcf5093363fbd4789141a661a4c6c8042769ed2001000000fd1d0100483045022100dfc75916f6bb5c5b72a45dea44dbc45b47ba90912efb84680a373acadb3b1212022022dbbd66e4871624609d875bdb592d11335eb4ec49c7b87bb0b8bc76f72f80f30147304402204c38cab196ec0e82a9f65ecba70a0dbf73f49e5886e1000b9bc52894e28fa5c9022007bff3f90bcece19036625806d4d1951a03c256627163f1ac4e76a6ee8eae072014c89522102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41eb53aeffffffff02e0c81000000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac301224030000000017a914d9cbe7c2c507c306f4872cf965cbb4fe51b621998700000000'
    > coin.pushtx(tx)
    {'status': 'success', 'data': {'txid': 'b64e19311e3aa197063e03657679e2974e04c02c5b651c4e8d55f428490ab75f', 'network': 'BTCTEST'}}


### Supported coins

    > from cryptos import *
    > priv = sha256('a big long brainwallet password')
    > b = Bitcoin()
    > b.privtoaddr(priv)
    '1GnX7YYimkWPzkPoHYqbJ4waxG6MN2cdSg'
    > b = Bitcoin(testnet=True)
    > b.privtoaddr(priv)
    'mwJUQbdhamwemrsR17oy7z9upFh4JtNxm1'
    > l = Litecoin()
    > l.privtoaddr(priv)
    'Lb1UNkrYrQkTFZ5xTgpta61MAUTdUq7iJ1'
    > l = Litecoin(testnet=True)
    > l.privtoaddr(priv)
    'mwJUQbdhamwemrsR17oy7z9upFh4JtNxm1'
    > c = BitcoinCash()
    > c.privtoaddr(priv)
    '1GnX7YYimkWPzkPoHYqbJ4waxG6MN2cdSg'
    > c = BitcoinCash(testnet=True)
    > c.privtoaddr(priv)
    'mwJUQbdhamwemrsR17oy7z9upFh4JtNxm1'
    > d = Dash()
    > d.privtoaddr(priv)
    'XrUMwoCcjTiz9gzP9S9p9bdNnbg3MvAB1F'
    > d = Dash(testnet=True)
    > d.privtoaddr(priv)
    'yc6xxkH4B1P4VRuviHUDBd3j4tAQpy4fzn'
    > d = Doge()
    > d.privtoaddr(priv)
    'DLvceoVN5AQgXkaQ28q9qq7BqPpefFRp4E'
    > bg = BitcinGold()
    > bg.privtoaddr(priv)
    'GZdSXfsfkc7h5Dh6DVVhiqHUsRtCMQ9fxG'
    > bg = BitcoinGold(legacy=True)
    > bg.privtoaddr(priv)
    '1GnX7YYimkWPzkPoHYqbJ4waxG6MN2cdSg'
    > bg = BitcoinGold(testnet=True)
    > bg.privtoaddr(priv)
    'mwJUQbdhamwemrsR17oy7z9upFh4JtNxm1'
    

### BIP39-BIP44 Standard Wallets:

Aims to be compatible with https://iancoleman.io/bip39/. Good choice for supporting different coins and networks from 
the same wallet words. Also compatible with electrum when bip39 option is selected.
    
    > from cryptos import *
    > words = entropy_to_words(os.urandom(16))
    > words
    'practice display use aisle armor salon glue okay sphere rather belt mansion'  
    > keystore.bip39_is_checksum_valid(words)
    (True, True)
    > coin = Bitcoin()
    > wallet = coin.wallet(words)
    > wallet.keystore.root_derivation
    "m/44'/0'/0'"
    > wallet.keystore.xprv      #Account Extended Private Key
    'xprv9y1M42LhHxTuoQbCuySz4Ek6EB3guE4CiXDXhHQnR7LwgpUV7AxQVm7D4HpUWRStwUXFepQRz7av2iaAXXYoizT9JoqWE6qffxNdiMxFQtc'
    > wallet.keystore.xpub      # Account Extended Public Key
    'xpub6BzhTXsb8L2D1tfg1zyzRNgpnCtBJgn45k98VfpPySsvZcodeiGf3ZRguZLoS6VwEQ4iZ7Y4bq5A5eqyooyc4jC9beFTB3mmxrGwjRLa3pm'
    > addr1 = wallet.new_receiving_address()
    > addr1
    '18q3EiCiKd5vydnaVwWEpAFyzfL2ftAZ1L'
    > wallet.privkey(addr1)
    'L4cKz3epcM3CAmwkSwJwZ2c4q5ukmSVWCrE9PqE46ybU3XyzfTYx'
    > addr2 = wallet.new_change_address()
    > addr2
    '1BgkpwEDrTbCNduyR97EpW4zvFhEzWsyvi'
    > wallet.privkey(addr2)
    'L5Xmbnsen2cN36WxbuHkAixBmuJ8b3GZPmLtaRPf66p4gfnqHDqi'
    > addr3 = wallet.new_change_address()
    > addr3
    '1KjxFsDP9SXAmKKD4ZgSep5kYaYgAGK3P9'
    > priv3 = wallet.privkey(addr3)
    > priv3
    'L1ktR1kifTXLXoroLZiB3AF9UtKLRW2FmYnnR7VbPZBYkscgRkyn'
    > assert coin.privtoaddr(priv3) == addr3
    True
    
Dash example:

    > from cryptos import *
    > words = 'practice display use aisle armor salon glue okay sphere rather belt mansion'  
    > coin = Dash()
    > wallet = coin.wallet(words)
    > wallet.keystore.root_derivation
    "m/44'/5'/0'"
    > wallet.keystore.xprv      #Account Extended Private Key
    'xprv9yiTHjM4MPNQndsxkrvE2QgF36nvutGt3e9k5DjkjfAnNbqGm1wL77XV2xHiwnUfwcgAZUWkdpEnxRWELTrgXDVhvntNFwme1CqCgm1a91f'
    > wallet.keystore.xpub      # Account Extended Public Key
    'xpub6ChohEsxBkvi17xRrtTEPYcyb8dRKLzjQs5Lsc9NHzhmFQARJZFaeuqxtEMHaF4J8MzatWSYrmq2qAc3BaxFiKzEwX1AKQx5uWHZr3y8s82'
    > addr1 = wallet.new_receiving_address()
    > addr1
    'Xea1GEenz6Toq5YQjvjz86MTT8ezT5ZwnY'
    > wallet.privkey(addr1)
    'XDbSZeVzBiHanwrSU5yripFd8Lq5tnrjxgvbaksNPhAExbS29aAa'
    > addr2 = wallet.new_change_address()
    > addr2
    'XwYCR4CwafwoGe6P4H9LndaqAQkmE6xYix'
    > wallet.privkey(addr2)
    'XHwHKxVfhzPEGZGGfQ9uwKK2xQjavF2yNUkq7FGXFA6SyZv4jge1'
    > addr3 = wallet.new_change_address()
    > addr3
    'XfZwJaFiBx4qLqnQydvqGyWDPciAtjFmgn'
    > priv3 = wallet.privkey(addr3)
    > priv3
    'XCNac8eQE642wWKaxnWHLa1GW1Y1uppvT5uda3LYVXAJZAAdR1Fx'
    > assert coin.privtoaddr(priv3) == addr3
    True
    
### BIP39-BIP49 Segwit Wallets:

    > from cryptos import *
    > words = entropy_to_words(os.urandom(20))
    > words
    'jealous silver churn hedgehog border physical market parent hungry design cage lab drill clay attack' 
    > keystore.bip39_is_checksum_valid(words)
    (True, True)
    > coin = Bitcoin()
    > wallet = coin.p2wpkh_p2sh_wallet(words)
    > wallet.keystore.root_derivation
    "m/49'/0'/0'"
    > wallet.keystore.xprv      #Account Extended Private Key
    'yprvAHoU8z6164hTNdwpArPgn2bdNExmUu9HwxeyhUok8pLDNQSCzYo8rvD6tFvMKk4EQXF2UGzRea5FBHjrtcuYmuBB7Z6EoznKCPeUwXaZduB'
    > wallet.keystore.xpub      # Account Extended Public Key
    'ypub6WnpYVctvSFkb82HGsvh9AYMvGoFtMs9KBaaVsDMh9sCFCmMY67PQiXajW1FQq7AKsgvWGSrmZ82rquUpwcKR6Ey1sdMdeQWvgCKvABjWy8'
    > addr1 = wallet.new_receiving_address()
    > addr1
    '38yA1L6u6NiADrafrqZKDt1fTRHpGC3E7g'
    > wallet.privkey(addr1)
    'Ky13njnYGrj5jowjUarqcmaRCG37zSwqRJkTj296cQsSvFtsV5a5'
    > addr2 = wallet.new_change_address()
    > addr2
    '3B5f8vVBRTAh2krbd4PiCtpyn7LhFJBDdV'
    > wallet.privkey(addr2)
    'KzCNhiuvwQ1T6hXL21Act86HacauJGe1c8ttECqx1Fai6tPc1bEG'
    > addr3 = wallet.new_change_address()
    > addr3
    '3NvrTctHm6dQc6G2p3XYciWH8H6Lfcz9Jc'
    > wallet.privkey(addr3)
    'KwdZhDopz3UVNW3Qso5UiyGkiDmayRZmAZdfAojvGsoP7da7HueX'
    
### BIP39-BIP84 New Segwit Wallets:

    > from cryptos import *
    > words = 'jealous silver churn hedgehog border physical market parent hungry design cage lab drill clay attack'
    > coin = Bitcoin()
    > wallet = coin.p2wpkh_wallet(words)
    > wallet.keystore.root_derivation
    "m/84'/0'/0'
    > wallet.keystore.xprv      #Account Extended Private Key
    'zprvAcSKXVdgJHh5vyEeC6HSVScUCHxrKEWkkFSE2YsLpTborr4y2rHMrmr66yvxkGVqiiwwUCqUVkPB7o5ThnK3Dybi5PEywikXbNKQcHNMYPd'
    > wallet.keystore.xpub      # Account Extended Public Key
    'zpub6qRfw1Aa8fFP9TK7J7pSraZCkKoLihEc7UMppwGxNo8njeQ7aPbcQaAZxFtnjCj9XveSJEnwV88YPyXXUCr3yRSSAKzibVCQB7AudUQn6Qg'
    > addr1 = wallet.new_receiving_address()
    > addr1
    'bc1qkh6wwkyhfceuxq236pc9gtv2agfqnelzh5m94f'
    > wallet.privkey(addr1)
    'Kwnaq7cvD4CAnTcppou6wpUpMFx5yZRqkpZcy6bBvPVKp2FQzJNf'
    > addr2 = wallet.new_change_address()
    > addr2
    'bc1qj3vc5ft8nuka447z7ecujksszq6cm2r8p750n9'
    > wallet.privkey(addr2)
    'L1QjmcLmeR5tbH62WxKoSdZBBHn69PuQSnLo2LaimnztsDANMP5M'
    > addr3 = wallet.new_change_address()
    > addr3
    'bc1qft00enx8c6unn00pmfdgq36ftd0u0q4lk5ajpy'
    > wallet.privkey(addr3)
    'Kx91EteCnRmUPr8eibiEsAcFDyKJ2z9uAwGUQfMVw5ABQx7QyVgg'

### Electrum wallets
These aim to be compatible with the default Electrum wallet seed style. They do not have different derivation paths for different coins. 
No checks have been made against any non-Bitcoin Electum wallet (e.g. Electrum Litecoin, Electron Cash)
At this moment, there is no support generating the seed words Electrum requires (which contains versioning) so seed words need to be copied from Electrum.
Electrum versioning allows for auto-detection of wallet type, .e.g standard or segwit.

    > from cryptos import *
    > seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
    > wallet = Bitcoin().electrum_wallet(seed_words)
    > wallet.keystore.xtype
    'p2wpkh'
    > wallet.keystore.root_derivation
    "m/0'/"
    > wallet.keystore.xprv
    'zprvAZswDvNeJeha8qZ8g7efN3FXYVJLaEUsE9TW6qXDEbVe74AZ75c2sZFZXPNFzxnhChDQ89oC8C5AjWwHmH1HeRKE1c4kKBQAmjUDdKDUZw2'
    > wallet.keystore.xpub
    'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ'
    > addr1 = wallet.new_receiving_address()
    > addr1
    'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af'
    > wallet.privkey(addr1)
    'L9fSXYNxYWHJWUqrQ6yhZCAJXq6XsfvcJ1Y2EnMAZfLLRNVQswQj'
    > addr2 = wallet.new_change_address()
    > addr2
    'bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p'
    > wallet.privkey(addr2)
    'L8rPGyfyzdLLEzxuBeC87Jvpp8FKxwrRtmkZ2PkRmRjqxNF8TVwG'
    > addr3 = wallet.new_change_address()
    > addr3
    'bc1q6xwxcw6m9ga35687tnu5tstmsvmzjwdnzktemv'
    > wallet.privkey(addr3)
    'L7NeR6r9yU2n4zddxTCUpKYmzugYuouyLsCZR9naTqkBW6sjpxDM'

### Watch wallets

For security reasons the seed and xprv should ideally be held in cold storage only. If a web application needs to be 
able to provide addresses on demand, the solution is to use a watch wallet, generated from the xpub.

For example, let's take the Dash xpub from a previous example:

    > from cryptos import *
    > coin = Dash()
    > xpub = 'xpub6ChohEsxBkvi17xRrtTEPYcyb8dRKLzjQs5Lsc9NHzhmFQARJZFaeuqxtEMHaF4J8MzatWSYrmq2qAc3BaxFiKzEwX1AKQx5uWHZr3y8s82'
    > wallet = coin.watch_wallet(xpub)
    > wallet.is_watching_only
    True
    > wallet.new_receiving_address()
    'Xea1GEenz6Toq5YQjvjz86MTT8ezT5ZwnY'
    > wallet.new_change_address()
    'XwYCR4CwafwoGe6P4H9LndaqAQkmE6xYix'

Full list of wallet methods:

* wallet -> BIP 39 Standard
* watch_wallet -> BIP 39 Standard, watch-only
* p2wpkh_p2sh_wallet -> BIP 39 Segwit P2SH addresses, beginning with 3 for Bitcoin mainnet
* watch_p2wpkh_p2sh_wallet -> BIP 39 Segwit P2SH addresses, watch-only
* p2wpkh_wallet -> BIP 39 New Segwit Addresses, beginning with 'bc' for Bitcoin mainnet
* watch_p2wpkh_wallet -> BIP New Segwit Address, watch-only
* electrum_wallet -> detects p2kh or p2wpkh based on seed
* watch_electrum_wallet -> Watch electrum standard wallet
* watch_electrum_p2wpkh_wallet -> Watch electrum new segwit wallet

### Old style Electrum words wallet:
    > import os
    > from cryptos import *
    > words = entropy_to_words(os.urandom(16))
    > words
    'float skirt road remind fire antique vendor select senior latin small glide'
    > seed = mnemonic_to_seed(words)
    > seed
    b'\xb7Z\x9b\x9b\x9c\x1bq\x81\x1b\xdc\x98\x1c\xbc\xb8\xbb\x130\xea,\xda\x14\xeb\x9bF\xafu\x88\xc2\xf9\xfc\x7f\xd0\xb0?\x9d\xf3\xa7$0Tx\xd3\xb7\x82\x87U\xe7\xcc\xdd\x16\xddd\xbf'T\t_\xdc R!x\t'
    > electrum_privkey(seed, 0)
    '5a37812b3057e44636c6e07023e16a8669e12a4365dfabbcb376ed272081d522'
    > electrum_privkey(seed, 300, 0)
    '04cf414f200cd090239f2116d90608a74eae34ae21103ca9eef7bd9579e48bed'
    > electrum_privkey(seed, 0, 1)      #Change address
    '9ca3631f813a6f81b70fbfc4384122bfe6fb159e6f7aea2811fe968c2a39d42a'

### The cryptotool command line interface:

    cryptotool bip32_master_key 21456t243rhgtucyadh3wgyrcubw3grydfbng
    xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT

    cryptotool bip32_ckd xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT 0
    xprv9vfzYrpwo7QHFdtrcvsSCTrBESFPUf1g7NRvayy1QkEfUekpDKLfqvHjgypF5w3nAvnwPjtQUNkyywWNkLbiUS95khfHCzJXFkLEdwRepbw 

    cryptotool bip32_privtopub xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT
    xpub661MyMwAqRbcFGfHrgLHpC5R4odnyasAZdefbDkHBcWarJcXh6SzTzbUkWuhnP142ZFdKdAJSuTSaiGDYjvm7bCLmA8DZqksYjJbYmcgrYF

The -s option lets you read arguments from the command line

    cryptotool sha256 'some big long brainwallet password' | pybtctool -s privtoaddr | pybtctool -s history
    [{'output': u'97f7c7d8ac85e40c255f8a763b6cd9a68f3a94d2e93e8bfa08f977b92e55465e:0', 'value': 50000, 'address': u'1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'}, {'output': u'4cc806bb04f730c445c60b3e0f4f44b54769a1c196ca37d8d4002135e4abd171:1', 'value': 50000, 'address': u'1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'}]
    cryptotool random_electrum_seed | pybtctool -s electrum_privkey 0 0
    593240c2205e7b7b5d7c13393b7c9553497854b75c7470b76aeca50cd4a894d7

The -b option lets you read binary data as an argument

    cryptotool sha256 123 | pybtctool -s changebase 16 256 | pybtctool -b changebase 256 16
    a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae30a

The -j option lets you read json from the command line (-J to split a json list into multiple arguments)

    cryptotool unspent 1FxkfJQLJTXpW6QmxGT6oF43ZH959ns8Cq | pybtctool -j select 200000001 | pybtctool -j mksend 1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P:20000 1FxkfJQLJTXpW6QmxGT6oF43ZH959ns8Cq 1000 | pybtctool -s signall 805cd74ca322633372b9bfb857f3be41db0b8de43a3c44353b238c0acff9d523
    0100000003d5001aae8358ae98cb02c1b6f9859dc1ac3dbc1e9cc88632afeb7b7e3c510a49000000008b4830450221009e03bb6122437767e2ca785535824f4ed13d2ebbb9fa4f9becc6d6f4e1e217dc022064577353c08d8d974250143d920d3b963b463e43bbb90f3371060645c49266b90141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff1529d655dff6a0f6c9815ee835312fb3ca4df622fde21b6b9097666e9284087d010000008a473044022035dd67d18b575ebd339d05ca6ffa1d27d7549bd993aeaf430985795459fc139402201aaa162cc50181cee493870c9479b1148243a33923cb77be44a73ca554a4e5d60141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff23d5f9cf0a8c233b35443c3ae48d0bdb41bef357b8bfb972336322a34cd75c80010000008b483045022014daa5c5bbe9b3e5f2539a5cd8e22ce55bc84788f946c5b3643ecac85b4591a9022100a4062074a1df3fa0aea5ef67368d0b1f0eaac520bee6e417c682d83cd04330450141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff02204e0000000000001976a914946cb2e08075bcbaf157e47bcb67eb2b2339d24288ac5b3c4411000000001976a914a41d15ae657ad3bfd0846771a34d7584c37d54a288ac00000000

Fun stuff with json:

    cryptotool unspent 1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P | pybtctool -j multiaccess value | pybtctool -j sum
    625216206372

    cryptotool unspent 1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P | pybtctool -j count
    6198

To use the testnet you can add --testnet:

    cryptotool unspent 2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF --testnet
    [{"output": "209e5caf8997a3caed4dce0399804ad7fa50c70f866bb7118a42c79de1b76efc:1", "value": 120000000}, {"output": "79f38b3e730eea0e44b5a2e645f0979
    2d9f8732a823079ba4778110657cbe7b2:0", "value": 100000000}, {"output": "99d88509d5f0e298bdb6883161c64c7f54444519ce28a0ef3d5942ff4ff7a924:0", "value
    ": 82211600}, {"output": "80acca12cf4b3b562b583f1dc7e43fff936e432a7ed4b16ac3cd10024820d027:0", "value": 192470000}, {"output": "3e5a3fa342c767d524b653aec51f3efe2122644c57340fbf5f79c75d1911ad35:0", "value": 10000000}]

Or the --coin option to use a coin other than bitcoin (bch, btc, dash, doge or ltc)

    cryptotool unspent LV3VLesnCi3p3zf26Y86kH2FZxfQq2RjrA --coin ltc
    [{"output": "42bfe7376410696e260b2198f484f5df4aa6c744465940f9922ac9f8589670a4:0", "value": 14282660}]

    cryptotool unspent myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW --coin ltc --testnet
    [{"output": "68f9c662503715a3baf29fe4b07c056b0bf6654dbdd9d5393f4d6a18225d0ff3:0", "value": 16333531}, {"output": "aa40041a1fcdb952d6a38594a27529f890d17d715fd54b6914cd6709fa94ca67:0", "value": 100000000}, {"output": "3b72bae956d27ab0ad309808ab76beaf203109f423e533fd7c40f1201672f598:1", "value": 164712303}]

Make and broadcast a transaction on the Bitcoin Cash testnet:

    cryptotool send 89d8d898b95addf569b458fbbd25620e9c9b19c9f730d5d60102abbabcb72678 mgRoeWs2CeCEuqQmNfhJjnpX8YvtPACmCX 999950000 --fee 50000 --coin bch --testnet
    {"status": "success", "data": {"txid": "caae4c059ac07827047237560ff44f97c940600f8f0a1e3392f4bcaf91e38c5c", "network": "tbcc"}}

The arguments are the private key of the sender, the receiver's address and the fee (default 10000). Change will be returned to the sender. 

### Listing of main coin-specific methods:

* privtopub            : (privkey) -> pubkey
* pubtoaddr            : (pubkey) -> address
* privtoaddr           : (privkey) -> address
* sign                 : (txobj, i, privkey) -> create digital signature of tx with privkey and add to input i
* signall              : (txobj, privkey) -> create digital signature of tx with privkey for all inputs
* history              : (address) -> tx history and balance of an address
* unspent              : (address) -> unspent outputs for an addresses
* pushtx               : (hex or bin tx) -> push a transaction to the blockchain
* fetchtx              : (txhash) -> fetch a tx from the blockchain
* txinputs             : (txhash) -> fetch inputs from a previous transaction in a format to be re-used as unspents             
* send                 : (privkey, to, value, fee=10000, change_addr=None, segwit=False, addr=None) -> create and a push a simple transaction to send coins to an address and return change to the change address or sender
* sendmultitx          : (privkey, to:value pairs, fee=10000, change_addr=None, segwit=False, addr=None) -> create and a push a transaction to send coins to multiple addresses and return change to the change address or sender
* preparetx            : (frm, to, value, fee, change_addr=None, segwit=False): -> create unsigned txobj with change output
* preparemultitx       : (frm, to:value pairs, fee, change_addr=None, segwit=False): -> create unsigned txobj with multiple outputs and additional change output
* preparesignedtx      : (privkey, to, value, fee=10000, change_addr=None, segwit=False, addr=None) -> create signed txobj with change output
* preparesignedmultitx : (privkey, *args, change_addr=None, segwit=False, addr=None) -> create signed txobj with multiple outputs and additional change output
* mktx                 : (inputs, outputs) -> create unsigned txobj
* mksend               : (inputs, outputs, change_addr, fee, segwit) -> create unsigned txobj
* mk_multisig_address  : (pubkeys, M) -> Returns both M-of-N multsig script and address pubkeys
* pubtop2w             : (pub) -> pay to witness script hash (segwit address)
* privtop2w            : (priv) -> pay to witness script hash (segwit address)
* is_address           : (addr) -> true if addr is a valid address for this network
* is_p2sh              : (addr) -> true if addr is a pay to script hash for this network
* is_segwit            : (priv, addr) -> true if priv-addr pair represent a pay to witness script hash
* current_block_height : () -> Latest block height
* block_height         : (txhash) -> Block height containing the txhash
* inspect              : (tx_hex) -> Deserialize a transaction and decode and ins and outs
* merkle_prove         : (txhash) -> Proves a transaction is valid and returns txhash, merkle siblings and block header.

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
* multisign            : (txobj, i, script, privkey) -> signature
* apply_multisignatures: (txobj, i, script, sigs) -> tx with index i signed with sigs
* scriptaddr           : (script) -> P2SH address
* mk_multisig_script   : (pubkeys, M) -> M-of-N multisig script from pubkeys
* verify_tx_input      : (tx, i, script, sig, pub) -> True/False
* tx_hash              : (hex or bin tx) -> hash

* access               : (json list/object, prop) -> desired property of that json object
* multiaccess          : (json list, prop) -> like access, but mapped across each list element
* slice                : (json list, start, end) -> given slice of the list
* count                : (json list) -> number of elements
* sum                  : (json list) -> sum of all values

* select               : (unspent, value) -> returns list of unspents which are enough to cover the value

### Another reminder and useful links
Another reminder, if you are doing something new with the library, whether a regular transaction, multisig,
segwit or a coin you haven't worked with before, try it out in testnet first or alternatively with small amounts
on the mainnet. The original pybitcointools had issues opened in Github where people lost money either due to 
not understanding what they were doing or because of bugs. 

Here are some links to testnet faucets:

https://testnet.manu.backend.hamburg/faucet

https://testnet.manu.backend.hamburg/bitcoin-cash-faucet

http://test.faucet.masternode.io/

https://faucet.thonguyen.net/ltc

http://testnet.litecointools.com/

Anyone know a working Dogecoin testnet faucet, or willing to send testnet coins to address 
nmfnMVSjfyfiv37HtbphRbLgMPUHQE7QdP so I can test? (Dogecoin mainnet is tested).
