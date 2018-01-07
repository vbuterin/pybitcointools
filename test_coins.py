from unittest import skip
import unittest
import blockcypher
from operator import itemgetter
from cryptos import *
from cryptos import coins
from cryptos import explorers

class BaseCoinCase(unittest.TestCase):
    name = ""
    unspent_address = ""
    unspent_address_multiple = []
    unspent = []
    unspent_multiple = []
    addresses = []
    script_addresses = []
    privkeys = []
    txid = None
    tx = None
    txinputs = None
    fee = 0
    coin = coins.Bitcoin
    blockcypher_api_key = None
    blockcypher_coin_symbol = None
    testnet = True

    @classmethod
    def setUpClass(cls):
        print('Starting %s tests' % cls.name)

    def assertUnorderedListEqual(self, list1, list2, key):
        list1 = sorted(list1, key=itemgetter(key))
        list2 = sorted(list2, key=itemgetter(key))
        self.assertEqual(list1, list2)

    def assertUnspentOK(self):
        c = self.coin(testnet=self.testnet)
        unspent_outputs = c.unspent(self.unspent_address)
        self.assertUnorderedListEqual(unspent_outputs, self.unspent, 'output')

    def assertParseArgsOK(self):
        addr_args = explorers.blockcypher.parse_addr_args(self.unspent_address)
        self.assertListEqual(addr_args, [self.unspent_address])

        addr_args = explorers.blockcypher.parse_addr_args(*self.unspent_address_multiple)
        self.assertListEqual(addr_args, self.unspent_address_multiple)

        addr_args = explorers.blockcypher.parse_addr_args(self.unspent_address_multiple)
        self.assertListEqual(addr_args, self.unspent_address_multiple)

    def assertMixedSegwitTransactionOK(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        segwit_max_value = 0
        segwit_sender = self.script_addresses[0]
        segwit_from_addr_i = 0
        segwit_unspents = []

        for i, addr in enumerate(self.script_addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > segwit_max_value:
                segwit_max_value = value
                segwit_sender = addr
                segwit_from_addr_i = i
                segwit_unspents = addr_unspents

        for u in segwit_unspents:
            u['segwit'] = True

        regular_max_value = 0
        regular_sender = None
        regular_from_addr_i = 0
        regular_unspents = []

        time.sleep(3)

        for i, addr in enumerate(self.addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > regular_max_value:
                regular_max_value = value
                regular_sender = addr
                regular_from_addr_i = i
                regular_unspents = addr_unspents

        unspents = segwit_unspents + regular_unspents

        #Arbitrarily set send value, change value, receiver and change address
        outputs_value = segwit_max_value + regular_max_value - self.fee
        send_value = int(outputs_value * 0.5)
        change_value = int(outputs_value - send_value)

        if segwit_sender == self.script_addresses[0]:
            receiver = self.script_addresses[1]
        elif segwit_sender == self.script_addresses[1]:
            receiver = self.script_addresses[2]
        else:
            receiver = self.script_addresses[0]

        if regular_sender == self.addresses[0]:
            change_address = self.addresses[1]
        elif regular_sender == self.addresses[1]:
            change_address = self.addresses[2]
        else:
            change_address = self.addresses[0]

        outs = [{'value': send_value, 'address': receiver},
                {'value': change_value, 'address': change_address}]

        #Create the transaction using all available unspents as inputs
        tx = c.mktx(unspents, outs)

        #3rd party check that transaction is ok, not really necessary. Blockcypher requires an API key for this request
        if self.blockcypher_api_key:
            tx_decoded = self.decodetx(tx)

        #For testnets, private keys are already available. For live networks, private keys need to be entered manually at this point
        try:
            segwit_privkey = self.privkeys[segwit_from_addr_i]
        except IndexError:
            segwit_privkey = input("Enter private key for script address %s: %s" % (segwit_from_addr_i, segwit_sender))
        try:
            regular_privkey = self.privkeys[regular_from_addr_i]
        except IndexError:
            regular_privkey = input("Enter private key for address %s: %s" % (regular_from_addr_i, regular_sender))

        #Verify that the private key belongs to the sender address for this network
        self.assertEqual(segwit_sender, c.privtop2wkh(segwit_privkey), msg="Private key does not belong to script %s on %s" % (segwit_sender, c.display_name))
        self.assertEqual(regular_sender, c.privtoaddr(regular_privkey), msg="Private key does not belong to address %s on %s" % (regular_sender, c.display_name))

        #Sign each input with the given private keys
        for i in range(0, len(segwit_unspents)):
            tx = c.sign(tx, i, segwit_privkey)
        for i in range(len(segwit_unspents), len(unspents)):
            tx = c.sign(tx, i, regular_privkey)

        self.assertEqual(len(tx['witness']), len(unspents))
        print(tx)
        tx = serialize(tx)

        #Check transaction format is still ok
        if self.blockcypher_api_key:
            signed_tx_decoded = self.decodetx(tx)
        print(tx)
        #Push the transaction to the network
        result = c.pushtx(tx)
        self.assertPushTxOK(result)
        pass

    def assertSegwitTransactionOK(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.script_addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.script_addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        for u in unspents:
            u['segwit'] = True

        #Arbitrarily set send value, change value, receiver and change address
        outputs_value = max_value - self.fee
        send_value = int(outputs_value * 0.1)
        change_value = int(outputs_value - send_value)

        if sender == self.script_addresses[0]:
            receiver = self.script_addresses[1]
            change_address = self.script_addresses[2]
        elif sender == self.script_addresses[1]:
            receiver = self.script_addresses[2]
            change_address = self.script_addresses[0]
        else:
            receiver = self.script_addresses[0]
            change_address = self.script_addresses[1]

        outs = [{'value': send_value, 'address': receiver},
                {'value': change_value, 'address': change_address}]

        #Create the transaction using all available unspents as inputs
        tx = c.mktx(unspents, outs)

        #3rd party check that transaction is ok, not really necessary. Blockcypher requires an API key for this request
        if self.blockcypher_api_key:
            tx_decoded = self.decodetx(tx)

        #For testnets, private keys are already available. For live networks, private keys need to be entered manually at this point
        try:
            privkey = self.privkeys[from_addr_i]
        except IndexError:
            privkey = input("Enter private key for address %s: %s" % (from_addr_i, sender))

        #Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, c.privtop2wkh(privkey), msg="Private key does not belong to script %s on %s" % (sender, c.display_name))

        #Sign each input with the given private key
        for i in range(0, len(unspents)):
            tx = c.sign(tx, i, privkey)

        self.assertEqual(len(tx['witness']), len(unspents))
        tx = serialize(tx)

        #Check transaction format is still ok
        if self.blockcypher_api_key:
            signed_tx_decoded = self.decodetx(tx)
        print(tx)
        #Push the transaction to the network
        result = c.pushtx(tx)
        self.assertPushTxOK(result)


    def assertTransactionOK(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        #Arbitrarily set send value, change value, receiver and change address
        outputs_value = max_value - self.fee
        send_value = int(outputs_value * 0.1)
        change_value = int(outputs_value - send_value)

        if sender == self.addresses[0]:
            receiver = self.addresses[1]
            change_address = self.addresses[2]
        elif sender == self.addresses[1]:
            receiver = self.addresses[2]
            change_address = self.addresses[0]
        else:
            receiver = self.addresses[0]
            change_address = self.addresses[1]

        outs = [{'value': send_value, 'address': receiver},
                {'value': change_value, 'address': change_address}]

        #Create the transaction using all available unspents as inputs
        tx = c.mktx(unspents, outs)

        #3rd party check that transaction is ok, not really necessary. Blockcypher requires an API key for this request
        if self.blockcypher_api_key:
            tx_decoded = self.decodetx(tx)

        #For testnets, private keys are already available. For live networks, private keys need to be entered manually at this point
        try:
            privkey = self.privkeys[from_addr_i]
        except IndexError:
            privkey = input("Enter private key for address %s: %s" % (from_addr_i, sender))

        #Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, c.privtoaddr(privkey), msg="Private key does not belong to address %s on %s" % (sender, c.display_name))

        #Sign each input with the given private key
        for i in range(0, len(unspents)):
            tx = c.sign(tx, i, privkey)

        tx = serialize(tx)

        #Check transaction format is still ok
        if self.blockcypher_api_key:
            signed_tx_decoded = self.decodetx(tx)

        #Push the transaction to the network
        result = c.pushtx(tx)
        self.assertPushTxOK(result)

    def assertPushTxOK(self, result):
        #For chain.so. Override for other explorers.
        if isinstance(result, dict):
            try:
                self.assertEqual(result['status'], "success")
                print("Txid %s successfully broadcast on %s network" % (result['data']['txid'], result['data']['network']))
            except AssertionError:
                raise AssertionError("Push tx failed. Result: %s" % result)
            except KeyError:
                raise AssertionError("Push tx failed. Response: %s" % result)
        else:
            if not result.status_code == 200:
                raise AssertionError(result.text)

    def decodetx(self, tx):
        return blockcypher.decodetx(tx, coin_symbol=self.blockcypher_coin_symbol, api_key=self.blockcypher_api_key)

    def delete_key_by_name(self, obj, key):
        if isinstance(obj, dict):
            for k, v  in obj.items():
                if k == key:
                    del obj[k]
                    self.delete_key_by_name(obj, key)
                    break
                elif isinstance(v, (dict, list)):
                    self.delete_key_by_name(v, key)
        elif isinstance(obj, list):
            for i in obj:
                self.delete_key_by_name(i, key)

    def assertFetchTXOK(self):
        coin = self.coin(testnet=self.testnet)
        tx = coin.fetchtx(self.txid)
        self.delete_key_by_name(tx, "confirmations")
        self.delete_key_by_name(self.tx, "confirmations")
        self.assertDictEqual(tx, self.tx)

    def assertTXInputsOK(self):
        coin = self.coin(testnet=self.testnet)
        inputs = coin.txinputs(self.txid)
        self.assertUnorderedListEqual(inputs, self.txinputs, key="output")


class TestBitcoin(BaseCoinCase):
    name = "Bitcoin"
    coin = coins.Bitcoin
    addresses = ["1Ba7UmguphMX1g8ibyWQL62qzNu7mrXLVz", "16mBWqf9zefiZcKrKSf6uo3He9ipzPyuTb", "15pXUHkdBXFeUUetZJnJqNoD7dyCzaJFUn"]
    fee = 54400
    blockcypher_coin_symbol = "btc"
    testnet = False

    unspent_address = "12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR"
    unspent = [
        {'output': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34:1', 'value': 5000000,
         'time': 'Wed Mar 23 23:38:20 2011'},
        {'output': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f:1', 'value': 16336000000,
         'time': 'Tue Apr  5 03:45:36 2011'}]
    txid = "fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690"
    txinputs = [{"output": "7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583:1", 'value': 1000000},
                {"output": "da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf:1", 'value': 100000}]
    tx = {'network': 'BTC', 'txid': 'fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690',
          'blockhash': '00000000000006b15ad1bd27555f9813137625bd24a3e5692c5a25ca74ad450a', 'confirmations': 365270,
          'time': 1310086870, 'inputs': [
            {'input_no': 0, 'value': '0.01000000', 'address': '1B55WSKjheXigBKTCyL4aQjKFmfaT6Ppev',
             'type': 'pubkeyhash',
             'script': '3045022076bf3b0edd6c9cdd35fb30d77d780f1d752e959242b2bbd58123617b8db350a6022100a602b91002b9c6c078a7513f72e1d7ccbfa3aa6f1261706b3110db00b1205ae401 04fafb576fcaf43a773ee1e34c5a76ab1f4fe1a7dc23256dd7a4525092537fc11686227d495dff710a291e7e9a6bf474a968158c56882b153e4b2e17bc584ec3cc',
             'from_output': {'txid': '7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583',
                             'output_no': 1}},
            {'input_no': 1, 'value': '0.00100000', 'address': '19aoyNZJpszbV9QYK8eW3SnvXK31uHA9gw',
             'type': 'pubkeyhash',
             'script': '3046022100aecef1b98cf1cead7daadfb538c4808e71c9ef0c1ecec04af64fb1fdcffa7afb022100ec1070f8dea90f9ef6d86ebf251a63a01eae48ff840e0aacce899775b2dd16c601 04d2eeecdff2d0fd3d19f07928689f2aed33f1298f7493f2ca77b3607b545a8b2a91af48c27bc949da72f6ef38412c95bdcf6618486207bb92cd9aa75cae2c116d',
             'from_output': {'txid': 'da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf',
                             'output_no': 1}}], 'outputs': [
            {'output_no': 0, 'value': '0.00100000', 'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
             'type': 'pubkeyhash',
             'script': 'OP_DUP OP_HASH160 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 OP_EQUALVERIFY OP_CHECKSIG'}],
          'tx_hex': '010000000283d5e599f8793ccad12bb9e71d19198133eea0b0416f3cc474e1f148a95d907a010000008b483045022076bf3b0edd6c9cdd35fb30d77d780f1d752e959242b2bbd58123617b8db350a6022100a602b91002b9c6c078a7513f72e1d7ccbfa3aa6f1261706b3110db00b1205ae4014104fafb576fcaf43a773ee1e34c5a76ab1f4fe1a7dc23256dd7a4525092537fc11686227d495dff710a291e7e9a6bf474a968158c56882b153e4b2e17bc584ec3ccffffffffdfda7cfd69df0e9ea41350115381d01d30e053f2ce243a5d10517c772bd81ada010000008c493046022100aecef1b98cf1cead7daadfb538c4808e71c9ef0c1ecec04af64fb1fdcffa7afb022100ec1070f8dea90f9ef6d86ebf251a63a01eae48ff840e0aacce899775b2dd16c6014104d2eeecdff2d0fd3d19f07928689f2aed33f1298f7493f2ca77b3607b545a8b2a91af48c27bc949da72f6ef38412c95bdcf6618486207bb92cd9aa75cae2c116dffffffff01a0860100000000001976a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac00000000',
          'size': 405, 'version': 1, 'locktime': 0}

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    @skip("very high fees")
    def test_transaction(self):
        self.assertTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()


class TestBitcoinTestnet(BaseCoinCase):
    name = "Bitcoin Testnet"
    coin = coins.Bitcoin
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu","mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    script_addresses = ["QWZiamp691VnEMLbwSmXj7Zx6aVsTF2Bkg", "QhAx5qBJphxMrSZfwzaf8KyP9T2DrAMbiC", "QMPRBmeVuqPf8KxYeF9ANdVKh6cNTePk7W"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = "btc-testnet"
    testnet = True

    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c:0', 'value': 180000000,
               'time': 'Sat Nov 25 16:52:50 2017'}]         #For verifying unspent data is correct
    txid = "1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c"
    txinputs = [{'output': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33:1', 'value': 190453372316}]
    tx = {'network': 'BTCTEST', 'txid': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c',
          'blockhash': '00000000000ac694c157a56de45e2f985adefda11d3e2d7375905a03950852df', 'confirmations': 17636,
          'time': 1511628770, 'inputs': [
            {'input_no': 0, 'value': '1904.53372316', 'address': '2N82RUEC3Vw7phe3aHdtbYYSdHq7xWDFqMh',
             'type': 'scripthash', 'script': '0014ffe21a1b058e7f8dedfcc3f1526f82303cff4fc7',
             'from_output': {'txid': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33',
                             'output_no': 1}}], 'outputs': [
            {'output_no': 0, 'value': '1.80000000', 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA',
             'type': 'pubkeyhash',
             'script': 'OP_DUP OP_HASH160 7e585aa1913cf12e9948e90f67188ee9250d5556 OP_EQUALVERIFY OP_CHECKSIG'},
            {'output_no': 1, 'value': '1902.73272316', 'address': '2NDrw9uodKHBZx9wB6kzqUBY5sAC1QCAdzL',
             'type': 'scripthash', 'script': 'OP_HASH160 e223701f10c2a5e7782ef6e10a2560f4c6e968a2 OP_EQUAL'}],
          'tx_hex': '01000000000101333ae299a6c6353d88e6540c67d8c82281259bc29b3313bcbc9b62a9a7e78a1b0100000017160014ffe21a1b058e7f8dedfcc3f1526f82303cff4fc7ffffffff020095ba0a000000001976a9147e585aa1913cf12e9948e90f67188ee9250d555688acfcb92b4d2c00000017a914e223701f10c2a5e7782ef6e10a2560f4c6e968a2870247304402207f2aa4118eee2ef231eab3afcbf6b01b4c1ca3672bd87a3864cf405741bd2c1d02202ab7502cbc50126f68cb2b366e5b3799d3ec0a3359c6a895a730a6891c7bcae10121023c13734016f27089393f9fc79736e4dca1f27725c68e720e1855202f3fbf037e00000000',
          'size': 249, 'version': 1, 'locktime': 0}

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_transaction(self):
        self.assertTransactionOK()

    def test_transaction_mixed_segwit(self):
        self.assertMixedSegwitTransactionOK()

    def test_transaction_segwit(self):
        self.assertSegwitTransactionOK()

    def test_sendmultitx(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0

        for i, addr in enumerate(self.addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i

        privkey = self.privkeys[from_addr_i]

        #Arbitrarily set send value, change value, receiver and change address
        fee = self.fee * 0.1
        outputs_value = max_value - fee
        send_value1 = int(outputs_value * 0.1)
        send_value2 = int(outputs_value * 0.5)

        if sender == self.addresses[0]:
            receiver1 = self.addresses[1]
            receiver2 = self.addresses[2]
        elif sender == self.addresses[1]:
            receiver1 = self.addresses[2]
            receiver2 = self.addresses[0]
        else:
            receiver1 = self.addresses[0]
            receiver2 = self.addresses[1]

        result = c.sendmultitx(privkey, "%s:%s" % (receiver1, send_value1), "%s:%s" % (receiver2, send_value2), self.fee)
        self.assertPushTxOK(result)

    def test_send(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0

        for i, addr in enumerate(self.addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i

        privkey = self.privkeys[from_addr_i]

        #Arbitrarily set send value, change value, receiver and change address
        outputs_value = max_value - self.fee
        send_value = int(outputs_value * 0.1)

        if sender == self.addresses[0]:
            receiver = self.addresses[1]
        elif sender == self.addresses[1]:
            receiver = self.addresses[2]
        else:
            receiver = self.addresses[0]

        result = c.send(privkey, receiver, send_value, fee=self.fee)
        self.assertPushTxOK(result)

    def test_unspent(self):
        self.assertUnspentOK()


class TestLitecoinTestnet(BaseCoinCase):
    name = "Litecoin Testnet"
    coin = coins.Litecoin
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu", "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_address = ["", "", ""]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000,
               'time': 'Wed Dec 20 14:21:21 2017'}]         #For verifying unspent data is correct

    txid = "2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93"
    txinputs = [{'output': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984:0', 'value': 17984768},
                {'output': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984:1', 'value': 161862912},
                {'output': 'f27a53b9433eeb9d011a8c77439edb7a582a01166756e00ea1076699bfa58371:1', 'value': 17941248}]
    tx = {'network': 'LTCTEST', 'txid': '2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93',
          'blockhash': '9c557ffb695078e9f79d92b449fc0e61d82c331692258eb38495013aaf636218', 'confirmations': 1956,
          'time': 1513789292, 'inputs': [
            {'input_no': 0, 'value': '0.17984768', 'address': 'mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu',
             'type': 'pubkeyhash',
             'script': '3045022100c7081d2329334a78cde23359da1d9684d60b7fdb3e396c9d2633c419f9ad30ff022058e7cd031df6b7c7208b3140887e9ba012c81e4f300fcf388256f2636b0682e401 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
             'from_output': {'txid': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984',
                             'output_no': 0}},
            {'input_no': 1, 'value': '1.61862912', 'address': 'mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu',
             'type': 'pubkeyhash',
             'script': '304402207ceb8ca2179fc4ff975ebc3a95b6b1ddc5ce0c280203576d8a1d53948c7138ac02201157f68003220b7f6c3abc7756e7838e062b81ed511f6caff66aa1a73525efa301 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
             'from_output': {'txid': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984',
                             'output_no': 1}},
            {'input_no': 2, 'value': '0.17941248', 'address': 'mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu',
             'type': 'pubkeyhash',
             'script': '3045022100a95b8b36d08f944949b7fa2dca32f5e44e568339dcde11a8713e4676ed3bc77202204d117c91053b667714b1496583583bf8633b7fb189a800d08fdaaefd3f1ef49301 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
             'from_output': {'txid': 'f27a53b9433eeb9d011a8c77439edb7a582a01166756e00ea1076699bfa58371',
                             'output_no': 1}}], 'outputs': [
            {'output_no': 0, 'value': '0.19773452', 'address': 'mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6',
             'type': 'pubkeyhash',
             'script': 'OP_DUP OP_HASH160 42a3e11a80b25ff63b2074c51d1745132bccbba1 OP_EQUALVERIFY OP_CHECKSIG'},
            {'output_no': 1, 'value': '1.77961076', 'address': 'myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW',
             'type': 'pubkeyhash',
             'script': 'OP_DUP OP_HASH160 c384950342cb6f8df55175b48586838b03130fad OP_EQUALVERIFY OP_CHECKSIG'}],
          'tx_hex': '010000000384c9a749888ec0b7372a5740dfe8ba059f67d7b48cb1110060a4e666b42ea383000000006b483045022100c7081d2329334a78cde23359da1d9684d60b7fdb3e396c9d2633c419f9ad30ff022058e7cd031df6b7c7208b3140887e9ba012c81e4f300fcf388256f2636b0682e401210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff84c9a749888ec0b7372a5740dfe8ba059f67d7b48cb1110060a4e666b42ea383010000006a47304402207ceb8ca2179fc4ff975ebc3a95b6b1ddc5ce0c280203576d8a1d53948c7138ac02201157f68003220b7f6c3abc7756e7838e062b81ed511f6caff66aa1a73525efa301210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff7183a5bf996607a10ee0566716012a587adb9e43778c1a019deb3e43b9537af2010000006b483045022100a95b8b36d08f944949b7fa2dca32f5e44e568339dcde11a8713e4676ed3bc77202204d117c91053b667714b1496583583bf8633b7fb189a800d08fdaaefd3f1ef49301210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff020cb82d01000000001976a91442a3e11a80b25ff63b2074c51d1745132bccbba188ac74789b0a000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000',
          'size': 521, 'version': 1, 'locktime': 0}

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_transaction(self):
        self.assertTransactionOK()

    def test_transaction_segwit(self):
        self.assertSegwitTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()

class TestDashTestnet(BaseCoinCase):
    name = "Dash Testnet"
    coin = coins.Dash
    addresses = ["ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz", "yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ", "ySPomQ35mpKiV89LDdAM3URFSibNiXEC4J"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "yV1AhJ3N3Dh4LeiN1ECYpWuLEgmfcA1y5G"
    unspent = [{'output': '546842058817fc29f18de4ba1f0aa5d45fa429c8716ea59d005f878af463ee6c:0', 'value': 29228600000,
               'time': 'Wed Dec 20 14:49:25 2017'}]         #For verifying unspent data is correct
    txid = "725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0"
    txinputs = [{'output': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777:0', 'value': 44907516684},
                {'output': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777:1', 'value': 4989724076}]
    tx = {'txid': '725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0', 'size': 374, 'version': 1,
          'locktime': 0, 'vin': [{'txid': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777', 'vout': 1,
                                  'scriptSig': {
                                      'asm': '3045022100db69455ce4b093372d64dd599d8c1debe05d3ea0e1118a7f96b26c149456937402201db29f3e0b70b8aeb1f3eb9854137f0d8c907336e67ec75aa572d6e97b744f77[ALL] 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
                                      'hex': '483045022100db69455ce4b093372d64dd599d8c1debe05d3ea0e1118a7f96b26c149456937402201db29f3e0b70b8aeb1f3eb9854137f0d8c907336e67ec75aa572d6e97b744f7701210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0'},
                                  'value': 449.07516684, 'valueSat': 44907516684,
                                  'address': 'yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ', 'sequence': 4294967295, 'n': 0,
                                  'addr': 'yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ', 'doubleSpentTxID': None,
                                  'isConfirmed': True, 'confirmations': 723, 'unconfirmedInput': False},
                                 {'txid': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777', 'vout': 0,
                                  'scriptSig': {
                                      'asm': '3045022100cf26f366cabd5a065cca183b1f67f7d00f3537791cd3f293c184790517a8221502203070dae8ffc0cb59354fc5add0d8a4cd7b56586038eb30fabe9832cf1e6a522d[ALL] 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
                                      'hex': '483045022100cf26f366cabd5a065cca183b1f67f7d00f3537791cd3f293c184790517a8221502203070dae8ffc0cb59354fc5add0d8a4cd7b56586038eb30fabe9832cf1e6a522d01210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0'},
                                  'value': 49.89724076, 'valueSat': 4989724076,
                                  'address': 'yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ', 'sequence': 4294967295, 'n': 1,
                                  'addr': 'yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ', 'doubleSpentTxID': None,
                                  'isConfirmed': True, 'confirmations': 723, 'unconfirmedInput': False}], 'vout': [
            {'value': '449.07516684', 'valueSat': 44907516684, 'n': 0, 'scriptPubKey': {
                'asm': 'OP_DUP OP_HASH160 c384950342cb6f8df55175b48586838b03130fad OP_EQUALVERIFY OP_CHECKSIG',
                'hex': '76a914c384950342cb6f8df55175b48586838b03130fad88ac', 'reqSigs': 1, 'type': 'pubkeyhash',
                'addresses': ['ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz']},
             'spentTxId': '90267c69d35999b21efadd99cbc68e8c7a18da525146254500fe8118d4176cf0', 'spentIndex': 0,
             'spentHeight': 45567,
             'multipleSpentAttempts': [{'txid': '90267c69d35999b21efadd99cbc68e8c7a18da525146254500fe8118d4176cf0'},
                                       {'txid': '90267c69d35999b21efadd99cbc68e8c7a18da525146254500fe8118d4176cf0',
                                        'index': 0}]}, {'value': '49.89704076', 'valueSat': 4989704076, 'n': 1,
                                                        'scriptPubKey': {
                                                            'asm': 'OP_DUP OP_HASH160 4f19399fc1f1fc2f4c0c2c33cae4e9067e7893b8 OP_EQUALVERIFY OP_CHECKSIG',
                                                            'hex': '76a9144f19399fc1f1fc2f4c0c2c33cae4e9067e7893b888ac',
                                                            'reqSigs': 1, 'type': 'pubkeyhash',
                                                            'addresses': ['yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ']}}],
          'blockhash': '00000000042772fe75e56decf162e39f5016450040a2953737e0bc7bd0475637', 'height': 45550,
          'confirmations': 488, 'time': 1513853163, 'blocktime': 1513853163, 'valueOut': 498.9722076,
          'valueIn': 498.9724076, 'fees': 0.0002}

    def test_unspent(self):
        self.assertUnspentOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_transaction(self):
        self.assertTransactionOK()

@skip("Explorer not working")
class TestDogeTestnet(BaseCoinCase):
    name = "Doge Testnet"
    coin = coins.Doge
    addresses = ['nn1xreE17QZVwuxxVY3N497SygcBPsm15j', 'nbQPs6XNsA2NzndkhpLDASy4Khg8ZfhUfj', 'naGXBTzJbwp4QRNzZJAjx651T6duZy2kgV']
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "ncst7MzasMBQFwx2LuCwj8Z6F4pCRppzBP"
    unspent = [{'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000,
               'time': 'Thu Sep 13 07:22:50 2012'}]         #For verifying unspent data is correct

    def test_transaction(self):
        self.assertTransactionOK()

class TestBitcoinCash(BaseCoinCase):
    name = "Bitcoin Cash"
    coin = coins.BitcoinCash
    addresses = ["1Ba7UmguphMX1g8ibyWQL62qzNu7mrXLVz", "16mBWqf9zefiZcKrKSf6uo3He9ipzPyuTb", "15pXUHkdBXFeUUetZJnJqNoD7dyCzaJFUn"]
    blockcypher_coin_symbol = "btc"
    fee = 54400
    testnet = False

    unspent_address = "1KomPE4JdF7P4tBzb12cyqbBfrVp4WYxNS"
    unspent = [
            {'output': 'e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476:1', 'value': 249077026}]

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_unspent(self):
        self.assertUnspentOK()

class TestBitcoinCashTestnet(BaseCoinCase):
    name = "Bitcoin Cash Testnet"
    coin = coins.BitcoinCash
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu","mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '80700e6d1125deafa22b307f6c7c99e75771f9fc05517fc795a1344eca7c8472:0', 'value': 550000000}]         #For verifying unspent data is correct
    txid = "b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a"
    txinputs = [{'output': "cbd43131ee11bc9e05f36f55088ede26ab5fb160cc3ff11785ce9cc653aa414b:0", 'value': 96190578808}]
    tx = {'txid': 'b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a', 'version': 1, 'locktime': 0,
          'vin': [{'txid': 'cbd43131ee11bc9e05f36f55088ede26ab5fb160cc3ff11785ce9cc653aa414b', 'vout': 1,
                   'sequence': 4294967295, 'n': 0, 'scriptSig': {
                  'hex': '483045022100b9050a1d58f36a771c4e0869900fb0474b809b134fdad566742e5b3a0ed7580d022065b80e9cc2bc9b921a9b0aad12228d9967345959b021214dbe60b3ffa44dbf0e412102ae83c12f8e2a686fb6ebb25a9ebe39fcd71d981cc6c172fedcdd042536a328f2',
                  'asm': '3045022100b9050a1d58f36a771c4e0869900fb0474b809b134fdad566742e5b3a0ed7580d022065b80e9cc2bc9b921a9b0aad12228d9967345959b021214dbe60b3ffa44dbf0e[ALL|FORKID] 02ae83c12f8e2a686fb6ebb25a9ebe39fcd71d981cc6c172fedcdd042536a328f2'},
                   'addr': 'mpEjdy5ZbKtU9ziXaK7LR75HirUsou5E1c', 'valueSat': 96190578808, 'value': 961.90578808,
                   'doubleSpentTxID': None}], 'vout': [{'value': '11.00000000', 'n': 0, 'scriptPubKey': {
            'hex': '76a914c384950342cb6f8df55175b48586838b03130fad88ac',
            'asm': 'OP_DUP OP_HASH160 c384950342cb6f8df55175b48586838b03130fad OP_EQUALVERIFY OP_CHECKSIG',
            'addresses': ['myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW'], 'type': 'pubkeyhash'},
                                                        'spentTxId': '359f1697c0aab8b6327e1141b1e6141a916654bce75ae30b762e0b5b3869402f',
                                                        'spentIndex': 0, 'spentHeight': 1201482},
                                                       {'value': '950.90478808', 'n': 1, 'scriptPubKey': {
                                                           'hex': '76a9143479daa7de5c6d8dad24535e648861d4e7e3f7e688ac',
                                                           'asm': 'OP_DUP OP_HASH160 3479daa7de5c6d8dad24535e648861d4e7e3f7e6 OP_EQUALVERIFY OP_CHECKSIG',
                                                           'addresses': ['mkJRQbswMT73HpbgqMLVRFRx4pp8iZpxbi'],
                                                           'type': 'pubkeyhash'},
                                                        'spentTxId': '6417082db0a718bd2d7c1dedaa01742713178fc1d3171d53d0fb5c7d299b8f7e',
                                                        'spentIndex': 0, 'spentHeight': 1198189}],
          'blockhash': '000000002bab447cbd0c60829a80051e320aa6308d578db3369eb85b2ebb9f46', 'blockheight': 1196454,
          'time': 1513786390, 'blocktime': 1513786390, 'valueOut': 961.90478808, 'size': 226, 'valueIn': 961.90578808,
          'fees': 0.001}

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_transaction(self):
        self.assertTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()

if __name__ == '__main__':
    unittest.main()
