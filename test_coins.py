from unittest import skip
import unittest
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
    segwit_addresses = []
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
        segwit_sender = self.segwit_addresses[0]
        segwit_from_addr_i = 0
        segwit_unspents = []

        for i, addr in enumerate(self.segwit_addresses):
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

        if segwit_sender == self.segwit_addresses[0]:
            receiver = self.segwit_addresses[1]
        elif segwit_sender == self.segwit_addresses[1]:
            receiver = self.segwit_addresses[2]
        else:
            receiver = self.segwit_addresses[0]

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
        self.assertEqual(segwit_sender, c.privtop2w(segwit_privkey), msg="Private key does not belong to script %s on %s" % (segwit_sender, c.display_name))
        self.assertEqual(regular_sender, c.privtoaddr(regular_privkey), msg="Private key does not belong to address %s on %s" % (regular_sender, c.display_name))

        self.assertTrue(c.is_segwit(segwit_privkey, segwit_sender))
        self.assertFalse(c.is_segwit(regular_privkey, regular_sender))

        #Sign each input with the given private keys
        for i in range(0, len(segwit_unspents)):
            tx = c.sign(tx, i, segwit_privkey)
        for i in range(len(segwit_unspents), len(unspents)):
            tx = c.sign(tx, i, regular_privkey)

        self.assertEqual(len(tx['witness']), len(unspents))
        tx = serialize(tx)

        #Push the transaction to the network
        result = c.pushtx(tx)
        self.assertPushTxOK(result)

    def assertSegwitTransactionOK(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.segwit_addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.segwit_addresses):
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

        if sender == self.segwit_addresses[0]:
            receiver = self.segwit_addresses[1]
            change_address = self.segwit_addresses[2]
        elif sender == self.segwit_addresses[1]:
            receiver = self.segwit_addresses[2]
            change_address = self.segwit_addresses[0]
        else:
            receiver = self.segwit_addresses[0]
            change_address = self.segwit_addresses[1]

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
        self.assertEqual(sender, c.privtop2w(privkey), msg="Private key does not belong to script %s on %s" % (sender, c.display_name))

        #Sign each input with the given private key
        for i in range(0, len(unspents)):
            tx = c.sign(tx, i, privkey)

        self.assertEqual(len(tx['witness']), len(unspents))
        tx = serialize(tx)

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
        try:
            import blockcypher
            return blockcypher.decodetx(tx, coin_symbol=self.blockcypher_coin_symbol, api_key=self.blockcypher_api_key)
        except ImportError:
            pass

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
        txid = tx.get('txid', None) or tx.get('hash', None) or tx.get('txhash', None)
        self.assertEqual(txid, self.tx['txid'])

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
        {'output': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34:1', 'value': 5000000,},
        {'output': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f:1', 'value': 16336000000}]
    txid = "fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690"
    txinputs = [{"output": "7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583:1", 'value': 1000000},
                {"output": "da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf:1", 'value': 100000}]
    tx = {'txid': 'fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690'}

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
    segwit_addresses = ["2N3CxTkwr7uSh6AaZKLjWeR8WxC43bQ2QRZ", "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU", "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = "btc-testnet"
    testnet = True

    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c:0', 'value': 180000000}]
    txid = "1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c"
    txinputs = [{'output': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33:1', 'value': 190453372316}]
    tx = {'txid': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c'}

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
    segwit_addresses = ["2N3CxTkwr7uSh6AaZKLjWeR8WxC43bQ2QRZ", "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU", "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000,}]

    txid = "2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93"
    txinputs = [{'output': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984:0', 'value': 17984768},
                {'output': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984:1', 'value': 161862912},
                {'output': 'f27a53b9433eeb9d011a8c77439edb7a582a01166756e00ea1076699bfa58371:1', 'value': 17941248}]
    tx = {'txid': '2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93'}

    def tearDown(self):
        time.sleep(8)

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
    unspent = [{'output': '546842058817fc29f18de4ba1f0aa5d45fa429c8716ea59d005f878af463ee6c:0', 'value': 29228600000}]
    txid = "725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0"
    txinputs = [{'output': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777:0', 'value': 4989724076},
                {'output': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777:1', 'value': 44907516684}]
    tx = {'txid': '725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0'}

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
    unspent = [{'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000}]

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
    unspent = [{'output': '80700e6d1125deafa22b307f6c7c99e75771f9fc05517fc795a1344eca7c8472:0', 'value': 550000000}]
    txid = "b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a"
    txinputs = [{'output': "cbd43131ee11bc9e05f36f55088ede26ab5fb160cc3ff11785ce9cc653aa414b:1", 'value': 96190578808}]
    tx = {'txid': 'b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a'}

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
