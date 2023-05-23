import unittest
from queue import Queue
from operator import itemgetter
from cryptos import *
from cryptos import coins
from cryptos.types import Tx, TxOut
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from typing import Any, Union, List


class BaseSyncCoinTestCase(unittest.TestCase):
    name: str = "Bitcoin Testnet"
    coin = coins.Bitcoin
    addresses: List[str] = ["n2DQVQZiA2tVBDu4fNAjKVBS2RArWhfncv", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu",
                            "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_addresses: List[str] = ["2N74sauceDn2qeHFJuNfJ3c1anxPcDRrVtz", "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU",
                                   "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    native_segwit_addresses: List[str] = ["tb1quvys2uxzwl4sqex5xh59kar2y8rt4k7ym0vug3",
                                          "tb1qfuvnn87p787z7nqv9seu4e8fqel83yacg7yf2r",
                                          "tb1qg237zx5qkf0lvweqwnz36969zv4uewapph2pws"]
    multisig_addresses: List[str] = ["2MvmK6SRDc13BaYbumBbtkCH2fKbViC5XEv", "2MtT7kkzRDn1kiT9GZoS1zSgh7twP145Qif"]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    fee: int = 410
    max_fee: int = 3500
    testnet: bool = True
    min_latest_height: int = 1258030

    unspent_addresses: List[str] = ["ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA", "2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy",
                                    "tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq"]
    unspent: List[ElectrumXTx] = [{'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c',
                                   'tx_pos': 0, 'height': 1238008, 'value': 180000000,
                                   'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'}]
    unspents: List[ElectrumXTx] = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'tx_pos': 0, 'height': 1238008,
         'value': 180000000, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'tx_pos': 1, 'height': 1275633,
         'value': 173980000, 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'tx_pos': 0, 'height': 1275633,
         'value': 6000000, 'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 180000000, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [
        {'confirmed': 180000000, 'unconfirmed': 0, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'confirmed': 173980000, 'unconfirmed': 0, 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'confirmed': 6000000, 'unconfirmed': 0, 'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    history: List[ElectrumXTx] = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'height': 1238008}]
    histories: List[ElectrumXTx] = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'height': 1238008,
         'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'tx_hash': 'e25d8f4036e44159b0364b45867e08ae47a57dda68ba800ba8abe1fb2dc54a40', 'height': 1275633,
         'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'height': 1275633,
         'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'height': 1275633,
         'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    txid: str = "1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c"
    txheight: int = 1238008
    txinputs: List[TxOut] = [
        {'output': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33:1', 'value': 190453372316}]
    raw_tx: str = "01000000000101333ae299a6c6353d88e6540c67d8c82281259bc29b3313bcbc9b62a9a7e78a1b0100000017160014ffe21a1b058e7f8dedfcc3f1526f82303cff4fc7ffffffff020095ba0a000000001976a9147e585aa1913cf12e9948e90f67188ee9250d555688acfcb92b4d2c00000017a914e223701f10c2a5e7782ef6e10a2560f4c6e968a2870247304402207f2aa4118eee2ef231eab3afcbf6b01b4c1ca3672bd87a3864cf405741bd2c1d02202ab7502cbc50126f68cb2b366e5b3799d3ec0a3359c6a895a730a6891c7bcae10121023c13734016f27089393f9fc79736e4dca1f27725c68e720e1855202f3fbf037e00000000"

    @classmethod
    def setUpClass(cls):
        print('Starting %s sync tests' % cls.name)

    def setUp(self) -> None:
        self._coin = self.coin(testnet=self.testnet)

    def tearDown(self) -> None:
        self._coin.close()

    def assertUnorderedListEqual(self, list1, list2, key):
        list1 = sorted(list1, key=itemgetter(key))
        list2 = sorted(list2, key=itemgetter(key))
        self.assertEqual(list1, list2)

    @property
    def tx(self) -> Tx:
        return deserialize(self.raw_tx)

    def assertBalanceOK(self):
        result = self._coin.get_balance(self.unspent_addresses[0])
        self.assertEqual(self.balance, result)

    def assertBalancesOK(self):
        result = self._coin.get_balances(*self.unspent_addresses)
        self.assertListEqual(self.balances, result)

    def assertBalanceMerkleProvenOK(self):
        result = self._coin.balance_merkle_proven(self.unspent_addresses[0])
        self.assertEqual(self.balance['confirmed'], result)

    def assertBalancesMerkleProvenOK(self):
        balances = [{'address': tx['address'], 'balance': tx['confirmed']} for tx in self.balances]
        result = self._coin.balances_merkle_proven(*self.unspent_addresses)
        self.assertListEqual(balances, result)

    def assertHistoryOK(self):
        result = self._coin.history(self.unspent_addresses[0])
        self.assertEqual(self.history, result)

    def assertHistoriesOK(self):
        result = self._coin.get_histories(*self.unspent_addresses, merkle_proof=True)
        self.assertUnorderedListsEqual(self.histories, result, "tx_hash")

    def assertUnspentOK(self):
        result = self._coin.unspent(self.unspent_addresses[0])
        self.assertEqual(self.unspent, result)

    def assertUnorderedListsEqual(self, expected: List[Any], result: List[Any], order_by: str):
        expected = sorted(expected, key=lambda d: d[order_by])
        result = sorted(result, key=lambda d: d[order_by])
        self.assertListEqual(expected, result)

    def assertUnspentsOK(self):
        unspent_outputs = self._coin.get_unspents(*self.unspent_addresses, merkle_proof=True)
        self.assertUnorderedListsEqual(self.unspents, unspent_outputs, 'tx_hash')

    def assertMixedSegwitTransactionOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        segwit_max_value = 0
        segwit_sender = self.segwit_addresses[0]
        segwit_from_addr_i = 0
        segwit_unspents = []

        for i, addr in enumerate(self.segwit_addresses):
            addr_unspents = self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > segwit_max_value:
                segwit_max_value = value
                segwit_sender = addr
                segwit_from_addr_i = i
                segwit_unspents = addr_unspents

        regular_max_value = 0
        regular_sender = None
        regular_from_addr_i = 0
        regular_unspents = []

        for i, addr in enumerate(self.addresses):
            addr_unspents = self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > regular_max_value:
                regular_max_value = value
                regular_sender = addr
                regular_from_addr_i = i
                regular_unspents = addr_unspents

        self.assertIn(regular_sender, self.addresses)
        self.assertIn(segwit_sender, self.segwit_addresses)
        unspents = segwit_unspents + regular_unspents
        total_value = segwit_max_value + regular_max_value
        # Arbitrarily set send value, change value, receiver and change address
        send_value = int(total_value * 0.5)

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

        outs = [{'value': send_value, 'address': receiver}]

        # Create the transaction using all available unspents as inputs
        tx = self._coin.mktx_with_change(unspents, outs, change_addr=change_address)

        segwit_privkey = self.privkeys[segwit_from_addr_i]
        regular_privkey = self.privkeys[regular_from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(segwit_sender, self._coin.privtop2wpkh_p2sh(segwit_privkey),
                         msg=f"Private key does not belong to address {segwit_sender} on {self._coin.display_name}")
        self.assertEqual(regular_sender, self._coin.privtoaddr(regular_privkey),
                         msg=f"Private key does not belong to address {regular_sender} on {self._coin.display_name}")

        self.assertTrue(self._coin.is_segwit_or_multisig(segwit_sender))
        self.assertFalse(self._coin.is_segwit_or_multisig(regular_sender))

        # Sign each input with the given private keys
        # Try signing one at a time and also with signall and make sure they give the same result

        tx2 = deepcopy(tx)

        for i in range(0, len(segwit_unspents)):
            tx = self._coin.sign(tx, i, segwit_privkey)
        for i in range(len(segwit_unspents), len(unspents)):
            tx = self._coin.sign(tx, i, regular_privkey)

        tx2 = self._coin.signall(tx2, {segwit_sender: segwit_privkey, regular_sender: regular_privkey})

        self.assertDictEqual(tx, dict(tx2))
        self.assertEqual(serialize(tx), serialize(tx2))

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = self._coin.calculate_fee(tx)
        self.assertGreater(fee, 0)
        self.assertLessEqual(fee, self.max_fee)
        self.assertEqual(len(tx['ins']), len(unspents))
        self.assertEqual(len(tx['outs']), 2)
        self.assertEqual(len(tx['witness']), len(unspents))
        self.assertEqual(tx['marker'], 0)
        self.assertEqual(tx['flag'], 1)

        prev_script = None

        for inp in tx['ins']:
            script = inp['script']
            self.assertIsInstance(script, str)
            self.assertIsNot(script, '')

        for o in tx['outs']:
            script = o['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertNotEqual(script, '')
            prev_script = script

        prev_script_code = None

        for w in tx['witness']:
            script_code = w['scriptCode']
            self.assertIsInstance(script_code, str)
            if script_code:
                self.assertEqual(w['number'], 2)
                if prev_script_code:
                    self.assertNotEqual(script_code, prev_script_code)
            else:
                self.assertEqual(w['number'], 0)
            prev_script_code = script_code

        tx = serialize(tx)
        print(tx)
        # Push the transaction to the network
        result = self._coin.pushtx(tx)
        self.assertTXResultOK(tx, result)

    def assertSegwitTransactionOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.segwit_addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.segwit_addresses):
            addr_unspents = self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        # Arbitrarily set send value, receiver and change address
        send_value = int(max_value * 0.1)

        if sender == self.segwit_addresses[0]:
            receiver = self.segwit_addresses[1]
            change_address = self.segwit_addresses[2]
        elif sender == self.segwit_addresses[1]:
            receiver = self.segwit_addresses[2]
            change_address = self.segwit_addresses[0]
        else:
            receiver = self.segwit_addresses[0]
            change_address = self.segwit_addresses[1]

        outs = [{'value': send_value, 'address': receiver}]

        # Create the transaction using all available unspents as inputs
        tx = self._coin.mktx_with_change(unspents, outs, change_addr=change_address)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtop2wpkh_p2sh(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = self._coin.calculate_fee(tx)
        self.assertGreater(fee, 0)
        self.assertLessEqual(fee, self.fee * 4)
        self.assertEqual(len(tx['ins']), len(unspents))
        self.assertEqual(len(tx['outs']), 2)
        self.assertEqual(len(tx['witness']), len(unspents))
        self.assertEqual(tx['marker'], 0)
        self.assertEqual(tx['flag'], 1)

        prev_script = None

        for inp in tx['ins']:
            script = inp['script']
            if prev_script:
                self.assertEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertIsNot(script, '')
            prev_script = script

        for o in tx['outs']:
            script = o['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertEqual(len(script), 46)
            prev_script = script

        prev_script_code = None
        for w in tx['witness']:
            self.assertEqual(w['number'], 2)
            script_code = w['scriptCode']
            if prev_script_code:
                self.assertNotEqual(script_code, prev_script_code)
            self.assertIsInstance(script_code, str)
            self.assertNotEqual(script_code, '')
            prev_script_code = script_code

        # Push the transaction to the network

        result = self._coin.pushtx(tx)
        self.assertTXResultOK(tx, result)

    def assertNativeSegwitTransactionOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.native_segwit_addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.native_segwit_addresses):
            addr_unspents = self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        # Arbitrarily set send value, change value, receiver and change address
        send_value = int(max_value * 0.1)

        if sender == self.native_segwit_addresses[0]:
            receiver = self.native_segwit_addresses[1]
            change_address = self.native_segwit_addresses[2]
        elif sender == self.native_segwit_addresses[1]:
            receiver = self.native_segwit_addresses[2]
            change_address = self.native_segwit_addresses[0]
        else:
            receiver = self.native_segwit_addresses[0]
            change_address = self.native_segwit_addresses[1]

        outs = [{'value': send_value, 'address': receiver}]

        # Create the transaction using all available unspents as inputs
        tx = self._coin.mktx_with_change(unspents, outs, change_addr=change_address)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtosegwitaddress(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = self._coin.calculate_fee(tx)
        self.assertGreater(fee, 0)
        self.assertLessEqual(fee, self.fee * 2)
        self.assertEqual(len(tx['ins']), len(unspents))
        self.assertEqual(len(tx['outs']), 2)
        self.assertEqual(len(tx['witness']), len(unspents))
        self.assertEqual(tx['marker'], 0)
        self.assertEqual(tx['flag'], 1)

        prev_script = None

        for inp in tx['ins']:
            script = inp['script']
            self.assertEqual(script, '')

        for o in tx['outs']:
            script = o['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertEqual(len(script), 44)
            prev_script = script

        prev_script_code = None
        for w in tx['witness']:
            self.assertEqual(w['number'], 2)
            script_code = w['scriptCode']
            if prev_script_code:
                self.assertNotEqual(script_code, prev_script_code)
            self.assertIsInstance(script_code, str)
            self.assertNotEqual(script_code, '')
            prev_script_code = script_code

        tx = serialize(tx)

        # Push the transaction to the network
        result = self._coin.pushtx(tx)
        self.assertTXResultOK(tx, result)

    def assertTXResultOK(self, tx: Union[str, Tx], result):
        if not isinstance(tx, str):
            tx = serialize(tx)
        tx_hash = public_txhash(tx)
        self.assertEqual(result, tx_hash)
        print("TX %s broadcasted successfully" % result)

    def assertTransactionOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.addresses):
            addr_unspents = self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        # Arbitrarily set send value, receiver and change address
        send_value = int(max_value * 0.1)

        if sender == self.addresses[0]:
            receiver = self.addresses[1]
            change_address = self.addresses[2]
        elif sender == self.addresses[1]:
            receiver = self.addresses[2]
            change_address = self.addresses[0]
        else:
            receiver = self.addresses[0]
            change_address = self.addresses[1]

        outs = [{'value': send_value, 'address': receiver}]

        # Create the transaction using all available unspents as inputs
        tx = self._coin.mktx_with_change(unspents, outs, change_addr=change_address)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtoaddr(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = self._coin.calculate_fee(tx)
        self.assertGreater(fee, 0)
        self.assertLessEqual(fee, self.max_fee)
        self.assertEqual(len(tx['ins']), len(unspents))
        self.assertEqual(len(tx['outs']), 2)
        self.assertNotIn('witness', tx)
        self.assertNotIn('marker', tx)
        self.assertNotIn('flag', tx)

        prev_script = None

        for inp in tx['ins']:
            script = inp['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertIsNot(script, '')
            prev_script = script

        for o in tx['outs']:
            script = o['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertEqual(len(script), 50)
            prev_script = script

        # Serialize and push the transaction to the network
        tx_serialized = serialize(tx)
        result = self._coin.pushtx(tx)
        self.assertTXResultOK(tx_serialized, result)

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

    def assertGetTXOK(self):
        tx = self._coin.get_tx(self.txid)
        self.assertListEqual(list(tx.keys()), ['ins', 'outs', 'version', 'locktime', 'tx_hash'])
        self.assertEqual(tx, self.tx)

    def assertGetSegwitTXOK(self):
        tx = self._coin.get_tx(self.txid)
        self.assertListEqual(list(tx.keys()), ['ins', 'outs', 'version', 'marker', 'flag', 'witness', 'locktime'])
        self.assertEqual(tx, self.tx)

    def assertGetVerboseTXOK(self):
        tx = self._coin.get_verbose_tx(self.txid)
        self.assertListEqual(sorted(tx.keys()),
                             ['blockhash', 'blocktime', 'confirmations', 'hash', 'hex', 'locktime', 'size', 'time',
                              'txid', 'version', 'vin', 'vout', 'vsize', 'weight'])

    def assertGetSegwitTxsOK(self):
        txs = self._coin.get_txs(self.txid)
        self.assertListEqual(list(txs[0].keys()),
                             ['ins', 'outs', 'version', 'marker', 'flag', 'witness', 'locktime'])

    def assertMultiSigTransactionOK(self):
        pubs = [privtopub(priv) for priv in self.privkeys]
        script, address1 = self._coin.mk_multisig_address(*pubs, num_required=2)
        self.assertEqual(address1, self.multisig_addresses[0])
        pubs2 = [privtopub(priv) for priv in self.privkeys[0:2]]
        script2, address2 = self._coin.mk_multisig_address(*pubs2)
        self.assertEqual(address2, self.multisig_addresses[1])

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = None

        for i, addr in enumerate(self.multisig_addresses):
            addr_unspents = self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr

        # Arbitrarily set send value, receiver and change address
        send_value = int(max_value * 0.1)

        receiver = address2 if sender == address1 else address1

        tx = self._coin.preparetx(sender, receiver, send_value, self.fee)

        for i in range(0, len(tx['ins'])):
            if sender == address1:
                sig1 = self._coin.multisign(tx, i, script, self.privkeys[0])
                sig3 = self._coin.multisign(tx, i, script, self.privkeys[2])
                tx = apply_multisignatures(tx, i, script, sig1, sig3)
            else:
                sig1 = self._coin.multisign(tx, i, script2, self.privkeys[0])
                sig2 = self._coin.multisign(tx, i, script2, self.privkeys[1])
                tx = apply_multisignatures(tx, i, script2, sig1, sig2)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = self._coin.calculate_fee(tx)
        self.assertEqual(fee, self.fee)
        self.assertGreaterEqual(len(tx['ins']), 1)
        self.assertEqual(len(tx['outs']), 2)
        self.assertNotIn('witness', tx)
        self.assertNotIn('marker', tx)
        self.assertNotIn('flag', tx)

        prev_script = None

        for inp in tx['ins']:
            script = inp['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertIsNot(script, '')
            prev_script = script

        for o in tx['outs']:
            script = o['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertNotEqual(script, '')
            prev_script = script

        # Push the transaction to the network
        result = self._coin.pushtx(tx)
        print(serialize(tx))
        self.assertTXResultOK(tx, result)

    def assertBlockHeaderOK(self):
        blockinfo = self._coin.block_header(self.txheight)
        self.assertListEqual(sorted(blockinfo.keys()),
                             ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']
                             )

    def assertBlockHeadersOK(self):
        blockinfos = self._coin.block_headers(self.txheight)
        for blockinfo in blockinfos:
            self.assertListEqual(sorted(blockinfo.keys()),
            ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']
        )

    def assertMerkleProofOK(self):
        tx = self.unspent[0]
        tx_hash = tx['tx_hash']
        proof = self._coin.merkle_prove(self.unspent[0])
        self.assertDictEqual(dict(proof), {
            'tx_hash': tx_hash,
            'proven': True
        })

    def assertSendMultiRecipientsTXOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0

        for i, addr in enumerate(self.addresses):
            addr_unspents = self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i

        privkey = self.privkeys[from_addr_i]

        # Arbitrarily set send value, change value, receiver and change address
        outputs_value = max_value - self.fee
        send_value1 = int(outputs_value * 0.2)
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

        self.assertEqual(sender, self._coin.privtoaddr(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        outs = [{'address': receiver1, 'value': send_value1},  {'address': receiver2, 'value': send_value2}]

        result = self._coin.send_to_multiple_receivers_tx(privkey, sender, outs, fee=self.fee)
        self.assertIsInstance(result, str)
        print("TX %s broadcasted successfully" % result)

    def assertSendOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0

        for i, addr in enumerate(self.addresses):
            addr_unspents = self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                break

        privkey = self.privkeys[from_addr_i]

        self.assertEqual(sender, self._coin.privtoaddr(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Arbitrarily set send value, change value, receiver and change address
        send_value = int(max_value * 0.2)

        if sender == self.addresses[0]:
            receiver = self.addresses[1]
        elif sender == self.addresses[1]:
            receiver = self.addresses[2]
        else:
            receiver = self.addresses[0]

        result = self._coin.send(privkey, sender, receiver, send_value)
        self.assertIsInstance(result, str)
        print("TX %s broadcasted successfully" % result)

    def assertSubscribeBlockHeadersOK(self):
        queue = Queue()
        block_keys = ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']

        def on_new_block(height: int, hex_header: str, header: BlockHeader) -> None:
            queue.put((height, hex_header, header))

        self._coin.subscribe_to_block_headers(on_new_block)
        result = queue.get()
        height, hex_header, header = result
        self.assertGreater(height, self.min_latest_height)
        self.assertEqual(deserialize_header(binascii.unhexlify(hex_header)), header)
        self.assertListEqual(sorted(header.keys()), block_keys)
        self._coin.unsubscribe_from_block_headers()

    def assertLatestBlockOK(self):
        height, hex_header, header = self._coin.block
        self.assertGreater(height, self.min_latest_height)
        self.assertIsInstance(hex_header, str)
        self.assertIsInstance(header, dict)
        height, hex_header, header = self._coin.block
        self.assertGreater(height, self.min_latest_height)
        self.assertIsInstance(hex_header, str)
        self.assertIsInstance(header, dict)

    def assertConfirmationsOK(self):
        confirmations = self._coin.confirmations(0)
        block = self._coin.block
        height = block[0]
        self.assertEqual(confirmations, 0)
        confirmations = self._coin.confirmations(height - 1)
        self.assertEqual(confirmations, 2)
        confirmations = self._coin.confirmations(1)
        self.assertEqual(confirmations, height)

    def assertSubscribeAddressOK(self):
        queue = Queue()
        address = self.addresses[0]

        def add_to_queue(addr: str, status: str) -> None:
            queue.put((addr, status))

        self._coin.subscribe_to_address(add_to_queue, address)
        addr, initial_status = queue.get()
        self.assertEqual(addr, address)
        self.assertTransactionOK()
        addr, status = queue.get()
        self.assertEqual(addr, address)
        self.assertNotEqual(initial_status, status)
        self._coin.unsubscribe_from_address(address)

    def assertSubscribeAddressTransactionsOK(self):
        queue = Queue()
        address = self.addresses[0]

        def add_to_queue(address: str, txs: List[Tx], newly_confirmed: List[Tx], history: List[Tx],
                         unspent: List[Tx], confirmed: int, unconfirmed: int, proven: int) -> None:
            queue.put((address, txs, newly_confirmed, history, unspent, confirmed, unconfirmed, proven))

        self._coin.subscribe_to_address_transactions(add_to_queue, address)
        addr, start_txs, start_newly_confirmed, start_history, start_unspent, start_confirmed, start_unconfirmed, start_proven = queue.get()
        self.assertEqual(addr, address)
        self.assertEqual(start_txs, [])
        self.assertEqual(start_newly_confirmed, [])
        self.assertSendOK()
        addr, new_txs, newly_confirmed, history, unspent, confirmed, unconfirmed, proven = queue.get()
        self.assertEqual(addr, address)
        self.assertGreaterEqual(len(new_txs), 1)
        self.assertEqual(len(newly_confirmed), 0)
        self.assertGreaterEqual(len(history), 9)
        self.assertEqual(len(start_history), len(history))
        self.assertNotEqual(unconfirmed, start_unconfirmed)
        self._coin.unsubscribe_from_address(address)

