import unittest
import asyncio
from queue import Queue
from operator import itemgetter
from cryptos import *
from cryptos.transaction import calculate_fee
from cryptos import coins_async
from cryptos.utils import alist
from cryptos.types import Tx
from typing import AsyncGenerator, Any, Union, List


class BaseAsyncCoinTestCase(unittest.IsolatedAsyncioTestCase):
    name = ""
    unspent_address = ""
    unspent_addresses = []
    unspent = {}
    unspents = []
    addresses = []
    segwit_addresses = []
    new_segwit_addresses = []
    txheight = None
    multisig_addresses: List[str] = []
    privkeys = []
    txid = None
    merkle_txhash = None
    merkle_txheight = None
    txinputs = None
    min_latest_height = 99999999999
    fee = 100
    coin = coins_async.Bitcoin
    blockcypher_api_key = None
    blockcypher_coin_symbol = None
    testnet = True
    num_merkle_siblings = 0
    balance = {}
    balances = []
    history = {}
    raw_tx = ''
    histories = []
    event = asyncio.Event()

    @classmethod
    def setUpClass(cls):
        print('Starting %s tests' % cls.name)

    def setUp(self) -> None:
        self._coin = self.coin(testnet=self.testnet)

    async def asyncTearDown(self) -> None:
        await self._coin.close()

    def assertUnorderedListEqual(self, list1, list2, key):
        list1 = sorted(list1, key=itemgetter(key))
        list2 = sorted(list2, key=itemgetter(key))
        self.assertEqual(list1, list2)

    @property
    def tx(self) -> Tx:
        return deserialize(self.raw_tx)

    async def assertBalanceOK(self):
        result = await self._coin.get_balance(self.unspent_addresses[0])
        self.assertEqual(self.balance, result)

    async def assertGeneratorEqual(self, expected: List[Any], agen: AsyncGenerator[Any, None], order_by: str = None):
        result = await alist(agen)
        if order_by:
            expected = sorted(expected, key=lambda d: d[order_by])
            result = sorted(result, key=lambda d: d[order_by])
        self.assertEqual(expected, result)

    async def assertBalancesOK(self):
        agen = self._coin.get_balances(*self.unspent_addresses)
        await self.assertGeneratorEqual(self.balances, agen)

    async def assertBalanceMerkleProvenOK(self):
        result = await self._coin.balance_merkle_proven(self.unspent_addresses[0])
        self.assertEqual(self.balance['confirmed'], result)

    async def assertBalancesMerkleProvenOK(self):
        balances = [{'address': tx['address'], 'balance': tx['confirmed']} for tx in self.balances]
        agen = self._coin.balances_merkle_proven(*self.unspent_addresses)
        await self.assertGeneratorEqual(balances, agen)

    async def assertHistoryOK(self):
        result = await self._coin.history(self.unspent_addresses[0])
        self.assertEqual(self.history, result)

    async def assertHistoriesOK(self):
        agen = self._coin.get_histories(*self.unspent_addresses, merkle_proof=True)
        await self.assertGeneratorEqual(self.histories, agen, 'tx_hash')

    async def assertUnspentOK(self):
        result = await self._coin.unspent(self.unspent_addresses[0])
        self.assertEqual(self.unspent, result)

    async def assertUnspentsOK(self):
        unspent_outputs = self._coin.get_unspents(*self.unspent_addresses, merkle_proof=True)
        await self.assertGeneratorEqual(self.unspents, unspent_outputs, 'tx_hash')

    async def assertMixedSegwitTransactionOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        segwit_max_value = 0
        segwit_sender = self.segwit_addresses[0]
        segwit_from_addr_i = 0
        segwit_unspents = []

        for i, addr in enumerate(self.segwit_addresses):
            addr_unspents = await self._coin.unspent(addr)
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
            addr_unspents = await self._coin.unspent(addr)
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
        tx = await self._coin.mktx_with_change(unspents, outs, change=change_address)

        segwit_privkey = self.privkeys[segwit_from_addr_i]
        regular_privkey = self.privkeys[regular_from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(segwit_sender, self._coin.privtop2w(segwit_privkey),
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

        self.assertDictEqual(tx, tx2)
        self.assertEqual(serialize(tx), serialize(tx2))

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = calculate_fee(tx)
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
        result = await self._coin.pushtx(tx)
        self.assertTXResultOK(tx, result)

    async def assertSegwitTransactionOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.segwit_addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.segwit_addresses):
            addr_unspents = await self._coin.unspent(addr)
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
        tx = await self._coin.mktx_with_change(unspents, outs, change=change_address)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtop2w(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = calculate_fee(tx)
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

        result = await self._coin.pushtx(tx)
        self.assertTXResultOK(tx, result)

    async def assertNewSegwitTransactionOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.new_segwit_addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.new_segwit_addresses):
            addr_unspents = await self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        # Arbitrarily set send value, change value, receiver and change address
        send_value = int(max_value * 0.1)

        if sender == self.new_segwit_addresses[0]:
            receiver = self.new_segwit_addresses[1]
            change_address = self.new_segwit_addresses[2]
        elif sender == self.new_segwit_addresses[1]:
            receiver = self.new_segwit_addresses[2]
            change_address = self.new_segwit_addresses[0]
        else:
            receiver = self.new_segwit_addresses[0]
            change_address = self.new_segwit_addresses[1]

        outs = [{'value': send_value, 'address': receiver}]

        # Create the transaction using all available unspents as inputs
        tx = await self._coin.mktx_with_change(unspents, outs, change=change_address)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtosegwitaddress(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = calculate_fee(tx)
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
        result = await self._coin.pushtx(tx)
        self.assertTXResultOK(tx, result)

    def assertTXResultOK(self, tx: Union[str, Tx], result):
        if not isinstance(tx, str):
            tx = serialize(tx)
        tx_hash = public_txhash(tx)
        self.assertEqual(result, tx_hash)
        print("TX %s broadcasted successfully" % result)

    async def assertTransactionOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.addresses):
            addr_unspents = await self._coin.unspent(addr)
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
        tx = await self._coin.mktx_with_change(unspents, outs, change=change_address)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtoaddr(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = calculate_fee(tx)
        self.assertGreater(fee, 0)
        self.assertLessEqual(fee, self.fee * 2)
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
        result = await self._coin.pushtx(tx)
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

    async def assertGetTXOK(self):
        tx = await self._coin.get_tx(self.txid)
        self.assertListEqual(list(tx.keys()), ['ins', 'outs', 'version', 'locktime', 'tx_hash'])
        self.assertEqual(tx, self.tx)

    async def assertGetSegwitTXOK(self):
        tx = await self._coin.get_tx(self.txid)
        self.assertListEqual(list(tx.keys()), ['ins', 'outs', 'version', 'marker', 'flag', 'witness', 'locktime'])
        self.assertEqual(tx, self.tx)

    async def assertGetSegwitTxsOK(self):
        txs = await alist(self._coin.get_txs(self.txid))
        self.assertListEqual(list(txs[0].keys()),
                             ['ins', 'outs', 'version', 'marker', 'flag', 'witness', 'locktime'])

    async def assertMultiSigTransactionOK(self):
        pubs = [privtopub(priv) for priv in self.privkeys]
        script, address1 = self._coin.mk_multsig_address(*pubs, num_required=2)
        self.assertEqual(address1, self.multisig_addresses[0])
        pubs2 = [privtopub(priv) for priv in self.privkeys[0:2]]
        script2, address2 = self._coin.mk_multsig_address(*pubs2)
        self.assertEqual(address2, self.multisig_addresses[1])

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        from_addr_i = 0
        unspents = []
        sender = None

        for i, addr in enumerate(self.multisig_addresses):
            addr_unspents = await self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        # Arbitrarily set send value, receiver and change address
        send_value = int(max_value * 0.1)

        receiver = address2 if sender == address1 else address1

        tx = await self._coin.preparetx(sender, receiver, send_value, self.fee)

        for i in range(0, len(tx['ins'])):
            if sender == address1:
                sig1 = self._coin.multisign(tx, i, script, self.privkeys[0])
                sig3 = self._coin.multisign(tx, i, script, self.privkeys[2])
                tx = apply_multisignatures(tx, i, script, sig1, sig3)
            else:
                sig1 = self._coin.multisign(tx, i, script, self.privkeys[0])
                sig2 = self._coin.multisign(tx, i, script, self.privkeys[1])
                tx = apply_multisignatures(tx, i, script, sig1, sig2)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = calculate_fee(tx)
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
        result = await self._coin.pushtx(tx)
        print(serialize(tx))
        self.assertTXResultOK(tx, result)

    async def assertBlockHeaderOK(self):
        blockinfo = await self._coin.block_header(self.txheight)
        self.assertListEqual(sorted(blockinfo.keys()),
                             ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']
                             )

    async def assertBlockHeadersOK(self):
        blockinfos = await alist(self._coin.block_headers(self.txheight))
        for blockinfo in blockinfos:
            self.assertListEqual(sorted(blockinfo.keys()),
            ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']
        )

    async def assertMerkleProofOK(self):
        tx = self.unspent[0]
        tx_hash = tx['tx_hash']
        proof = await self._coin.merkle_prove(self.unspent[0])
        self.assertDictEqual(dict(proof), {
            'tx_hash': tx_hash,
            'proven': True
        })

    async def assertSendMultiRecipientsTXOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0

        for i, addr in enumerate(self.addresses):
            addr_unspents = await self._coin.unspent(addr)
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

        result = await self._coin.send_to_multiple_receivers_tx(privkey, sender, outs, fee=self.fee)
        self.assertIsInstance(result, str)
        print("TX %s broadcasted successfully" % result)

    async def assertSendOK(self):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0

        for i, addr in enumerate(self.addresses):
            addr_unspents = await self._coin.unspent(addr)
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

        result = await self._coin.send(privkey, sender, receiver, send_value)
        self.assertIsInstance(result, str)
        print("TX %s broadcasted successfully" % result)

    async def assertSubscribeBlockHeadersOK(self):
        queue = asyncio.Queue()
        block_keys = ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']

        async def on_new_block(height: int, hex_header: str, header: BlockHeader) -> None:
            await queue.put((height, hex_header, header))

        await self._coin.subscribe_to_block_headers(on_new_block)
        result = await queue.get()
        height, hex_header, header = result
        self.assertGreater(height, self.min_latest_height)
        self.assertEqual(deserialize_header(binascii.unhexlify(hex_header)), header)
        self.assertListEqual(sorted(header.keys()), block_keys)
        await self._coin.unsubscribe_from_block_headers()

    async def assertSubscribeBlockHeadersSyncCallbackOK(self):
        queue = Queue()
        block_keys = ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']

        def on_new_block(height: int, hex_header: str, header: BlockHeader) -> None:
            queue.put_nowait((height, hex_header, header))

        await self._coin.subscribe_to_block_headers(on_new_block)
        result = await asyncio.get_event_loop().run_in_executor(None, queue.get)
        height, hex_header, header = result
        self.assertGreater(height, self.min_latest_height)
        self.assertEqual(deserialize_header(binascii.unhexlify(hex_header)), header)
        self.assertListEqual(sorted(header.keys()), block_keys)
        await self._coin.unsubscribe_from_block_headers()

    async def assertLatestBlockOK(self):
        height, hex_header, header = await self._coin.block
        self.assertGreater(height, self.min_latest_height)
        self.assertIsInstance(hex_header, str)
        self.assertIsInstance(header, dict)
        height, hex_header, header = await self._coin.block
        self.assertGreater(height, self.min_latest_height)
        self.assertIsInstance(hex_header, str)
        self.assertIsInstance(header, dict)

    async def assertConfirmationsOK(self):
        confirmations = await self._coin.confirmations(0)
        block = await self._coin.block
        height = block[0]
        self.assertEqual(confirmations, 0)
        confirmations = await self._coin.confirmations(height - 1)
        self.assertEqual(confirmations, 2)
        confirmations = await self._coin.confirmations(1)
        self.assertEqual(confirmations, height)

    async def assertSubscribeAddressOK(self):
        queue = asyncio.Queue()
        address = self.addresses[0]

        async def add_to_queue(addr: str, status: str) -> None:
            await queue.put((addr, status))

        await self._coin.subscribe_to_address(add_to_queue, address)
        addr, initial_status = await queue.get()
        self.assertEqual(addr, address)
        await self.assertTransactionOK()
        addr, status = await queue.get()
        self.assertEqual(addr, address)
        self.assertNotEqual(initial_status, status)
        await self._coin.unsubscribe_from_address(address)

    async def assertSubscribeAddressSyncCallbackOK(self):
        queue = Queue()
        address = self.segwit_addresses[0]

        def add_to_queue(addr: str, status: str) -> None:
            queue.put((addr, status))

        await self._coin.subscribe_to_address(add_to_queue, address)
        addr, initial_status = await asyncio.get_event_loop().run_in_executor(None, queue.get)
        self.assertEqual(addr, address)
        await self.assertSegwitTransactionOK()
        addr, status = await asyncio.get_event_loop().run_in_executor(None, queue.get)
        self.assertEqual(addr, address)
        self.assertNotEqual(initial_status, status)
        await self._coin.unsubscribe_from_address(address)

    async def assertSubscribeAddressTransactionsOK(self):
        queue = asyncio.Queue()
        address = self.addresses[0]

        async def add_to_queue(address: str, txs: List[Tx], newly_confirmed: List[Tx], history: List[Tx],
                               confirmed: int, unconfirmed: int, proven: int) -> None:
            await queue.put((address, txs, newly_confirmed, history, confirmed, unconfirmed, proven))

        await self._coin.subscribe_to_address_transactions(add_to_queue, address)
        addr, start_txs, start_newly_confirmed, start_history, start_confirmed, start_unconfirmed, start_proven = await queue.get()
        self.assertEqual(addr, address)
        self.assertEqual(start_txs, [])
        self.assertEqual(start_newly_confirmed, [])
        await self.assertSendOK()
        addr, new_txs, newly_confirmed, history, confirmed, unconfirmed, proven = await queue.get()
        self.assertEqual(addr, address)
        self.assertEqual(len(new_txs), 1)
        self.assertEqual(len(newly_confirmed), 0)
        self.assertGreaterEqual(len(history), 9)
        self.assertEqual(len(start_history), len(history))
        self.assertNotEqual(unconfirmed, start_unconfirmed)
        await self._coin.unsubscribe_from_address(address)

    async def assertSubscribeAddressTransactionsSyncOK(self):
        queue = Queue()
        address = self.addresses[0]

        def add_to_queue(address: str, txs: List[Tx], newly_confirmed: List[Tx], history: List[Tx],
                         confirmed: int, unconfirmed: int, proven: int) -> None:
            queue.put((address, txs, newly_confirmed, history, confirmed, unconfirmed, proven))

        await self._coin.subscribe_to_address_transactions(add_to_queue, address)
        addr, start_txs, start_newly_confirmed, start_history, start_confirmed, start_unconfirmed, start_proven = await asyncio.get_event_loop().run_in_executor(None, queue.get)
        self.assertEqual(addr, address)
        self.assertEqual(start_txs, [])
        self.assertEqual(start_newly_confirmed, [])
        await self.assertSendOK()
        addr, new_txs, newly_confirmed, history, confirmed, unconfirmed, proven = await asyncio.get_event_loop().run_in_executor(
            None, queue.get)
        self.assertEqual(addr, address)
        self.assertEqual(len(new_txs), 1)
        self.assertEqual(len(newly_confirmed), 0)
        self.assertGreaterEqual(len(history), 9)
        self.assertEqual(len(start_history), len(history))
        self.assertNotEqual(unconfirmed, start_unconfirmed)
        await self._coin.unsubscribe_from_address(address)
