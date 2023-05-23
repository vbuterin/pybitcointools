import unittest
import asyncio
from queue import Queue
from operator import itemgetter
from cryptos import *
from cryptos import coins_async
from cryptos.utils import alist
from cryptos.types import Tx, TxOut
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse, ElectrumXUnspentResponse
from typing import AsyncGenerator, Any, Union, List, Optional, Type


class BaseAsyncCoinTestCase(unittest.IsolatedAsyncioTestCase):
    name: str = ""
    coin: Type[coins_async.BaseCoin] = coins_async.Bitcoin
    addresses: List[str] = []
    segwit_addresses: List[str] = []
    native_segwit_addresses: List[str] = []
    multisig_addresses: List[str] = []
    cash_multisig_addresses: List[str] = []
    native_segwit_multisig_addresses: List[str] = []
    cash_addresses: List[str] = []

    fee: int = 500
    max_fee: int = 3500
    testnet: bool = True
    min_latest_height: int = 99999999999

    unspent_addresses: List[str] = []
    unspent: List[ElectrumXTx] = []
    unspents: List[ElectrumXTx] = []

    txheight: int = None
    privkeys: List[str] = []     # Private keys for above addresses in same order
    privkey_standard_wifs: List[str] = []
    privkey_segwit_wifs: List[str] = []
    privkey_native_segwit_wifs: List[str] = []
    txid: str = None
    txinputs: List[TxOut] = None
    block_hash: str = None

    balance: ElectrumXMultiBalanceResponse = {}
    balances: List[ElectrumXMultiBalanceResponse] = []
    history: List[ElectrumXTx] = {}
    histories: List[ElectrumXTx] = []
    raw_tx: str = ''
    expected_tx_verbose_keys: List[str] = [
        'blockhash', 'blocktime', 'confirmations', 'hash', 'hex', 'locktime', 'size', 'time', 'txid',
        'version', 'vin', 'vout']

    @classmethod
    def setUpClass(cls):
        print('Starting %s tests' % cls.name)

    def setUp(self) -> None:
        self._coin = self.coin(testnet=self.testnet, connection_timeout=100)

    async def asyncTearDown(self) -> None:
        await self._coin.close()

    def assertUnorderedListEqual(self, list1, list2, key):
        list1 = sorted(list1, key=itemgetter(key))
        list2 = sorted(list2, key=itemgetter(key))
        self.assertEqual(list1, list2)

    async def mock_electrumx_send_request(self, method: str, args=(),
                                          **kwargs) -> Optional[Union[float, ElectrumXUnspentResponse, str, List[str]]]:
        if method == "blockchain.scripthash.listunspent":
            scripthash = args[0]
            available_addresses = [addresses[0] for addresses in (
                self.addresses, self.segwit_addresses, self.native_segwit_addresses,
                self.multisig_addresses, self.cash_addresses, self.native_segwit_multisig_addresses,
                [privtopub(p) for p in self.privkeys]
            ) if addresses]
            if any(scripthash == self._coin.addrtoscripthash(address) for address in
                   available_addresses):
                return deepcopy(self.unspent)
            return []
        if method == "blockchain.transaction.broadcast":
            tx = args[0]
            tx_hash = public_txhash(
                tx
            )
            return tx_hash
        elif method == "server.version":
            return ["ElectrumX 1.16.0", "1.4"]
        elif method == "server.ping":
            return None
        elif method == "blockchain.estimatefee":
            return 1e-05

    @property
    def tx(self) -> Tx:
        return deserialize(self.raw_tx)

    def assertStandardWifOK(self):
        for privkey, expected_wif, address in zip(self.privkeys, self.privkey_standard_wifs, self.addresses):
            frmt = get_privkey_format(privkey)
            wif_format = "wif_compressed" if "compressed" in frmt else "wif"
            wif = self._coin.encode_privkey(privkey, formt=wif_format)
            self.assertEqual(wif, expected_wif)
            self.assertEqual(self._coin.privtop2pkh(privkey), address)
            self.assertEqual(self._coin.privtop2pkh(wif), address)
            self.assertEqual(self._coin.privtoaddr(privkey), address)
            self.assertEqual(self._coin.privtoaddr(wif), address)
            self.assertEqual(self._coin.pubtoaddr(privtopub(privkey)), address)
            self.assertEqual(self._coin.pubtoaddr(privtopub(wif)), address)
            self.assertTrue(self._coin.is_p2pkh(address))
            self.assertTrue(self._coin.is_address(address))
            self.assertFalse(self._coin.is_p2sh(address))
            if self._coin.segwit_supported:
                self.assertFalse(self._coin.is_native_segwit(address))

    def assertP2WPKH_P2SH_WifOK(self):
        for privkey, expected_wif, address in zip(self.privkeys, self.privkey_segwit_wifs, self.segwit_addresses):
            wif = self._coin.encode_privkey(privkey, formt="wif_compressed", script_type="p2wpkh-p2sh")
            self.assertEqual(wif, expected_wif)
            self.assertEqual(self._coin.privtop2wpkh_p2sh(privkey), address)
            self.assertEqual(self._coin.privtop2wpkh_p2sh(wif), address)
            self.assertEqual(self._coin.privtoaddr(wif), address)
            self.assertEqual(self._coin.pubtop2wpkh_p2sh(privtopub(privkey)), address)
            self.assertEqual(self._coin.pubtop2wpkh_p2sh(privtopub(wif)), address)
            self.assertTrue(self._coin.is_p2sh(address))
            self.assertTrue(self._coin.is_address(address))
            self.assertFalse(self._coin.is_p2pkh(address))
            self.assertFalse(self._coin.is_native_segwit(address))

    def assertP2WPKH_WIFOK(self):
        for privkey, expected_wif, address in zip(self.privkeys, self.privkey_native_segwit_wifs, self.native_segwit_addresses):
            wif = self._coin.encode_privkey(privkey, formt="wif_compressed", script_type="p2wpkh")
            self.assertEqual(wif, expected_wif)
            self.assertEqual(self._coin.privtosegwitaddress(privkey), address)
            self.assertEqual(self._coin.privtosegwitaddress(wif), address)
            self.assertEqual(self._coin.privtoaddr(wif), address)
            self.assertEqual(self._coin.pubtosegwitaddress(privtopub(privkey)), address)
            self.assertEqual(self._coin.pubtosegwitaddress(privtopub(wif)), address)
            self.assertTrue(self._coin.is_native_segwit(address))
            self.assertTrue(self._coin.is_address(address))
            self.assertFalse(self._coin.is_p2sh(address))
            self.assertFalse(self._coin.is_p2pkh(address))

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

    async def assertMixedSegwitTransactionOK(self, expected_tx_id: str = None):

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
        fee = self.fee if expected_tx_id else None
        tx = await self._coin.mktx_with_change(unspents, outs, change_addr=change_address, fee=fee)

        segwit_privkey = self.privkeys[segwit_from_addr_i]
        regular_privkey = self.privkeys[regular_from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(segwit_sender, self._coin.privtop2wpkh_p2sh(segwit_privkey),
                         msg=f"Private key does not belong to address {segwit_sender} on {self._coin.display_name}")
        self.assertEqual(regular_sender, self._coin.privtoaddr(regular_privkey),
                         msg=f"Private key does not belong to address {regular_sender} on {self._coin.display_name}")

        self.assertTrue(self._coin.is_segwit_or_p2sh(segwit_sender))
        self.assertFalse(self._coin.is_segwit_or_p2sh(regular_sender))

        # Sign each input with the given private keys
        # Try signing one at a time and also with signall and make sure they give the same result

        tx2 = deepcopy(tx)

        for i in range(0, len(segwit_unspents)):
            tx = self._coin.sign(tx, i, segwit_privkey)
        for i in range(len(segwit_unspents), len(unspents)):
            tx = self._coin.sign(tx, i, regular_privkey)

        tx2 = self._coin.signall(tx2, {segwit_sender: segwit_privkey, regular_sender: regular_privkey})

        self.assertDictEqual(dict(tx), dict(tx2))
        self.assertEqual(serialize(tx), serialize(tx2))

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
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
        # Push the transaction to the network
        result = await self._coin.pushtx(tx)

        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)    # mainnet
        else:
            self.assertTXResultOK(tx, result)           # testnet
            await asyncio.wait([
                asyncio.create_task(self._coin.wait_unspents_changed(regular_sender, unspents)),
                asyncio.create_task(self._coin.wait_unspents_changed(segwit_sender, unspents))
                ], timeout=3.5)

    async def assertSegwitTransactionOK(self, expected_tx_id: str = None):

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
        fee = self.fee if expected_tx_id else None
        tx = await self._coin.mktx_with_change(unspents, outs, change_addr=change_address, fee=fee)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtop2wpkh_p2sh(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
        self.assertGreaterEqual(fee, self._coin.minimum_fee)
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

        deserialize(serialize(tx))
        result = await self._coin.pushtx(tx)

        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)    # mainnet
        else:
            self.assertTXResultOK(tx, result)
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 3.5)

    async def assertNativeSegwitTransactionOK(self, expected_tx_id: str = None):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.native_segwit_addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.native_segwit_addresses):
            addr_unspents = await self._coin.unspent(addr)
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
        unspents = select(unspents, outs[0]['value'] + self.max_fee)
        fee = self.fee if expected_tx_id else None
        tx = await self._coin.mktx_with_change(unspents, outs, change_addr=change_address, fee=fee)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtosegwitaddress(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
        self.assertGreater(fee, 0)
        self.assertGreaterEqual(fee, self._coin.minimum_fee)
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
            self.assertGreaterEqual(len(script), 44)
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
        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)    # mainnet
        else:
            self.assertTXResultOK(tx, result)           # testnet
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 3.5)

    async def assertCashAddressTransactionOK(self, expected_tx_id: str = None):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.cash_addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.cash_addresses):
            addr_unspents = await self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        # Arbitrarily set send value, change value, receiver and change address
        send_value = int(max_value * 0.1)

        if sender == self.cash_addresses[0]:
            receiver = self.cash_addresses[1]
            change_address = self.cash_addresses[2]
        elif sender == self.cash_addresses[1]:
            receiver = self.cash_addresses[2]
            change_address = self.cash_addresses[0]
        else:
            receiver = self.cash_addresses[0]
            change_address = self.cash_addresses[1]

        outs = [{'value': send_value, 'address': receiver}]

        # Create the transaction using all available unspents as inputs
        unspents = select(unspents, outs[0]['value'] + self.max_fee)
        fee = self.fee if expected_tx_id else None
        tx = await self._coin.mktx_with_change(unspents, outs, change_addr=change_address, fee=fee)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtocashaddress(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
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
        result = await self._coin.pushtx(tx)
        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)  # mainnet
        else:
            self.assertTXResultOK(tx_serialized, result)  # testnet
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 3.5)


    def assertTXResultOK(self, tx: Union[str, Tx], result):
        if not isinstance(tx, str):
            tx = serialize(tx)
        tx_hash = public_txhash(tx)
        self.assertEqual(result, tx_hash)
        print("TX %s broadcasted successfully" % result)

    async def assertTransactionOK(self, expected_tx_id: str = None):

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

        fee = self.fee if expected_tx_id else None
        tx = await self._coin.mktx_with_change(unspents, outs, change_addr=change_address, fee=fee)

        privkey = self.privkeys[from_addr_i]

        # Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, self._coin.privtoaddr(privkey),
                         msg=f"Private key does not belong to address {sender} on {self._coin.display_name}")

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
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
        result = await self._coin.pushtx(tx)
        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)        # mainnet
        else:
            self.assertTXResultOK(tx_serialized, result)       # testnet
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 0.5)

    async def assertTransactionToPKOK(self, expected_tx_id: str = None):

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        pub_keys = [privtopub(priv) for priv in self.privkeys]
        sender = pub_keys[0]
        from_addr_i = 0
        unspents = []

        for i, pub in enumerate(pub_keys):
            addr_unspents = await self._coin.unspent(pub)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = pub
                from_addr_i = i
                unspents = addr_unspents

        # Arbitrarily set send value, receiver and change address
        send_value = int(max_value * 0.1)

        if sender == pub_keys[0]:
            receiver = pub_keys[1]
            change_address = pub_keys[2]
        elif sender == pub_keys[1]:
            receiver = pub_keys[2]
            change_address = pub_keys[0]
        else:
            receiver = pub_keys[0]
            change_address = pub_keys[1]

        outs = [{'value': send_value, 'address': receiver}]

        # Create the transaction using all available unspents as inputs
        fee = self.fee if expected_tx_id else None
        tx = await self._coin.mktx_with_change(unspents, outs, change_addr=change_address, fee=fee)

        privkey = self.privkeys[from_addr_i]

        # Sign each input with the given private key
        tx = self._coin.signall(tx, privkey)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
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
            self.assertTrue(any(val == len(script) for val in (70, 134)))
            prev_script = script

        # Serialize and push the transaction to the network
        tx_serialized = serialize(tx)
        result = await self._coin.pushtx(tx)
        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)        # mainnet
        else:
            self.assertTXResultOK(tx_serialized, result)       # testnet
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 0.5)

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
        self.assertListEqual(list(tx.keys()), ['ins', 'outs', 'version', 'locktime'])
        self.assertEqual(tx, self.tx)

    async def assertGetTxsOK(self):
        txs = await alist(self._coin.get_txs(self.txid))
        self.assertListEqual(list(txs[0].keys()),
                             ['ins', 'outs', 'version',  'locktime'])

    async def assertGetSegwitTXOK(self):
        tx = await self._coin.get_tx(self.txid)
        self.assertListEqual(list(tx.keys()), ['ins', 'outs', 'version', 'marker', 'flag', 'witness', 'locktime'])
        self.assertEqual(tx, self.tx)

    async def assertGetVerboseTXOK(self):
        tx = await self._coin.get_verbose_tx(self.txid)
        for key in ('height', 'vsize', 'weight'):
            if key in tx:
                self.expected_tx_verbose_keys.append(key)
        self.assertListEqual(sorted(tx.keys()), sorted(self.expected_tx_verbose_keys))

    async def assertTxsOK(self):
        txs = await alist(self._coin.get_txs(self.txid))
        self.assertListEqual(list(txs[0].keys()),
                             ['ins', 'outs', 'version', 'locktime'])

    async def assertGetSegwitTxsOK(self):
        txs = await alist(self._coin.get_txs(self.txid))
        self.assertListEqual(list(txs[0].keys()),
                             ['ins', 'outs', 'version', 'marker', 'flag', 'witness', 'locktime'])

    async def assertMultiSigTransactionOK(self, expected_tx_id: str = None):
        pubs = [privtopub(priv) for priv in self.privkeys]
        script1, address1 = self._coin.mk_multisig_address(*pubs, num_required=2)
        self.assertEqual(address1, self.multisig_addresses[0])
        pubs2 = pubs[0:2]
        script2, address2 = self._coin.mk_multisig_address(*pubs2)
        self.assertEqual(address2, self.multisig_addresses[1])

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = None
        unspents = []

        for i, addr in enumerate(self.multisig_addresses):
            addr_unspents = await self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                unspents = addr_unspents

        self.assertGreater(max_value, 0)

        # Arbitrarily set send value, receiver and change address
        send_value = int(max_value * 0.5)

        receiver, script = (address2, script1) if sender == address1 else (address1, script2)

        fee = self.fee

        tx = await self._coin.preparetx(sender, receiver, send_value, fee)

        for i in range(0, len(tx['ins'])):
            if sender == address1:
                sig1 = self._coin.multisign(tx, i, script, self.privkeys[0])
                sig3 = self._coin.multisign(tx, i, script, self.privkeys[2])
                tx = self._coin.apply_multisignatures(tx, i, script, sig1, sig3)
            else:
                sig1 = self._coin.multisign(tx, i, script2, self.privkeys[0])
                sig2 = self._coin.multisign(tx, i, script2, self.privkeys[1])
                tx = self._coin.apply_multisignatures(tx, i, script, sig1, sig2)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
        self.assertGreaterEqual(fee, self._coin.minimum_fee)
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
        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)    # mainnet
        else:
            self.assertTXResultOK(tx, result)           # testnet
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 4.5)

    async def assertNativeSegwitMultiSigTransactionOK(self, expected_tx_id: str = None):
        pubs = [privtopub(priv) for priv in self.privkeys]
        script1, address1 = self._coin.mk_multsig_segwit_address(*pubs, num_required=2)
        self.assertEqual(address1, self.native_segwit_multisig_addresses[0])
        pubs2 = pubs[0:2]
        script2, address2 = self._coin.mk_multsig_segwit_address(*pubs2)
        self.assertEqual(address2, self.native_segwit_multisig_addresses[1])

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = None
        unspents = []

        for i, addr in enumerate(self.native_segwit_multisig_addresses):
            addr_unspents = await self._coin.unspent(addr)

            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                unspents = addr_unspents

        self.assertGreater(max_value, 0)
        # Arbitrarily set send value, receiver and change address
        send_value = int(max_value * 0.1)

        receiver, script = (address2, script1) if sender == address1 else (address1, script2)

        fee = self.fee if expected_tx_id else None

        tx = await self._coin.preparetx(sender, receiver, send_value, fee=fee)

        for i in range(0, len(tx['ins'])):
            if sender == address1:
                sig1 = self._coin.multisign(tx, i, script, self.privkeys[0])
                sig3 = self._coin.multisign(tx, i, script, self.privkeys[2])
                tx = self._coin.apply_multisignatures(tx, i, script, sig1, sig3)
            else:
                sig1 = self._coin.multisign(tx, i, script, self.privkeys[0])
                sig2 = self._coin.multisign(tx, i, script, self.privkeys[1])
                tx = self._coin.apply_multisignatures(tx, i, script, sig1, sig2)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
        self.assertGreaterEqual(fee, self._coin.minimum_fee)
        self.assertGreaterEqual(len(tx['ins']), 1)
        self.assertEqual(len(tx['outs']), 2)
        self.assertEqual(tx['marker'], 0)
        self.assertEqual(tx['flag'], 1)
        self.assertEqual(len(tx['witness']), len(tx['ins']))

        prev_script = None

        for inp in tx['ins']:
            script = inp['script']
            # self.assertEqual(script, '')

        for o in tx['outs']:
            script = o['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            self.assertGreaterEqual(len(script), 44)
            prev_script = script

        prev_script_code = None
        for w in tx['witness']:
            self.assertEqual(w['number'], 4)
            script_code = w['scriptCode']
            if prev_script_code:
                self.assertNotEqual(script_code, prev_script_code)
            self.assertIsInstance(script_code, str)
            self.assertNotEqual(script_code, '')
            prev_script_code = script_code

        prev_script = None

        for inp in tx['ins']:
            script = inp['script']
            if prev_script:
                self.assertNotEqual(script, prev_script)
            self.assertIsInstance(script, str)
            # self.assertEqual(script, '')
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
        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)    # mainnet
        else:
            self.assertTXResultOK(tx, result)           # testnet
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 3.5)


    async def assertCashAddressMultiSigTransactionOK(self, expected_tx_id: str = None):
        pubs = [privtopub(priv) for priv in self.privkeys]
        script1, address1 = self._coin.mk_multsig_cash_address(*pubs, num_required=2)
        self.assertEqual(address1, self.cash_multisig_addresses[0])
        pubs2 = pubs[0:2]
        script2, address2 = self._coin.mk_multsig_cash_address(*pubs2)
        self.assertEqual(address2, self.cash_multisig_addresses[1])

        # Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = None
        unspents = []

        for i, addr in enumerate(self.cash_multisig_addresses):
            addr_unspents = await self._coin.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                unspents = addr_unspents

        self.assertGreater(max_value, 0)

        # Arbitrarily set send value, receiver and change address
        send_value = int(max_value * 0.5)

        receiver, script = (address2, script1) if sender == address1 else (address1, script2)

        fee = self.fee

        tx = await self._coin.preparetx(sender, receiver, send_value, fee)

        for i in range(0, len(tx['ins'])):
            if sender == address1:
                sig1 = self._coin.multisign(tx, i, script, self.privkeys[0])
                sig3 = self._coin.multisign(tx, i, script, self.privkeys[2])
                tx = self._coin.apply_multisignatures(tx, i, script, sig1, sig3)
            else:
                sig1 = self._coin.multisign(tx, i, script2, self.privkeys[0])
                sig2 = self._coin.multisign(tx, i, script2, self.privkeys[1])
                tx = self._coin.apply_multisignatures(tx, i, script, sig1, sig2)

        self.assertEqual(tx['locktime'], 0)
        self.assertEqual(tx['version'], 1)
        fee = await self._coin.calculate_fee(tx)
        self.assertGreaterEqual(fee, self.coin.minimum_fee)
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
        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)    # mainnet
        else:
            self.assertTXResultOK(tx, result)           # testnet
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 2.5)

    async def assertBlockHeaderOK(self):
        blockinfo = await self._coin.block_header(self.txheight)
        block_hash = hexlify(blockinfo['hash']).decode()
        self.assertListEqual(sorted(blockinfo.keys()),
                             ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']
                             )
        self.assertEqual(block_hash, self.block_hash)

    async def assertBlockHeadersOK(self):
        blockinfos = await alist(self._coin.block_headers(self.txheight))
        for blockinfo in blockinfos:
            self.assertListEqual(sorted(blockinfo.keys()),
                ['bits', 'hash', 'merkle_root', 'nonce', 'prevhash', 'timestamp', 'version']
            )
            block_hash = hexlify(blockinfo['hash']).decode()
            self.assertEqual(block_hash, self.block_hash)

    async def assertMerkleProofOK(self):
        tx = self.unspent[0]
        tx_hash = tx['tx_hash']
        proof = await self._coin.merkle_prove(self.unspent[0])
        self.assertDictEqual(dict(proof), {
            'tx_hash': tx_hash,
            'proven': True
        })

    async def assertSendMultiRecipientsTXOK(self, expected_tx_id: str = None):

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

        privkey = self.privkeys[from_addr_i]

        # Arbitrarily set send value, change value, receiver and change address
        fee = self.fee

        outputs_value = max_value - fee
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

        result = await self._coin.send_to_multiple_receivers_tx(privkey, sender, outs, fee=fee)

        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)            # mainnet
        else:
            self.assertIsInstance(result, str)                  # testnet
            print("TX %s broadcasted successfully" % result)
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 3.5)

    async def assertSendOK(self, expected_tx_id: str = None):

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

        privkey = self.privkey_standard_wifs[from_addr_i]

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
        if expected_tx_id:
            self.assertEqual(result, expected_tx_id)    # mainnet
        else:
            self.assertIsInstance(result, str)  # testnet
            print("TX %s broadcasted successfully" % result)
            await asyncio.wait_for(self._coin.wait_unspents_changed(sender, unspents), 10)

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
        try:
            address = self.segwit_addresses[0]
        except IndexError:
            try:
                address = self.cash_addresses[0]
            except IndexError:
                address = self.addresses[0]


        def add_to_queue(addr: str, status: str) -> None:
            queue.put((addr, status))

        await self._coin.subscribe_to_address(add_to_queue, address)
        addr, initial_status = await asyncio.get_event_loop().run_in_executor(None, queue.get)
        self.assertEqual(addr, address)
        if self.segwit_addresses:
            await self.assertSegwitTransactionOK()
        elif self.cash_addresses:
            await self.assertCashAddressTransactionOK()
        else:
            await self.assertTransactionOK()
        addr, status = await asyncio.get_event_loop().run_in_executor(None, queue.get)
        self.assertEqual(addr, address)
        self.assertNotEqual(initial_status, status)
        await self._coin.unsubscribe_from_address(address)

    async def assertSubscribeAddressTransactionsOK(self):
        queue = asyncio.Queue()
        address = self.addresses[0]

        async def add_to_queue(address: str, txs: List[Tx], newly_confirmed: List[Tx], history: List[Tx],
                               unspent: List[Tx], confirmed: int, unconfirmed: int, proven: int) -> None:
            await queue.put((address, txs, newly_confirmed, history, unspent, confirmed, unconfirmed, proven))

        await self._coin.subscribe_to_address_transactions(add_to_queue, address)
        addr, start_txs, start_newly_confirmed, start_history, unspent, start_confirmed, start_unconfirmed, start_proven = await queue.get()
        self.assertEqual(addr, address)
        self.assertEqual(start_txs, [])
        self.assertEqual(start_newly_confirmed, [])
        await self.assertTransactionOK()
        addr, new_txs, newly_confirmed, history, unspent, confirmed, unconfirmed, proven = await queue.get()
        self.assertEqual(addr, address)
        self.assertGreaterEqual(len(new_txs), 1)
        self.assertEqual(len(newly_confirmed), 0)
        self.assertGreaterEqual(len(history), 1)
        self.assertEqual(len(start_history), len(history))
        self.assertNotEqual(unconfirmed, start_unconfirmed)
        await self._coin.unsubscribe_from_address(address)

    async def assertSubscribeAddressTransactionsSyncOK(self):
        queue = Queue()
        address = self.addresses[0]

        def add_to_queue(address: str, txs: List[Tx], newly_confirmed: List[Tx], history: List[Tx],
                         unspent: List[Tx], confirmed: int, unconfirmed: int, proven: int) -> None:
            queue.put((address, txs, newly_confirmed, history, unspent, confirmed, unconfirmed, proven))

        await self._coin.subscribe_to_address_transactions(add_to_queue, address)
        addr, start_txs, start_newly_confirmed, start_history, start_unspent, start_confirmed, start_unconfirmed, start_proven = await asyncio.get_event_loop().run_in_executor(None, queue.get)
        self.assertEqual(addr, address)
        self.assertEqual(start_txs, [])
        self.assertEqual(start_newly_confirmed, [])
        await self.assertTransactionOK()
        addr, new_txs, newly_confirmed, history, unspent, confirmed, unconfirmed, proven = await asyncio.get_event_loop().run_in_executor(
            None, queue.get)
        self.assertEqual(addr, address)
        self.assertGreaterEqual(len(new_txs), 1)
        self.assertEqual(len(newly_confirmed), 0)
        self.assertGreaterEqual(len(history), 1)
        self.assertEqual(len(start_history), len(history))
        self.assertNotEqual(unconfirmed, start_unconfirmed)
        await self._coin.unsubscribe_from_address(address)
