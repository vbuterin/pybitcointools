import unittest

from cryptos import coins_async
from cryptos.main import privtopub
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.types import ElectrumXTx, TxOut
from cryptos.electrumx_client.types import ElectrumXMultiBalanceResponse
from typing import List, Type


class TestBitcoinCashTestnet(BaseAsyncCoinTestCase):
    name = "Bitcoin Cash Testnet"
    coin: Type[coins_async.BaseCoin] = coins_async.BitcoinCash
    addresses: List[str] = ["n2DQVQZiA2tVBDu4fNAjKVBS2RArWhfncv",
                            "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu",
                            "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    cash_addresses = ["bchtest:qr3sjptscfm7kqry6s67skm5dgsudwkmcsd7lhzflx",
                      "bchtest:qp83jwvlc8clct6vpskr8jhyayr8u7ynhqd4xj2gld",
                      "bchtest:qpp28cg6sze9la3myp6v28ghg5fjhn9m5yh0kd7ta6"]
    privkeys: List[str] = [
        "098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
        "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
        "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  # Private keys for above address_derivations in same order
    privkey_standard_wifs: List[str] = ['91f8DFTsmhtawuLjR8CiHNkgZGPkUqfJ45LxmENPf3k6fuX1m4N',
                                       'cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f',
                                       "9354Dkk67pJCfmRfMedJPhGPfZCXv2uWd9ZoVNMUtDxjUBbCVZK"]
    multisig_addresses: List[str] = ["2MvmK6SRDc13BaYbumBbtkCH2fKbViC5XEv", "2MtT7kkzRDn1kiT9GZoS1zSgh7twP145Qif"]
    cash_multisig_addresses: List[str] = ["bchtest:pqnfj8jmtpj30fnjgc2gy0gs4l6sptdyhcr8c3e5nk",
                                          "bchtest:pqxn06syr9twx9ecx892alre33yuuwn2gu6stxug97"]
    fee: int = 1000
    max_fee: int = 3500
    testnet: bool = True

    min_latest_height: int = 1524427
    unspent_addresses: List[str] = ["ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"]
    unspent_cash_addresses: List[str] = ['bchtest:qpl9sk4pjy70zt5efr5s7ecc3m5j2r242c4czjmhfy']
    unspent: List[ElectrumXTx] = [{'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA',
                                   'height': 1196454,
                                   'tx_hash': '80700e6d1125deafa22b307f6c7c99e75771f9fc05517fc795a1344eca7c8472',
                                   'tx_pos': 0,
                                   'value': 550000000}]
    unspents: List[ElectrumXTx] = unspent
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 550000000, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [{'address': unspent_addresses[0]} | dict(balance)]
    history: List[ElectrumXTx] = [{'height': 1196454, 'tx_hash': '80700e6d1125deafa22b307f6c7c99e75771f9fc05517fc795a1344eca7c8472'}]
    histories: List[ElectrumXTx] = [{'address': unspent_addresses[0]} | dict(history[0])]
    txid: str = "b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a"
    txheight: int = 1196454
    block_hash: str = "000000002bab447cbd0c60829a80051e320aa6308d578db3369eb85b2ebb9f46"
    txinputs: List[TxOut] = [{'output': "cbd43131ee11bc9e05f36f55088ede26ab5fb160cc3ff11785ce9cc653aa414b:1", 'value': 96190578808}]
    raw_tx: str = "01000000014b41aa53c69cce8517f13fcc60b15fab26de8e08556ff3059ebc11ee3131d4cb010000006b483045022100b9050a1d58f36a771c4e0869900fb0474b809b134fdad566742e5b3a0ed7580d022065b80e9cc2bc9b921a9b0aad12228d9967345959b021214dbe60b3ffa44dbf0e412102ae83c12f8e2a686fb6ebb25a9ebe39fcd71d981cc6c172fedcdd042536a328f2ffffffff0200ab9041000000001976a914c384950342cb6f8df55175b48586838b03130fad88acd88ed523160000001976a9143479daa7de5c6d8dad24535e648861d4e7e3f7e688ac00000000"

    def test_address_conversion(self):
        for addr, cashaddr in zip(self.addresses, self.cash_addresses):
            convert_cashaddr = self._coin.legacy_addr_to_cash_address(addr)
            self.assertEqual(convert_cashaddr, cashaddr)
            convert_addr = self._coin.cash_address_to_legacy_addr(cashaddr)
            self.assertEqual(addr, convert_addr)

    def test_cash_address_multisig_ok(self):
        pubs = [privtopub(priv) for priv in self.privkeys]
        script1, address1 = self._coin.mk_multsig_cash_address(*pubs, num_required=2)
        self.assertEqual(address1, self.cash_multisig_addresses[0])
        pubs2 = pubs[0:2]
        script2, address2 = self._coin.mk_multsig_cash_address(*pubs2)
        self.assertEqual(address2, self.cash_multisig_addresses[1])

    def test_address_conversion_multisig(self):
        for addr, cashaddr in zip(self.multisig_addresses, self.cash_multisig_addresses):
            convert_cashaddr = self._coin.legacy_addr_to_cash_address(addr)
            self.assertEqual(convert_cashaddr, cashaddr)
            convert_addr = self._coin.cash_address_to_legacy_addr(cashaddr)
            self.assertEqual(addr, convert_addr)

    def test_standard_wif_ok(self):
        self.assertStandardWifOK()
        for privkey, addr in zip(self.privkeys, self.cash_addresses):
            cash_addr = self._coin.privtocashaddress(privkey)
            self.assertEqual(cash_addr, addr)

    async def test_balance(self):
        await self.assertBalanceOK()

    async def test_balance_cash_address(self):
        result = await self._coin.get_balance(self.unspent_cash_addresses[0])
        self.assertEqual(self.balance, result)

    async def test_balances(self):
        await self.assertBalancesOK()

    async def test_unspent(self):
        await self.assertUnspentOK()

    async def test_unspents(self):
        await self.assertUnspentsOK()

    async def test_merkle_proof(self):
        await self.assertMerkleProofOK()

    async def test_history(self):
        await self.assertHistoryOK()

    async def test_histories(self):
        await self.assertHistoriesOK()

    async def test_block_header(self):
        await self.assertBlockHeaderOK()

    async def test_block_headers(self):
        await self.assertBlockHeadersOK()

    async def test_gettx(self):
        await self.assertGetTXOK()

    @unittest.skip('Intermittent failures')
    async def test_getverbosetx(self):
        await self.assertGetVerboseTXOK()

    async def test_gettxs(self):
        await self.assertGetTxsOK()

    async def test_balance_merkle_proven(self):
        await self.assertBalanceMerkleProvenOK()

    async def test_balances_merkle_proven(self):
        await self.assertBalancesMerkleProvenOK()

    async def test_transaction(self):
        """
        Sample transaction:
        TxID: d4e8e93ba458c675270a5e6ac6772e35356ec95c37f8de6eb4a7a74103ecac8a
        """
        await self.assertTransactionOK()

    async def test_transaction_cash_address(self):
        """
        Sample transaction:
        TxID: 1ec96ce25a0104cda556f16d0d630768308a6b14dd35363dabe62fa96aa3237a
        """
        await self.assertCashAddressTransactionOK()

    async def test_transaction_multisig(self):
        """
        Sample transaction:
        TxID: c8987d59357f108fff46837b9309b28a1dc91d0fa4daa2c2f515107f61943a05
        """
        await self.assertMultiSigTransactionOK()

    async def test_transaction_multisig_cash_address(self):
        """
        Sample transaction:
        TxID: eb8a0ad9434786bfe69c992f286cbe391c4845058ae130f8a35e205e3280c6d4
        """
        await self.assertCashAddressMultiSigTransactionOK()

    async def test_sendmulti_recipient_tx(self):
        """
        Sample transaction:
        TxID: 49a731c4eaae1c6570590cd3eb5f4af4d4f6b282186b368b574169e9a7d576ab
        """
        await self.assertSendMultiRecipientsTXOK()

    async def test_send(self):
        """
        Sample transaction:
        TxID: ae9dd16e61521791659080c58299937a5d0ac2d20608e8bc1f494a08f6d9f5fb
        """
        await self.assertSendOK()

    async def test_subscribe_block_headers(self):
        await self.assertSubscribeBlockHeadersOK()

    async def test_subscribe_block_headers_sync(self):
        await self.assertSubscribeBlockHeadersSyncCallbackOK()

    async def test_latest_block(self):
        await self.assertLatestBlockOK()

    async def test_confirmations(self):
        await self.assertConfirmationsOK()

    async def test_subscribe_address(self):
        await self.assertSubscribeAddressOK()

    async def test_subscribe_address_sync(self):
        await self.assertSubscribeAddressSyncCallbackOK()

    async def test_subscribe_address_transactions(self):
        await self.assertSubscribeAddressTransactionsOK()

    async def test_subscribe_address_transactions_sync(self):
        await self.assertSubscribeAddressTransactionsSyncOK()
