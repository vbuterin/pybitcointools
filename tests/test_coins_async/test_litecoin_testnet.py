import unittest

from cryptos import coins_async
from cryptos.main import privtopub, compress
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.types import ElectrumXTx, TxOut
from cryptos.electrumx_client.types import ElectrumXMultiBalanceResponse
from typing import List


class TestLitecoinTestnet(BaseAsyncCoinTestCase):
    name = "Litecoin Testnet"
    coin = coins_async.Litecoin
    addresses: List[str] = ["n2DQVQZiA2tVBDu4fNAjKVBS2RArWhfncv",
                            "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu",
                            "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_addresses: List[str] = ["QaRdhvUtEt5vnU1MXUhK8JT1wLqS7Y29Ua",
                                  "QhAx5qBJphxMrSZfwzaf8KyP9T2DrAMbiC",
                                  "QMPRBmeVuqPf8KxYeF9ANdVKh6cNTePk7W"]
    native_segwit_addresses: List[str] = [
        "tltc1q95cgql39zvtc57g4vn8ytzmlvtt43skn39z3vs",
        "tltc1qfuvnn87p787z7nqv9seu4e8fqel83yac3kxh62",
        "tltc1qst3pkm860tjt9y70ugnaluqyqnfa7h54q7xv2n"]
    multisig_addresses: List[str] = ["QQ85DTHTd76GijMxPHduptiToi3KbZFpcw",
                                     "QMossmrfEt4qrduKBuU35988GHPCtUY4ZQ"]
    native_segwit_multisig_addresses: List[str] = [
        "tltc1q7e42a8gmgp5d7kw8myrruj5qnxp8edp7v5y0y95hrjz6t530uehqf3n2q4",
        "tltc1qu7fz4uku8kh6tg7qghj7rnf88g858lal258gzfu85kx7vc5h0qpsm9lgv7"
    ]
    # Private keys for above addresses in same order
    privkeys = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    privkey_standard_wifs: List[str] = ['7QMPk7vLsHRiUXSsuJQkVyyWbnqHH3DGHPwo43MMwbRUz7o9yLi',
                                       'VG2jGVfRhLNtN6HHohBYJo9tGXVgJcbyWPjBHPDJrbqRYtCsGKDb',
                                       "7RmKkdCZDPqLCPXoqpqLcJVDi5e4iETUrUAdnBLTAme7nJDsayK"]
    privkey_segwit_wifs: List[str] = ['VZEGXeGF3FLN1XQkmzdcbGfQ9RhQWdJanFX7PL54QvSV5Qcy4Stv',
                                       'VZBzQpPE3eDAK8JpuqyKu9LrmPtyyT9RqGySQHuVqZLr7YZusmsc',
                                       "VfTtusVoY1cbgJUWrev99ANXbBsu3pwLGE9nTKK3V5YFVHKwMvh4"]
    privkey_native_segwit_wifs: List[str] = ["VQedxUuLs6RE31PzDvEio6ZutzVkgD2rcotypsixvSgmo5QjrRhM",
                                             "VQcMqf2KsVJ2LcJ4MmaS6yFNWxhL92shfqMJqqZQM5b8qDNnGqBj",
                                             "VWtGLi8uMrhThnTkJaXFLzH3LkgFDQfc6nXetrxwzbnYCxAXw4MK"]
    fee: int = 2000
    max_fee: int = 4000
    testnet: bool = True

    min_latest_height: int = 2391524
    unspent_addresses: List[str] = ["ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"]
    unspent: List[ElectrumXTx] = [{'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA',
                                   'height': 296481,
                                   'tx_hash': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19',
                                   'tx_pos': 1,
                                   'value': 100000000}]
    unspents: List[ElectrumXTx] = unspent
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 100000000, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [{'address': unspent_addresses[0]} | dict(balance)]
    history: List[ElectrumXTx] = [{'height': 296481, 'tx_hash': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19'}]
    histories: List[ElectrumXTx] = [{'address': unspent_addresses[0]} | dict(history[0])]
    txid: str = "2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93"
    txheight: int = 296568
    block_hash: str = "9c557ffb695078e9f79d92b449fc0e61d82c331692258eb38495013aaf636218"
    txinputs: List[TxOut] = []
    raw_tx: str = "010000000384c9a749888ec0b7372a5740dfe8ba059f67d7b48cb1110060a4e666b42ea383000000006b483045022100c7081d2329334a78cde23359da1d9684d60b7fdb3e396c9d2633c419f9ad30ff022058e7cd031df6b7c7208b3140887e9ba012c81e4f300fcf388256f2636b0682e401210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff84c9a749888ec0b7372a5740dfe8ba059f67d7b48cb1110060a4e666b42ea383010000006a47304402207ceb8ca2179fc4ff975ebc3a95b6b1ddc5ce0c280203576d8a1d53948c7138ac02201157f68003220b7f6c3abc7756e7838e062b81ed511f6caff66aa1a73525efa301210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff7183a5bf996607a10ee0566716012a587adb9e43778c1a019deb3e43b9537af2010000006b483045022100a95b8b36d08f944949b7fa2dca32f5e44e568339dcde11a8713e4676ed3bc77202204d117c91053b667714b1496583583bf8633b7fb189a800d08fdaaefd3f1ef49301210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff020cb82d01000000001976a91442a3e11a80b25ff63b2074c51d1745132bccbba188ac74789b0a000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000"

    def test_standard_wif_ok(self):
        self.assertStandardWifOK()

    def test_p2wpkh_p2sh_wif_ok(self):
        self.assertP2WPKH_P2SH_WifOK()

    def test_p2wpkh_wif_ok(self):
        self.assertP2WPKH_WIFOK()

    async def test_balance(self):
        await self.assertBalanceOK()

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

    @unittest.skip("Intermittent Failure")
    async def test_getverbosetx(self):
        await self.assertGetVerboseTXOK()

    async def test_gettxs(self):
        await self.assertGetTXOK()

    async def test_balance_merkle_proven(self):
        await self.assertBalanceMerkleProvenOK()

    async def test_balances_merkle_proven(self):
        await self.assertBalancesMerkleProvenOK()

    @unittest.skip("Intermittent Failure")
    async def test_transaction(self):
        """
        Sample transaction:
        TxID: 319107640d6dbbbf0da7c6341074410862f61e167c49094477e10f80ecf41b20
        """
        await self.assertTransactionOK()

    async def test_transaction_segwit(self):
        """
        Sample transaction:
        TxID: cc1aba794b8f7bb0176906e724594ce6c79f598cd904c1483de4b43331b25cc5
        """
        await self.assertSegwitTransactionOK()

    @unittest.skip("Intermittent Failure")
    async def test_transaction_native_segwit(self):
        """
        Sample transaction:
        TxID: 8dbaffbd6206147389e0bb9c30c84e9f0a5dedb9a1e15563c950c7470b3c90c5
        """
        await self.assertNativeSegwitTransactionOK()

    async def test_transaction_mixed_segwit(self):
        """
        Sample transaction:
        TxID: 3dc675d5addfad9d142f51411372ed2ad9700a19019114aab775048effadf7da
        """
        await self.assertMixedSegwitTransactionOK()

    async def test_transaction_multisig(self):
        """
        Sample transaction:
        TxID: 6d68cdc662fc92164b371aba385aec9afc99058a6ce6dfaa5c5766705e099f85
        """
        await self.assertMultiSigTransactionOK()

    @unittest.skip("Intermittent Failure")
    async def test_transaction_native_segwit_multisig(self):
        """
        Sample transaction:
        TxID: 4076340f359668b325808ec98888863402c0fb829f0f1d15e2e8ab816841d749
        """
        await self.assertNativeSegwitMultiSigTransactionOK()

    @unittest.skip("Intermittent Failure")
    async def test_sendmulti_recipient_tx(self):
        """
        Sample transaction:
        TxID: da7c7f99f2f1968bfd53dc7a817b4a9f3f3f596727194c4df57fac3f0e68e777
        """
        await self.assertSendMultiRecipientsTXOK()

    async def test_send(self):
        """
        Sample transaction:
        TxID: 779221217a57596149d1ea4bf017066df6a488d1afe730d8d805bbaa6b6b0deb
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
