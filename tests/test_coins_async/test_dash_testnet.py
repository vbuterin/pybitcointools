import unittest
from unittest import skip
from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from typing import List


class TestDashTestnet(BaseAsyncCoinTestCase):
    name = "Dash Testnet"
    coin = coins_async.Dash
    addresses = ["yh1u3ZD4kGKttnwaNXpyP85FH3eD8E99vP",
                 "yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ",
                 "ySPomQ35mpKiV89LDdAM3URFSibNiXEC4J"]
    multisig_addresses: List[str] = ["8hwYpDfDw526ppvaRveUv16nG2zXwp1Z7X", "8fdMUYERYqzfxjTwEYUcAFWSicLRBA7rxn"]
    privkeys = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    privkey_standard_wifs: List[str] = ["91f8DFTsmhtawuLjR8CiHNkgZGPkUqfJ45LxmENPf3k6fuX1m4N",
                                        "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                                        "9354Dkk67pJCfmRfMedJPhGPfZCXv2uWd9ZoVNMUtDxjUBbCVZK"]
    fee: int = 5000
    max_fee: int = 100000
    testnet: bool = True
    min_latest_height = 830385
    unspent_addresses = ["ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz"]
    unspent = [{'address': 'ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz',
                'height': 830413,
                'tx_hash': 'a9f58c5bf785528edcda59a1e1f679a690be2f2c036e194bb2bc3f6ed0b5a9a5',
                'tx_pos': 0,
                'value': 378260000}]
    unspents = unspent
    balance = {'confirmed': 378260000, 'unconfirmed': 0}
    balances = [{'address': unspent_addresses[0]} | dict(balance)]
    history = [
        {'height': 830413,
         'tx_hash': 'a9f58c5bf785528edcda59a1e1f679a690be2f2c036e194bb2bc3f6ed0b5a9a5'}
    ]
    histories = [{'address': unspent_addresses[0]} | dict(history[0])]
    txid = 'a9f58c5bf785528edcda59a1e1f679a690be2f2c036e194bb2bc3f6ed0b5a9a5'
    txheight = 45550
    block_hash: str = "5a353b1bc4974919fc49c0b15f6c2226e27dfdef0fe1809cd90f67eb50e6b478"
    raw_tx: str = "020000000112f461b7fbc2607586659722ec82d81e568ea5e66308e2ea76b0b284fabefb1f010000006a47304402201fcd36ce719006af4278f0624c922df5e275be767a468fdf66c72a0de8b6bb8202206cb4fc48f0b91be14b1135856fd37c0ba9c6b670199131ea3d8150979f652322012103c54188322b2e2639a465f63c9a30ee620c3bd3af157e1c5781d34d2f779dca9ffeffffff0220ca8b16000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac1c181c50000000001976a9146fd4df7d158c66f9f00c1247ad64a9e7d6a6c33388acc5ab0c00"
    expected_tx_verbose_keys: List[str] = ['blockhash', 'blocktime', 'chainlock', 'confirmations', 'hex', 'instantlock', 'instantlock_internal', 'locktime', 'size', 'time', 'txid', 'type', 'version', 'vin', 'vout']

    def test_standard_wif_ok(self):
        self.assertStandardWifOK()

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

    async def test_balance_merkle_proven(self):
        await self.assertBalanceMerkleProvenOK()

    async def test_balances_merkle_proven(self):
        await self.assertBalancesMerkleProvenOK()

    async def test_block_header(self):
        await self.assertBlockHeaderOK()

    async def test_block_headers(self):
        await self.assertBlockHeadersOK()

    async def test_gettx(self):
        await self.assertGetTXOK()

    async def test_getverbosetx(self):
        await self.assertGetVerboseTXOK()

    async def test_gettxs(self):
        await self.assertGetTXOK()

    async def test_transaction(self):
        """
        Sample transaction:
        TxID: 23ebe2519c10803ff4d3cab0013d80b63e2ba90103c98084aacbc79c78dd736f
        """
        await self.assertTransactionOK()

    @unittest.skip("Unspents unrecognized")
    async def test_transaction_multisig(self):
        """
        Sample transaction:
        TxID:
        """
        await self.assertMultiSigTransactionOK()

    @unittest.skip("Intermittent failure")
    async def test_sendmulti_recipient_tx(self):
        """
        Sample transaction:
        TxID: 6fb0071bd94dff8de1f9784fd30aadeebd2d8ca27f5451b7725e05c868e98593
        """
        await self.assertSendMultiRecipientsTXOK()

    async def test_send(self):
        """
        Sample transaction:
        TxID: 81a22353f6dc45ae9b32a8fdea26b74fa71050c6993959cb07ce7092b26b1287
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
