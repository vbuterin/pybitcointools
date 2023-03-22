from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXMultiBalanceResponse
from typing import List
from unittest import mock


class TestDash(BaseAsyncCoinTestCase):
    name = "Dash"
    coin = coins_async.Dash

    addresses = ["XwPJ2c8dJifpZ422ogWaM6etzm9qZ7RyBz",
                 "Xhu5S5VibUsxjkUYoJ1RDotx339EEL1qGH",
                 "XgmCkSxeLGfe9PDnemqx1SzuAS71BPYDoY"]
    multisig_addresses: List[str] = ["7VvjrtmMoXdUNXWKMfeXTdHRNXDhhs16sQ", "7TcYXDLZRJc3WS3gAHUehsh5q6Zb4KSUic"]
    privkeys = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    privkey_standard_wifs: List[str] = ["7qd538kkwpDfEC13gqUju9maWGqcjCAeWhsCDzJ1s7WXQCRhBqM",
                                        "XBZvhbM7yLHg2pTGzgK9f4PDWB7AA48Rd8psZHiYEpdgDBikbLbe",
                                        "7s313e2yHvdGx45ydMuL1UHHcZeQAPQs5n62x8H76HjACPvsS4x"]
    unspent_addresses = ["XtuVUju4Baaj7YXShQu4QbLLR7X2aw9Gc8"]
    unspent = [
        {'address': 'XtuVUju4Baaj7YXShQu4QbLLR7X2aw9Gc8', 'height': 1086570,
         'tx_hash': '47266dc659f7271d26dd2b10369895c26d7b16b7db7cd577b60896c7c6cc1974', 'tx_pos': 0,
         'value': 99808}]
    unspents = unspent
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 99808, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] =[{'address': unspent_addresses[0]} | dict(balance)]
    history = [{'height': 1086570, 'tx_hash': '47266dc659f7271d26dd2b10369895c26d7b16b7db7cd577b60896c7c6cc1974'}]
    histories = [{'address': 'XtuVUju4Baaj7YXShQu4QbLLR7X2aw9Gc8', 'height': 1086570,
                  'tx_hash': '47266dc659f7271d26dd2b10369895c26d7b16b7db7cd577b60896c7c6cc1974'}]
    fee: int = 500
    max_fee: int = 3500
    testnet = False
    min_latest_height = 801344
    txheight: int = 509045
    block_hash = "0134634c7f95ebc31f3929d30a334f7d5c87a41625b64e26bf680028fa47fc63"
    txid = "e7a607c5152863209f33cec4cc0baed973f7cfd75ae28130e623c099fde7072c"
    raw_tx = "0100000001b8f99a18e65963d07b239c77528ac0521b607e10ae3d82d2d417283fd61273ac000000006b483045022100dd5bce7f3898d754813e3b77f25fb9731a3d4e3fa7877d9313db9d728a5b28df02203be0bc1166c7a5669d0f8134b9dcc3a2c5fcf69e4a9106780f9ea3b6c9c60edd01210301fb572fa47ec4de2c8cecc1a38fe4fedc2c533dc3a9ae126fb8a225c8d895f5ffffffff02a5d93d10000000001976a9144ce676449e20eb2e329173d34b752fd70f02299088ac00ef1c0d000000001976a914561a5126d9674f51688677c7d19127bd6386795988ac00000000"
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

    async def test_block_header(self):
        await self.assertBlockHeaderOK()

    async def test_block_headers(self):
        await self.assertBlockHeadersOK()

    async def test_gettx(self):
        await self.assertGetTXOK()

    async def test_getverbosetx(self):
        await self.assertGetVerboseTXOK()

    async def test_gettxs(self):
        await self.assertTxsOK()

    async def test_balance_merkle_proven(self):
        await self.assertBalanceMerkleProvenOK()

    async def test_balances_merkle_proven(self):
        await self.assertBalancesMerkleProvenOK()

    async def test_transaction(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertTransactionOK(
                "f6e42d4bae97868779ce7377fd34e973c17b38e9029b37e961ae75dd82a9e34f")

    async def test_transaction_multisig(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertMultiSigTransactionOK(
                "d786997a1d0faa3f17b9d597a631822e0e3f29780fbeb4259545f77c40fd7d25")

    async def test_sendmulti_recipient_tx(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSendMultiRecipientsTXOK("29433a1fed7577398e5414b0c887a59e5a4cfd5a2a26bbd6d5c495bfd46c3061")

    async def test_send(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSendOK("66b37a63f0bfdc9b9a09543966a7ba22aab9f5c614267ca75ccdc1a85ffcc5a3")

    async def test_subscribe_block_headers(self):
        await self.assertSubscribeBlockHeadersOK()

    async def test_subscribe_block_headers_sync(self):
        await self.assertSubscribeBlockHeadersSyncCallbackOK()

    async def test_latest_block(self):
        await self.assertLatestBlockOK()

    async def test_confirmations(self):
        await self.assertConfirmationsOK()
