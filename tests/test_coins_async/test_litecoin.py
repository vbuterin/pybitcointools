from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from cryptos.types import TxInput
from typing import List, Type
from unittest import mock


class TestLitecoin(BaseAsyncCoinTestCase):
    name: str = "Litecoin"
    coin: Type[coins_async.BaseCoin] = coins_async.Litecoin
    addresses: List[str] = ["", "",
                            ""]
    segwit_addresses: List[str] = ["", "",
                                   ""]
    native_segwit_addresses: List[str] = ["",
                                          "",
                                          ""]
    multisig_addresses: List[str] = ["", ""]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]

    fee: int = 54400
    max_fee: int = fee
    testnet: bool = False

    unspent_addresses: List[str] = ["LcHdcvAs71DAnkEPLSEuqMGcCWu3zG4Dw5"]
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 16341002035, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [
        {'confirmed': 16341002035, 'unconfirmed': 0, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'confirmed': 8000100547, 'unconfirmed': 0, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'}]
    history: List[ElectrumXTx] = []
    histories: List[ElectrumXTx] = []
    unspent: List[ElectrumXTx] = [{'output': '0c2d49e00dd1372a7219fbc4378611b39f54790bbd597b4c29517f0d93c9faa2:0', 'value': 1107944447}]
    unspents: List[ElectrumXTx] = []
    min_latest_height : int= 1347349
    txid: str = "0c2d49e00dd1372a7219fbc4378611b39f54790bbd597b4c29517f0d93c9faa2"
    txinputs: List[TxInput] = [{'output': 'b3105972beef05e88cf112fd9718d32c270773462d62e4659dc9b4a2baafc038:0', 'value': 1157763509}]
    tx = {'txid': txid}

    async def test_balance(self):
        await self.assertBalanceOK()

    async def test_balances(self):
        await self.assertBalancesOK()

    async def test_unspent(self):
        await self.assertUnspentOK()

    async def test_unspents(self):
        await self.assertUnspentsOK()

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

    async def test_merkle_proof(self):
        await self.assertMerkleProofOK()

    async def test_balance_merkle_proven(self):
        await self.assertBalanceMerkleProvenOK()

    async def test_balances_merkle_proven(self):
        await self.assertBalancesMerkleProvenOK()

    async def test_getverbosetx(self):
        await self.assertGetVerboseTXOK()

    async def test_gettxs(self):
        await self.assertTxsOK()

    async def test_transaction(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertTransactionOK("687f014010fbc1d46cf6e9d5588aa7b676b5a9eff12babec576bb75bcb53558d")

    async def test_transaction_segwit(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSegwitTransactionOK("90e891de968b966177d736e004d096f8158a2f8a4ed51f1daf29b261399475df")

    async def test_transaction_native_segwit(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertNativeSegwitTransactionOK("e5c37f35186f52909f6e825daf02261b8f59794bdfba356f1a992d5bcec060b3")

    async def test_transaction_mixed_segwit(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertMixedSegwitTransactionOK("5d9e032c74cf47fa1beafc973b2a7765b3c88a77af5ecf328d1f890db70c79ee")

    async def test_transaction_multisig(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertMultiSigTransactionOK("")

    async def test_sendmulti_recipient_tx(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSendMultiRecipientsTXOK("29ce6ce80bf5f381eae1b27049e6b15d2a6316664b1f8ffc3404293b2a4b56e2")

    async def test_send(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSendOK("00648605d4e84b9d9f07d6766eb63a45ab47d1cfd84ea282e54f1c009fa320d3")

    async def test_subscribe_block_headers(self):
        await self.assertSubscribeBlockHeadersOK()

    async def test_subscribe_block_headers_sync(self):
        await self.assertSubscribeBlockHeadersSyncCallbackOK()

    async def test_latest_block(self):
        await self.assertLatestBlockOK()

    async def test_confirmations(self):
        await self.assertConfirmationsOK()
