from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from cryptos.types import TxInput
from typing import List, Type
from unittest import mock


class TestBitcoinCash(BaseAsyncCoinTestCase):
    name: str = "Bitcoin Cash"
    coin:  Type[coins_async.BaseCoin] = coins_async.BitcoinCash
    addresses = ["1Ba7UmguphMX1g8ibyWQL62qzNu7mrXLVz", "16mBWqf9zefiZcKrKSf6uo3He9ipzPyuTb", "15pXUHkdBXFeUUetZJnJqNoD7dyCzaJFUn"]
    fee: int = 54400
    max_fee: int = fee
    testnet: bool = False
    unspent_addresses: List[str] = ["1KomPE4JdF7P4tBzb12cyqbBfrVp4WYxNS"]
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 16341002035, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [
        {'confirmed': 16341002035, 'unconfirmed': 0, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'confirmed': 8000100547, 'unconfirmed': 0, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'}]
    history: List[ElectrumXTx] = []
    histories: List[ElectrumXTx] = []
    unspent: List[ElectrumXTx] = [
        {'output': 'e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476:1', 'value': 249077026}]
    unspents: List[ElectrumXTx] = []
    min_latest_height: int = 512170
    txinputs: List[TxInput] = [{'output': 'b3105972beef05e88cf112fd9718d32c270773462d62e4659dc9b4a2baafc038:0', 'value': 1157763509}]
    txid: str = "e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476"
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
