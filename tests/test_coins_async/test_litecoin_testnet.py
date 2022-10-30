from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.types import ElectrumXTx, TxOut
from cryptos.electrumx_client.types import ElectrumXMultiBalanceResponse
from typing import List


class TestLitecoinTestnet(BaseAsyncCoinTestCase):
    name = "Litecoin Testnet"
    coin = coins_async.Litecoin
    addresses: List[str] = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu", "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_addresses: List[str]= ["2N3CxTkwr7uSh6AaZKLjWeR8WxC43bQ2QRZ", "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU", "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    native_segwit_addresses: List[str] = ["", "", ""]
    multisig_addresses: List[str] = ["", ""]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    fee: int = 500
    max_fee: int = 3500
    testnet: bool = True

    min_latest_height: int = 2580721
    unspent_addresses: List[str] = ["ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"]
    unspent: List[ElectrumXTx] = [
        {'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000}
    ]
    unspents: List[ElectrumXTx] = [
        {'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000,
         'address': "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"}
    ]
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 180000000, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = []
    history: List[ElectrumXTx] = []
    histories: List[ElectrumXTx] = []
    txid: str = "2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93"
    txheight: int = 296568
    txinputs: List[TxOut] = []
    raw_tx: str = ""

    async def test_balance(self):
        await self.assertBalanceOK()

    async def test_balances(self):
        await self.assertBalancesOK()

    async def test_merkle_proof(self):
        await self.assertMerkleProofOK()

    async def test_unspent(self):
        await self.assertUnspentOK()

    async def test_unspents(self):
        await self.assertUnspentsOK()

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
        await self.assertGetSegwitTXOK()

    async def test_getverbosetx(self):
        await self.assertGetVerboseTXOK()

    async def test_gettxs(self):
        await self.assertGetSegwitTxsOK()

    async def test_transaction(self):
        """
        Sample transaction:
        TxID:
        """
        await self.assertTransactionOK()

    async def test_transaction_segwit(self):
        """
        Sample transaction:
        TxID:         """
        await self.assertSegwitTransactionOK()

    async def test_transaction_native_segwit(self):
        """
        Sample transaction:
        TxID:
        """
        await self.assertNativeSegwitTransactionOK()

    async def test_transaction_mixed_segwit(self):
        """
        Sample transaction:
        TxID:
        """
        await self.assertMixedSegwitTransactionOK()

    async def test_transaction_multisig(self):
        """
        Sample transaction:
        TxID:
        """
        await self.assertMultiSigTransactionOK()

    async def test_sendmulti_recipient_tx(self):
        """
        Sample transaction:
        TxID:         """
        await self.assertSendMultiRecipientsTXOK()

    async def test_send(self):
        """
        Sample transaction:
        TxID:
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
