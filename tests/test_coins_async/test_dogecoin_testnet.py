import unittest

from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from typing import List


@unittest.skip('Only Doge Electrumx server is often down')
class TestDogeTestnet(BaseAsyncCoinTestCase):
    name = "Doge Testnet"
    coin = coins_async.Doge
    addresses = ['nptcTdAHaPpEp6BEiCqNHjj1HRgjtFELjM',
                 'nbQPs6XNsA2NzndkhpLDASy4Khg8ZfhUfj',
                 'naGXBTzJbwp4QRNzZJAjx651T6duZy2kgV']
    multisig_addresses: List[str] = ["2MvmK6SRDc13BaYbumBbtkCH2fKbViC5XEv",
                                     "2MtT7kkzRDn1kiT9GZoS1zSgh7twP145Qif"]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    privkey_standard_wifs: List[str] = ['95YcZiMwUZF3DYW9EHSiC1xEPVdBnFM3dMVBFXkBeMksf8k8F53',
                                       'cf2FrZgQT2Bm5xwhTUvC7VtEiFYJ3YAKeUshG6Y3QXX1dSAZ9s9h',
                                       '96xYaDe9pfeewQb5AosJJLTwVnRyDSbGCRi1yfjGsXyWTNCJpxv']
    fee: int = 300000
    max_fee: int = 1000000
    testnet = True
    min_latest_height = 4109697

    unspent_addresses = ["ncst7MzasMBQFwx2LuCwj8Z6F4pCRppzBP"]
    unspent = [{'address': 'ncst7MzasMBQFwx2LuCwj8Z6F4pCRppzBP',
                'height': 4107911,
                'tx_hash': '268bff71633310c974e262a67a057a618f6d6596bfa95e45692d6c9269a13873',
                'tx_pos': 0,
                'value': 10000000000}]
    unspents = unspent
    balance = {'confirmed': 10000000000, 'unconfirmed': 0}
    balances = [{'address': unspent_addresses[0]} | dict(balance)]
    history = [{'height': 4107911,
                'tx_hash': '268bff71633310c974e262a67a057a618f6d6596bfa95e45692d6c9269a13873'}]
    histories = [{'address': unspent_addresses[0]} | dict(history[0])]
    txid: str = "268bff71633310c974e262a67a057a618f6d6596bfa95e45692d6c9269a13873"
    txheight: int = 4107911
    block_hash: str = "de125596a7937dcccdb49bb55ea50b776fbe32f8bfa9afcda236dcdc6b9880e3"
    raw_tx: str = "0100000001502100e4c8a3c0bb1aabc6698b128ffdaf06be518f126fe3400880920d680600010000006b483045022100918045061097ed4e3ae63d3f5a0fa5aa188a0e1f8f0041fb0693a0c05cb3ce8b02206efcb89204e4924a71704e105b1d8c7cc8a701a70262efb91dc426cdb97c40670121030d78465ee4506029a720bd691c883705391271d9a8f428abae5c577ce44841f1feffffff0200e40b54020000001976a9145f44291007a8a4000b9b8424843793f402638e9388acaae442dc310000001976a914a7106a8a40e93b097a383446d30ce8d1f7af1db288ac86ae3e00"

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
        await self.assertGetTxsOK()

    async def test_transaction(self):
        """
        Sample transaction:
        TxID: 4d859f797f678f0cbe608490e0ba5bc7f1fa670b34192bbbf6f468fb2ed00fe4
        """
        await self.assertTransactionOK()

    async def test_transaction_multisig(self):
        """
        Sample transaction:
        TxID: 092df25d3bb39bb82e1d00faf08a0aec2255a3214bab2a1a7c6437dd77b6281b
        """
        await self.assertMultiSigTransactionOK()

    @unittest.skip("Intermittent failure")
    async def test_sendmulti_recipient_tx(self):
        """
        Sample transaction:
        TxID: 5723b84848f00d2b315086ce564e535bd6d75fa13225ff75fce0d9ed7cd306a9
        """
        await self.assertSendMultiRecipientsTXOK()

    async def test_send(self):
        """
        Sample transaction:
        TxID: 21fdea144f28d0cb1da99c5fe7c96268aaa98ddef3a14fd627b44ea31ce0be3e
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

