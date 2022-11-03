from binascii import unhexlify
from cryptos import coins_async
from cryptos import cashaddr
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from cryptos.types import TxInput
from typing import List, Type
from unittest import mock


class TestBitcoinCash(BaseAsyncCoinTestCase):
    name: str = "Bitcoin Cash"
    coin:  Type[coins_async.BaseCoin] = coins_async.BitcoinCash
    addresses = ["1MhTCMUjM1TEQ7RSwoCMVZy7ARa9aAP82Z",  ""
                 "18DEbpqpdmfNaosxwQhCNHDAChZYCNG836",
                 "175MvCJkNZT3zSdCntXj9vK7L6XKDWjLnD"]  # n2DQVQZiA2tVBDu4fNAjKVBS2RArWhfncv
    cash_addresses = ["bitcoincash:qr3sjptscfm7kqry6s67skm5dgsudwkmcsfvmsq7c6",
                      "bitcoincash:qp83jwvlc8clct6vpskr8jhyayr8u7ynhqf8z4glc3",
                      "bitcoincash:qpp28cg6sze9la3myp6v28ghg5fjhn9m5ynaj2uu6x"]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    privkey_standard_wifs: List[str] = ['5HtVdWeLBUpSyqqSnnJoQnCiuc33Kg86i8V1gc1tKK13tw1Cqrg',
                                        "KwW1FKxkfefDyVStxvKH9qCCb9qaiFXBFZUy2mPLvTMap2f5YaXR",
                                        "5KJRe1vYXbE4hhvNjJjPX6iS1tqpksNKHChrQjzyYVDgh9Z8H5o"]
    fee: int = 54400
    max_fee: int = fee
    testnet: bool = False
    unspent_addresses: List[str] = ["1KomPE4JdF7P4tBzb12cyqbBfrVp4WYxNS"]
    unspent_cash_addresses: List[str] = ["bitcoincash:qr8y5u55y3j9lsyk0rsmsvnm03udrnplcg6jpj24wk"]
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 249077026, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [{'address': unspent_addresses[0]} | dict(balance)]
    unspent: List[ElectrumXTx] = [{'address': '1KomPE4JdF7P4tBzb12cyqbBfrVp4WYxNS',
                                   'height': 508381,
                                   'tx_hash': 'e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476',
                                   'tx_pos': 1,
                                   'value': 249077026}]
    unspents: List[ElectrumXTx] = unspent
    history: List[ElectrumXTx] = [{'height': 508381, 'tx_hash': 'e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476'}]
    histories: List[ElectrumXTx] = [{'address': unspent_addresses[0]} | dict(history[0])]
    min_latest_height: int = 764434
    txheight: int = 509045
    block_hash: str = "0000000000000000006d011e3ab462725dad9d4e8d1a7398bcc2895defd1fa3f"
    txinputs: List[TxInput] = [{'output': 'b3105972beef05e88cf112fd9718d32c270773462d62e4659dc9b4a2baafc038:0', 'value': 1157763509}]
    txid: str = "e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476"
    raw_tx: str = "0200000001ab293b56edcc8d99b665ebe6265132408df132ecf7a1948d68bee425cef7bb63010000006b483045022100fca8f51dc515e85862cd087729136656e4f73f76eb1ce9d4ce90b092e4b9efea02204943929a08bab03e95dad6781e128f49a3d35af055a146a9c8e4aec3a4c90db54121039b190dc5e0bcea42cec072f7aebf097f379691b3dfcc67fd587dddc1d004eaa4feffffff0222ec4377000000001976a9149119c4f8dc64fde6e9d6f59ae9273993b858c03388ac229dd80e000000001976a914ce4a729424645fc09678e1b8327b7c78d1cc3fc288acdac10700"

    def test_cash_addr(self):
        # https://reference.cash/protocol/blockchain/encoding/cashaddr
        public_key_hash = unhexlify("211b74ca4686f81efda5641767fc84ef16dafe0b")
        addr = cashaddr.encode_full(self._coin.segwit_hrp, 0, public_key_hash)
        self.assertEqual(addr, "bitcoincash:qqs3kax2g6r0s8ha54jpwelusnh3dkh7pvu23rzrru")

    def test_address_conversion(self):
        for addr, cashaddr in zip(self.addresses, self.cash_addresses):
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
            await self.assertTransactionOK("b305a30989d159731d7b4b3a9db726528bb86662bf0972486f665d2257a7e245")

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
