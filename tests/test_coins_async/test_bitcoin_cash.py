import unittest
from binascii import unhexlify
from cryptos import coins_async
from cryptos import cashaddr
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from cryptos.main import privtopub
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
    multisig_addresses = ["35D72hVBzYXqNkyN63z28FHmSyPKuJh9Q2", "32tuh24PcKWQWfWitfp9NVhRuYjDKG7vCH"]
    cash_multisig_addresses = ["bitcoincash:pqnfj8jmtpj30fnjgc2gy0gs4l6sptdyhc84ukmr52",
                               "bitcoincash:pqxn06syr9twx9ecx892alre33yuuwn2gu7z0p7lzz"]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    privkey_standard_wifs: List[str] = ['5HtVdWeLBUpSyqqSnnJoQnCiuc33Kg86i8V1gc1tKK13tw1Cqrg',
                                        "KwW1FKxkfefDyVStxvKH9qCCb9qaiFXBFZUy2mPLvTMap2f5YaXR",
                                        "5KJRe1vYXbE4hhvNjJjPX6iS1tqpksNKHChrQjzyYVDgh9Z8H5o"]
    fee: int = 500
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
    min_latest_height: int = 129055
    txheight: int = 509045
    block_hash: str = "0000000000000000006d011e3ab462725dad9d4e8d1a7398bcc2895defd1fa3f"
    txinputs: List[TxInput] = [{'output': 'b3105972beef05e88cf112fd9718d32c270773462d62e4659dc9b4a2baafc038:0', 'value': 1157763509}]
    txid: str = "e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476"
    raw_tx: str = "0200000001ab293b56edcc8d99b665ebe6265132408df132ecf7a1948d68bee425cef7bb63010000006b483045022100fca8f51dc515e85862cd087729136656e4f73f76eb1ce9d4ce90b092e4b9efea02204943929a08bab03e95dad6781e128f49a3d35af055a146a9c8e4aec3a4c90db54121039b190dc5e0bcea42cec072f7aebf097f379691b3dfcc67fd587dddc1d004eaa4feffffff0222ec4377000000001976a9149119c4f8dc64fde6e9d6f59ae9273993b858c03388ac229dd80e000000001976a914ce4a729424645fc09678e1b8327b7c78d1cc3fc288acdac10700"

    def test_cash_addr(self):
        # https://reference.cash/protocol/blockchain/encoding/cashaddr
        public_key_hash = unhexlify("211b74ca4686f81efda5641767fc84ef16dafe0b")
        addr = cashaddr.encode_full(self._coin.cash_hrp, 0, public_key_hash)
        self.assertEqual(addr, "bitcoincash:qqs3kax2g6r0s8ha54jpwelusnh3dkh7pvu23rzrru")

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

    @unittest.skip("Unreliable")
    async def test_balance(self):
        await self.assertBalanceOK()

    @unittest.skip("Address needs updating")
    async def test_balance_cash_address(self):
        result = await self._coin.get_balance(self.unspent_cash_addresses[0])
        self.assertEqual(self.balance, result)

    async def test_balances(self):
        await self.assertBalancesOK()

    async def test_unspent(self):
        await self.assertUnspentOK()

    @unittest.skip("Unreliable")
    async def test_unspents(self):
        await self.assertUnspentsOK()

    async def test_merkle_proof(self):
        await self.assertMerkleProofOK()

    @unittest.skip("Intermittent Failures")
    async def test_history(self):
        await self.assertHistoryOK()

    async def test_histories(self):
        await self.assertHistoriesOK()

    @unittest.skip('Out of range error returned, not sure why')
    async def test_block_header(self):
        await self.assertBlockHeaderOK()

    async def test_block_headers(self):
        await self.assertBlockHeadersOK()

    async def test_gettx(self):
        await self.assertGetTXOK()

    @unittest.skip('Transaction not found')
    async def test_getverbosetx(self):
        await self.assertGetVerboseTXOK()

    async def test_gettxs(self):
        await self.assertTxsOK()

    @unittest.skip("Test address needs updating")
    async def test_balance_merkle_proven(self):
        await self.assertBalanceMerkleProvenOK()

    async def test_balances_merkle_proven(self):
        await self.assertBalancesMerkleProvenOK()

    async def test_transaction(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertTransactionOK("744e0a28ed754ceb551a4fc3a45f57f0b3bd34ff415c3724a2ce774ccc24eff9")

    async def test_transaction_cash_address(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertCashAddressTransactionOK(
                "744e0a28ed754ceb551a4fc3a45f57f0b3bd34ff415c3724a2ce774ccc24eff9")

    async def test_transaction_multisig(self):
        # 010000000176f465265b8d0fcb8cfd6598d1640f5f10297aaed5ab498fb322ade6c8d2eae301000000fd3d01004830450221009a556d396ad8ceec4cbb1cacda67933818deac5210a96a445ac13e97fe8c476102202682d3d25c62e23865b00e1c3ea36c53a2691c64dd43b04de76a35ecd64e5364414730440220045fd2daec62375ffe538c8758ab1461b4d7cc430ec24c57883a6048006daa1a022025d1dec4c9a36000539c283fb1be428b317b66e71ca29fa964efa4d287032f1b414ca9524104de476e251a827e58199ed4d6d7c2177f0a97a2dda150d7a9e59fc5682519eb94d37bc387edff66e7b0f16e92dd045fe968d63e1f203613b76ad733e5cdf8e818210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41eb53aeffffffff02914e6c070000000017a9140d37ea041956e3173831caaefc798c49ce3a6a4787514d6c070000000017a91426991e5b586517a6724614823d10aff500ada4be8700000000
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertMultiSigTransactionOK("9a44b27e7d03361ab66dff6bb9ce49a743b1e91123610dca94099ce92c50eeed")

    async def test_transaction_multisig_cash(self):
        # 010000000176f465265b8d0fcb8cfd6598d1640f5f10297aaed5ab498fb322ade6c8d2eae301000000fd3d0100473044022055dc9295816ce57fc78cd5e5b2e49d7811073e31532508a887e5acc562752e3a0220304788647824903c9fe0d10df3e0379391c85f572e15e966eac6744f3623473f41483045022100fa2a6222842a8102ab944cf9e0e282e907c3699921487f7da350a8879b45064c02202ab2a4eca7adb31c40b4210b8ff42171fad87370a8f84adbae5ceb694607f62e414ca9524104de476e251a827e58199ed4d6d7c2177f0a97a2dda150d7a9e59fc5682519eb94d37bc387edff66e7b0f16e92dd045fe968d63e1f203613b76ad733e5cdf8e818210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41eb53aeffffffff02914e6c070000000017a9140d37ea041956e3173831caaefc798c49ce3a6a4787117a6b070000000017a91426991e5b586517a6724614823d10aff500ada4be8700000000
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertCashAddressMultiSigTransactionOK("9a44b27e7d03361ab66dff6bb9ce49a743b1e91123610dca94099ce92c50eeed")


    async def test_sendmulti_recipient_tx(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSendMultiRecipientsTXOK("2f5046ed857685a08ffb642a8e352b7cdb5cc6b981d690086fb337b868f26dcd")

    async def test_send(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSendOK("9fea356516a2cb97b2242fb6b468f4f9264c26977e456b643cc787dc0f3480c0")

    async def test_subscribe_block_headers(self):
        await self.assertSubscribeBlockHeadersOK()

    async def test_subscribe_block_headers_sync(self):
        await self.assertSubscribeBlockHeadersSyncCallbackOK()

    async def test_latest_block(self):
        await self.assertLatestBlockOK()

    async def test_confirmations(self):
        await self.assertConfirmationsOK()
