from cryptos import coins_async
from cryptos.types import TxInput, Tx
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from typing import List, Type
from unittest import mock


class TestBitcoin(BaseAsyncCoinTestCase):
    name: str = "Bitcoin"
    coin: Type[coins_async.BaseCoin] = coins_async.Bitcoin
    addresses: List[str] = ["1MhTCMUjM1TEQ7RSwoCMVZy7ARa9aAP82Z",
                            "18DEbpqpdmfNaosxwQhCNHDAChZYCNG836",
                            "175MvCJkNZT3zSdCntXj9vK7L6XKDWjLnD"]
    segwit_addresses: List[str] = ["3FWfXAgccKXVSVcmEF3RRf2KacBSQ6rcix",
                                   "3NFyu5P3C9PvWUB5ekvmRgYgniNEE1n5za",
                                   "32UT11rEHGqDnMZxM1VGfz4dLMxNrJWnu3"]
    native_segwit_addresses: List[str] = ["bc1q95cgql39zvtc57g4vn8ytzmlvtt43sknztmu82",
                                          "bc1qfuvnn87p787z7nqv9seu4e8fqel83yaczcl63s",
                                          "bc1qst3pkm860tjt9y70ugnaluqyqnfa7h54nslppf"]
    multisig_addresses: List[str] = ["35D72hVBzYXqNkyN63z28FHmSyPKuJh9Q2", "32tuh24PcKWQWfWitfp9NVhRuYjDKG7vCH"]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    privkey_standard_wifs: List[str] = ['5HtVdWeLBUpSyqqSnnJoQnCiuc33Kg86i8V1gc1tKK13tw1Cqrg',
                                        "KwW1FKxkfefDyVStxvKH9qCCb9qaiFXBFZUy2mPLvTMap2f5YaXR",
                                        "5KJRe1vYXbE4hhvNjJjPX6iS1tqpksNKHChrQjzyYVDgh9Z8H5o"]
    privkey_segwit_wifs: List[str] = ["LEhYWUZa1ZchcvaMwDmMSJhiU43JvGDnXRGu8iF6UmxeLZ9MvbRp",
                                      "LEfGPegZ1xVVvXUS5574kBPB62EtP64daSjE9g5XuQs1Nh2hh3u3",
                                      "LLwAtho8WKtwHhe81t3szCQqupDoTTrY1PuaChV5Yw4QkRnUhx4Y"]
    privkey_native_segwit_wifs: List[str] = ["L67uwKCfqQhZeQZbP9NTe8cEDcqf5qx4MyemaFtzzJCw4DvrFkVK",
                                             "L65dpVKeqoaMx1TfWziAx1Hgqb3EYfnuR176bDjSQw7J6MrvP2GZ",
                                             "LCMYKYSELAyoKBdMToezC2KMfP29d3aoqxHSeF8z4TJhU6gYDEQV"]
    fee: int = 54400
    max_fee: int = fee
    testnet: bool = False
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 16341002035, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [
        {'confirmed': 16341002035, 'unconfirmed': 0, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'confirmed': 8000100547, 'unconfirmed': 0, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'}]
    history: List[ElectrumXTx] = [{'tx_hash': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34', 'height': 114743},
                {'tx_hash': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f', 'height': 116768},
               {'height': 547011,
                'tx_hash': 'e66ebcd04e86196b59e8ff54c071fb82d055c40cbd7314309088e6c2b5658a0a'},
               {'height': 621585,
                'tx_hash': '655620ced5f7f6ff0edcb930ab787f1e61a0872ce8d318a94ff884a9c7e81808'},
               {'height': 651450,
                'tx_hash': '04eac4e98bc74b344d85bd1f008d227d8a7715224f5d1af0929810c08fd7fed2'}]
    histories: List[ElectrumXTx] = [{'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR',
      'height': 651450,
      'tx_hash': '04eac4e98bc74b344d85bd1f008d227d8a7715224f5d1af0929810c08fd7fed2'},
     {'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR',
      'height': 621585,
      'tx_hash': '655620ced5f7f6ff0edcb930ab787f1e61a0872ce8d318a94ff884a9c7e81808'},
     {'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT',
      'height': 248365,
      'tx_hash': 'a146923df9579f7c7b9a8f5ddf27e230e8d838117379bdf6b57113ce31bf52e0'},
     {'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR',
      'height': 114743,
      'tx_hash': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34'},
     {'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT',
      'height': 659070,
      'tx_hash': 'cc0b5794055a0f84682c29cd6fee42d595cf7624045cf2920768694f36ca8dca'},
     {'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR',
      'height': 547011,
      'tx_hash': 'e66ebcd04e86196b59e8ff54c071fb82d055c40cbd7314309088e6c2b5658a0a'},
     {'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR',
      'height': 116768,
      'tx_hash': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f'},
     {'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT',
      'height': 187296,
      'tx_hash': 'fd232fe21b6ad7f096f3012e935467a7f2177258cdcd07c748502a5b1f31ccd5'}]
    unspent_addresses: List[str] = ["12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR", "1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT"]
    unspent: List[ElectrumXTx] = [
        {'tx_hash': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34', 'tx_pos': 1, 'height': 114743,
         'value': 5000000, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'tx_hash': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f', 'tx_pos': 1, 'height': 116768,
         'value': 16336000000, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'tx_hash': 'e66ebcd04e86196b59e8ff54c071fb82d055c40cbd7314309088e6c2b5658a0a', 'tx_pos': 1974, 'height': 547011,
         'value': 888, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'tx_hash': '655620ced5f7f6ff0edcb930ab787f1e61a0872ce8d318a94ff884a9c7e81808', 'tx_pos': 1, 'height': 621585,
         'value': 600, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'tx_hash': '04eac4e98bc74b344d85bd1f008d227d8a7715224f5d1af0929810c08fd7fed2', 'tx_pos': 531, 'height': 651450,
         'value': 547, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'}
    ]
    unspents: List[ElectrumXTx] = unspent + [
        {'height': 659070, 'tx_hash': 'cc0b5794055a0f84682c29cd6fee42d595cf7624045cf2920768694f36ca8dca', 'tx_pos': 40,
         'value': 547, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'},
        {'tx_hash': 'fd232fe21b6ad7f096f3012e935467a7f2177258cdcd07c748502a5b1f31ccd5', 'tx_pos': 0, 'height': 187296,
         'value': 8000000000, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'},
        {'tx_hash': 'a146923df9579f7c7b9a8f5ddf27e230e8d838117379bdf6b57113ce31bf52e0', 'tx_pos': 41, 'height': 248365,
         'value': 100000, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'}]

    min_latest_height: int = 503351
    txid: str = "fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690"
    txheight: int = 509045
    block_hash: str = "000000000000000000103a149fa9a449e5b4840fb18d22d5458eb650e1098ea9"
    txinputs: List[TxInput] = [{"output": "7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583:1", 'value': 1000000},
                               {"output": "da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf:1", 'value': 100000}]
    tx: Tx = {'ins': [{'tx_hash': '7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583', 'tx_pos': 1,
                       'script': '483045022076bf3b0edd6c9cdd35fb30d77d780f1d752e959242b2bbd58123617b8db350a6022100a602b91002b9c6c078a7513f72e1d7ccbfa3aa6f1261706b3110db00b1205ae4014104fafb576fcaf43a773ee1e34c5a76ab1f4fe1a7dc23256dd7a4525092537fc11686227d495dff710a291e7e9a6bf474a968158c56882b153e4b2e17bc584ec3cc',
                       'sequence': 4294967295},
                   {'tx_hash': 'da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf', 'tx_pos': 1,
                    'script': '493046022100aecef1b98cf1cead7daadfb538c4808e71c9ef0c1ecec04af64fb1fdcffa7afb022100ec1070f8dea90f9ef6d86ebf251a63a01eae48ff840e0aacce899775b2dd16c6014104d2eeecdff2d0fd3d19f07928689f2aed33f1298f7493f2ca77b3607b545a8b2a91af48c27bc949da72f6ef38412c95bdcf6618486207bb92cd9aa75cae2c116d',
                    'sequence': 4294967295}],
              'outs': [{'value': 100000, 'script': '76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac'}], 'version': 1,
              'locktime': 0}

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

    async def test_transaction_p2pk(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertTransactionToPKOK("9627672d628c0ae307bcae1b0da6adf37eee3c38584d7a5de950e7ce2e9e77df")

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
            await self.assertMultiSigTransactionOK("adb10a2b21a2b764ec4904127d0e47d5f1923eb05e6b0a258ffc2ad17b7dd4be")

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
