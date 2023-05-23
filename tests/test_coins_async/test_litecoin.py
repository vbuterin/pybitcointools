import unittest

from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from cryptos.types import TxInput
from typing import List, Type
from unittest import mock


class TestLitecoin(BaseAsyncCoinTestCase):
    name: str = "Litecoin"
    coin: Type[coins_async.BaseCoin] = coins_async.Litecoin
    addresses: List[str] = ["LfvQTZnZRfhHev7c7wBemb2sNdwRf4eeEC",
                            "LSSBs39eiRuRqca87YgVeJGvQuvpNwaVkr",
                            "LRJKBQcaTDh7FFKMy2X2RwNsYJtbJBvfvc"]
    segwit_addresses: List[str] = ["MMioq46aZSNvEztfL82mFJGiuJmtRVTFAp",
                                   "MUU8Cxo19GFMJySykdv7FKo67QxgEHzvPG",
                                   "M8gbJuGCEPgearqrStUcVdK2f4YpqCmp9d"]
    native_segwit_addresses: List[str] = ["ltc1q95cgql39zvtc57g4vn8ytzmlvtt43sknxhpcl6",
                                          "ltc1qfuvnn87p787z7nqv9seu4e8fqel83yacxy97fq",
                                          "ltc1qst3pkm860tjt9y70ugnaluqyqnfa7h54hv99ee"]
    multisig_addresses: List[str] = ["MBRFLau9wfPGBGFGBvyMwtYAmfymspELC4", "M973zuUMZSMqKAnczYoVC8wqEFKfHMjANu"]
    native_segwit_multisig_addresses: List[str] = [
        "ltc1q7e42a8gmgp5d7kw8myrruj5qnxp8edp7v5y0y95hrjz6t530uehqz7h5lq",
        "ltc1qu7fz4uku8kh6tg7qghj7rnf88g858lal258gzfu85kx7vc5h0qpss2mknt"
    ]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    privkey_standard_wifs: List[str] = ['6uCE6eBs5uHKTDjJJc6mCAyts5bWXUa8UotBPo2v2mKfakiBJnv',
                                        "T3LGh5Fw52dpkL5mWZG9NBjaY1UtnLY54mPDta1tVRXkKvEGabgc",
                                        "6vcA79U5S1gwB5pEF8XMJVVbyNQHxfpM3t727w21FwYJNzcDXkb"]
    privkey_segwit_wifs: List[str] = ["TLXoxDrkQwbJPmDEUriDefF6QugczMEgLdB9zWse3k8orSi53T7e",   # Not supported in eleectrum
                                      "TLVXqPyjRLU6hN7Jci3vxXvZ2stCTB5XPedV1Ui5UP3AtaYfaxw2",
                                      "TSmSLT6JuhsY4YGzZWzkCYxDrfs7XYsRpboq4W7d7uEaGKLwHQfc"]
    privkey_native_segwit_wifs: List[str] = ["TBxBP4VrEngARFCTvnKKrV9cAUUy9vxxBBZ2S4XYZGP6a7WtRR8a",    # Not recognised in electrum
                                             "TBuuGEcqFBYxir6Y4df3AMq4nSgYckooED1MT2MyyuHTcFPhEP7W",
                                             "TJBomHjQjYxQ62GE1SbrQNrjcEfTh8bhfABhW3mXdRUryzB2UR2g"]
    fee: int = 54400
    max_fee: int = fee
    testnet: bool = False

    unspent_addresses: List[str] = ["LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y"]
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 83571855, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [{'address': unspent_addresses[0]} | dict(balance)]
    unspent: List[ElectrumXTx] = [{'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 1495972,
                                  'tx_hash': '6cf532663cd14013aa6ccb394f86d64aa48fce4d6aa8a175f9b75ea486465ca9',
                                  'tx_pos': 0,
                                  'value': 1984},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 1509957,
                                  'tx_hash': '4987fcebf1643d6a254e6352b72867de1c64a0f5b9e6e1e83c103be419ed9914',
                                  'tx_pos': 1,
                                  'value': 10000917},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 1514616,
                                  'tx_hash': '107cc3d3bf8f1977f9c60b80d02c6e44b1e272a8ebe0d43f712762113bb47c43',
                                  'tx_pos': 0,
                                  'value': 262765},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 1710946,
                                  'tx_hash': '5acea20cf6d767ad4e4c32b4c92354a3545ef147de75494a00b74ad0998b2fa7',
                                  'tx_pos': 0,
                                  'value': 9977400},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 1762963,
                                  'tx_hash': '7f32b287c6264965f8cac174d0b106163572516cf573907a54ad15ce2a47dfa0',
                                  'tx_pos': 0,
                                  'value': 7507184},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 1770983,
                                  'tx_hash': 'cdebcffb1622fe8ea511f2f6ed9059b6b3eca1dba547d6386d21564a15571b13',
                                  'tx_pos': 863,
                                  'value': 23045},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 1800218,
                                  'tx_hash': '68f98cd415c0586c917e4ba6c78747e7281adca09837048ff8fa211cab9326cd',
                                  'tx_pos': 1,
                                  'value': 54059898},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 2192455,
                                  'tx_hash': '8391ba465fe818e7041a2316e508731b6e20bf9488c0b7579bfd7de46c6e9ab3',
                                  'tx_pos': 0,
                                  'value': 360933},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 2262951,
                                  'tx_hash': '43eb70acc4c8c6bdbfabdf76cdbf0a6a969b82051514d105f8c00dff23e715c6',
                                  'tx_pos': 0,
                                  'value': 200000},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 2352771,
                                  'tx_hash': '7158c6f05ef2b06a40cd00b64647da6735d2eb3908f958fcbc5d0584f34be460',
                                  'tx_pos': 0,
                                  'value': 1121169},
                                 {'address': 'LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y',
                                  'height': 2454373,
                                  'tx_hash': '02c0665f6ddaed09a365ddafdff05b188969ee754acf6867b9dd1b970d254a8b',
                                  'tx_pos': 0,
                                  'value': 56560
                                  }]
    history: List[ElectrumXTx] = [{'height': 1495972,
                                   'tx_hash': '6cf532663cd14013aa6ccb394f86d64aa48fce4d6aa8a175f9b75ea486465ca9'},
                                  {'height': 1509957,
                                   'tx_hash': '4987fcebf1643d6a254e6352b72867de1c64a0f5b9e6e1e83c103be419ed9914'},
                                  {'height': 1514616,
                                   'tx_hash': '107cc3d3bf8f1977f9c60b80d02c6e44b1e272a8ebe0d43f712762113bb47c43'},
                                  {'height': 1710946,
                                   'tx_hash': '5acea20cf6d767ad4e4c32b4c92354a3545ef147de75494a00b74ad0998b2fa7'},
                                  {'height': 1762963,
                                   'tx_hash': '7f32b287c6264965f8cac174d0b106163572516cf573907a54ad15ce2a47dfa0'},
                                  {'height': 1770983,
                                   'tx_hash': 'cdebcffb1622fe8ea511f2f6ed9059b6b3eca1dba547d6386d21564a15571b13'},
                                  {'height': 1800218,
                                   'tx_hash': '68f98cd415c0586c917e4ba6c78747e7281adca09837048ff8fa211cab9326cd'},
                                  {'height': 2192455,
                                   'tx_hash': '8391ba465fe818e7041a2316e508731b6e20bf9488c0b7579bfd7de46c6e9ab3'},
                                  {'height': 2262951,
                                   'tx_hash': '43eb70acc4c8c6bdbfabdf76cdbf0a6a969b82051514d105f8c00dff23e715c6'},
                                  {'height': 2352771,
                                   'tx_hash': '7158c6f05ef2b06a40cd00b64647da6735d2eb3908f958fcbc5d0584f34be460'},
                                  {'height': 2454373,
                                   'tx_hash': '02c0665f6ddaed09a365ddafdff05b188969ee754acf6867b9dd1b970d254a8b'}]
    histories: List[ElectrumXTx] = [dict(h) | {'address': "LSdTvMHRm8sScqwCi6x9wzYQae8JeZhx6y"} for h in history]
    unspents: List[ElectrumXTx] = unspent
    min_latest_height: int = 2360220
    txheight: int = 509045
    block_hash: str = "3bfd5d7f95a28e1af34cc50a36aee92c4aa4c317d4d0f7795034f7a8fc74b6c9"
    txid: str = "0c2d49e00dd1372a7219fbc4378611b39f54790bbd597b4c29517f0d93c9faa2"
    txinputs: List[TxInput] = [{'output': 'b3105972beef05e88cf112fd9718d32c270773462d62e4659dc9b4a2baafc038:0', 'value': 1157763509}]
    raw_tx: str = "020000000138c0afbaa2b4c99d65e4622d467307272cd31897fd12f18ce805efbe725910b3000000006b483045022100b9dfcf3d1cc384797db57f14adf17716c6dc8d47f7733a3ebceb233ed9d18cc202205f44701f5f371404026a165ffe2dbd405853ca838c28710aa64bb3038102f5de012102158315db717fbda2d709f41a913fdfc384f269884dc0915bd0a347bc3cf3750bffffffff02ffe30942000000001976a914bb2c3d60bfaf9d3b87fc9f225e8a925200d4832388ac968cf002000000001976a91444baf967037464e3c3f5bfe7ae2c98385aca39c188ac00000000"

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
        await self.assertTxsOK()

    async def test_balance_merkle_proven(self):
        await self.assertBalanceMerkleProvenOK()

    async def test_balances_merkle_proven(self):
        await self.assertBalancesMerkleProvenOK()

    async def test_transaction(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertTransactionOK("5f2bee84fdd62038a5f34848cd427cca3ed278d990d7ed4e50d7f62378c23757")

    async def test_transaction_segwit(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSegwitTransactionOK(
                "1956512ac84a0624d1c771463ed08c19b9e4add2d7f23975b4c4fcd9c6d0a006")

    async def test_transaction_native_segwit(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertNativeSegwitTransactionOK(
                "eab7dcbf60408c9a72bfd5f60ffcef3c266e8b9a0f159686f97334740ff2b88c")

    async def test_transaction_mixed_segwit(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertMixedSegwitTransactionOK(
                "69678157448b00cfdafaf07bf7825072094552c5f5f3626152845118b3b30969")

    async def test_transaction_multisig(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertMultiSigTransactionOK(
                "6ecbbfe2af2744b3000e02e21f70c96d5e2128a04db07e3d1c983036f7683d70")

    async def test_transaction_native_segwit_multisig(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertNativeSegwitMultiSigTransactionOK("27fb482d29a85b3141141622dde4015499cdf17ecc41b57c01dc387e9e87431e")

    async def test_sendmulti_recipient_tx(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSendMultiRecipientsTXOK("b714d2614e05ae9442c44f39faa82cc41ef4d37348d04075e5315f41b9467071")

    async def test_send(self):
        with mock.patch('cryptos.electrumx_client.client.NotificationSession.send_request',
                        side_effect=self.mock_electrumx_send_request):
            await self.assertSendOK("ba75fb9bafeb6dd02d044b7814f3da917037bedf3d187eae4b94c10a6559e7d1")

    async def test_subscribe_block_headers(self):
        await self.assertSubscribeBlockHeadersOK()

    async def test_subscribe_block_headers_sync(self):
        await self.assertSubscribeBlockHeadersSyncCallbackOK()

    async def test_latest_block(self):
        await self.assertLatestBlockOK()

    async def test_confirmations(self):
        await self.assertConfirmationsOK()
