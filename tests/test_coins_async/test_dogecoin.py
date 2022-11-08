from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from typing import List


class TestDoge(BaseAsyncCoinTestCase):
    name = "Dogecoin"
    coin = coins_async.Doge
    addresses = ['DRqYjcRNeRMWw7c3gPBv3L8i3ZJSqbm6PV',
                 'DCML95nTwBZf7p4Zfzgkv3Nm5qHqY1g17S',
                 'DBDTTTFPfyMLXSooXUXHhgUiDEFcTRnvFf']
    multisig_addresses: List[str] = ["", ""]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    privkey_standard_wifs: List[str] = ['6JCpvU7HkF7F2TGbzAvn2QBxP2WapoQNKJcF16en8yCghYr1m7W',
                                       'QNtvQAmjvG9MD1qwZCA5342p4Bs9koez8pAspPnBeoxwFxbqYcre',
                                       '6KckvyPW6MWrkKMXvhMN8ihfVKKNFzeatNq5jEdsN9RKVnJrynQ']
    native_segwit_addresses: List[str] = ["doge1q95cgql39zvtc57g4vn8ytzmlvtt43sknp354v0",
                                          "tb1qfuvnn87p787z7nqv9seu4e8fqel83yacg7yf2r",
                                          "tb1qst3pkm860tjt9y70ugnaluqyqnfa7h54ekyj66"]
    privkey_native_segwit_wifs: List[str] = ["QXWq6A1f62BgsvxdyRDFXMSqgesE8Q5sFELgMtHqiepHW9vBUBfE",
                                             "cWSdHQKWGsGd7SvvuQXJKKnkTpLeD7tbV3FZheBwv3mJM6yc95xc",
                                             "cciXnTS5mEg4Ud6crDU7ZLpRHcKZHVgVuzRukfbVZZxhiqfSyfBH"]
    fee: int = 250
    max_fee: int = 1500
    testnet = False

    min_latest_height = 4464523
    unspent_addresses = ["DTXcEMwdwx6ZNjPdfVTSMFYABqqDqZQCVJ"]
    unspent = []
    unspents = []

    txid: str = "345c28885d265edbf8565f553f9491c511b6549d3923a1d63fe158b8000bbee2"
    txheight: int = 2046470
    block_hash: str = ""
    raw_tx: str = ""

    def test_standard_wif_ok(self):
        self.assertStandardWifOK()

    def test_p2wpkh_wif_ok(self):
        self.assertP2WPKH_WIFOK()
