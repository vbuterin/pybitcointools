from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from typing import List


class TestDash(BaseAsyncCoinTestCase):
    name = "Dash"
    coin = coins_async.Dash

    addresses = ["XwPJ2c8dJifpZ422ogWaM6etzm9qZ7RyBz",
                 "Xhu5S5VibUsxjkUYoJ1RDotx339EEL1qGH",
                 "XgmCkSxeLGfe9PDnemqx1SzuAS71BPYDoY"]
    multisig_addresses: List[str] = ["", ""]
    privkeys = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    privkey_standard_wifs: List[str] = ["7qd538kkwpDfEC13gqUju9maWGqcjCAeWhsCDzJ1s7WXQCRhBqM",
                                        "XBZvhbM7yLHg2pTGzgK9f4PDWB7AA48Rd8psZHiYEpdgDBikbLbe",
                                        "7s313e2yHvdGx45ydMuL1UHHcZeQAPQs5n62x8H76HjACPvsS4x"]

    fee = 54400
    testnet = False

    num_merkle_siblings = 4
    min_latest_height = 801344
    txid = "e7a607c5152863209f33cec4cc0baed973f7cfd75ae28130e623c099fde7072c"
    txinputs = [{'output': 'ac7312d63f2817d4d2823dae107e601b52c08a52779c237bd06359e6189af9b8:0', 'value': 493488869}]
    tx = {'txid': txid}
    txheight = 801268
    unspent_address = "XiY7UHfBCBkMCZR3L96kuCQ5HHEEuPZRXk"
    unspent = [
            {'output': 'e7a607c5152863209f33cec4cc0baed973f7cfd75ae28130e623c099fde7072c:1', 'value': 220000000}]

    def test_standard_wif_ok(self):
        self.assertStandardWifOK()

    def test_block_info(self):
        self.assertBlockHeadersOK()

    def test_merkle_proof(self):
        self.assertMerkleProofOK()

    def test_block_height(self):
        self.assertBlockHeightOK()
        self.assertLatestBlockHeightOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_fetchtx(self):
        self.assertGetTXOK()

    def test_unspent(self):
        self.assertUnspentOK()