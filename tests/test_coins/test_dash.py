from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestDash(BaseCoinTestCase):
    name = "Dash"
    coin = coins.Dash
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