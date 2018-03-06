from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestLitecoin(BaseCoinTestCase):
    name = "Litecoin"
    coin = coins.Litecoin
    fee = 54400
    testnet = False

    num_merkle_siblings = 8
    min_latest_height = 1347349
    txid = "0c2d49e00dd1372a7219fbc4378611b39f54790bbd597b4c29517f0d93c9faa2"
    txinputs = [{'output': 'b3105972beef05e88cf112fd9718d32c270773462d62e4659dc9b4a2baafc038:0', 'value': 1157763509}]
    tx = {'txid': txid}
    txheight = 1347312
    unspent_address = "LcHdcvAs71DAnkEPLSEuqMGcCWu3zG4Dw5"
    unspent = [
            {'output': '0c2d49e00dd1372a7219fbc4378611b39f54790bbd597b4c29517f0d93c9faa2:0', 'value': 1107944447}]

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

    @skip("Need to find stable transaction")
    def test_unspent(self):
        self.assertUnspentOK()