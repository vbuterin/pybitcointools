from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestDoge(BaseCoinTestCase):
    name = "Dogecoin"
    coin = coins.Doge
    fee = 54400
    testnet = False

    num_merkle_siblings = 8
    min_latest_height = 2046537
    txid = "345c28885d265edbf8565f553f9491c511b6549d3923a1d63fe158b8000bbee2"
    txinputs = [{'output': '72ee1f1f41d7613db02e89a58104a4c0cb0b3e9e5d46bfe4b14c80b80a9c2285:0', 'value': 3661230900743}]
    txheight = 2046470
    tx = {'txid': txid}
    unspent_address = "DTXcEMwdwx6ZNjPdfVTSMFYABqqDqZQCVJ"
    unspent = [
            {'output': '345c28885d265edbf8565f553f9491c511b6549d3923a1d63fe158b8000bbee2:1', 'value': 3485074167413}]

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

    @skip("Need stable transaction")
    def test_unspent(self):
        self.assertUnspentOK()