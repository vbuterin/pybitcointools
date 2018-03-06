from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestBitcoinGold(BaseCoinTestCase):
    name = "Bitcoin Gold"
    coin = coins.BitcoinGold
    blockcypher_coin_symbol = None
    fee = 54400
    testnet = False
    unspent_address = "GKXERWCKgrTj3LL3CG6qxTVuWsQyrwXuzu"
    unspent = [
        {'output': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34:1', 'value': 5000000},
        {'output': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f:1', 'value': 16336000000}]
    min_latest_height = 503351
    txid = "fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690"
    txheight = 135235
    txinputs = [{"output": "7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583:1", 'value': 1000000},
                {"output": "da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf:1", 'value': 100000}]
    tx = {'txid': 'fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690'}
    num_merkle_siblings = 6

    def test_block_info(self):
        self.assertBlockHeadersOK()

    def test_merkle_proof(self):
        self.assertMerkleProofOK()

    def test_block_height(self):
        self.assertBlockHeightOK()
        self.assertLatestBlockHeightOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_unspent(self):
        self.assertUnspentOK()