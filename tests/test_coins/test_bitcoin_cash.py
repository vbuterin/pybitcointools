from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestBitcoinCash(BaseCoinTestCase):
    name = "Bitcoin Cash"
    coin = coins.BitcoinCash
    addresses = ["1Ba7UmguphMX1g8ibyWQL62qzNu7mrXLVz", "16mBWqf9zefiZcKrKSf6uo3He9ipzPyuTb", "15pXUHkdBXFeUUetZJnJqNoD7dyCzaJFUn"]
    blockcypher_coin_symbol = "btc"
    fee = 54400
    testnet = False
    min_latest_height = 512170
    num_merkle_siblings = 9
    txid = "e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476"
    txheight = 508381
    unspent_address = "1KomPE4JdF7P4tBzb12cyqbBfrVp4WYxNS"
    unspent = [
            {'output': 'e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476:1', 'value': 249077026}]

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