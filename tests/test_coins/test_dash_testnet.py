from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestDashTestnet(BaseCoinTestCase):
    name = "Dash Testnet"
    coin = coins.Dash
    addresses = ["ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz", "yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ", "ySPomQ35mpKiV89LDdAM3URFSibNiXEC4J"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True
    num_merkle_siblings = 1
    min_latest_height = 56045
    unspent_address = "yV1AhJ3N3Dh4LeiN1ECYpWuLEgmfcA1y5G"
    unspent = [{'output': '546842058817fc29f18de4ba1f0aa5d45fa429c8716ea59d005f878af463ee6c:0', 'value': 29228600000}]
    txid = "725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0"
    txinputs = [{'output': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777:0', 'value': 4989724076},
                {'output': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777:1', 'value': 44907516684}]
    tx = {'txid': '725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0'}
    txheight = 45550

    def test_block_info(self):
        self.assertBlockHeadersOK()

    def test_merkle_proof(self):
        self.assertMerkleProofOK()

    def test_block_height(self):
        self.assertBlockHeightOK()
        self.assertLatestBlockHeightOK()

    def test_unspent(self):
        self.assertUnspentOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_fetchtx(self):
        self.assertGetTXOK()

    def test_transaction(self):
        self.assertTransactionOK()