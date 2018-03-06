from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestBitcoinCashTestnet(BaseCoinTestCase):
    name = "Bitcoin Cash Testnet"
    coin = coins.BitcoinCash
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu","mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    num_merkle_siblings = 2
    min_latest_height = 1201889
    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '80700e6d1125deafa22b307f6c7c99e75771f9fc05517fc795a1344eca7c8472:0', 'value': 550000000}]
    txid = "b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a"
    txinputs = [{'output': "cbd43131ee11bc9e05f36f55088ede26ab5fb160cc3ff11785ce9cc653aa414b:1", 'value': 96190578808}]
    tx = {'txid': 'b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a'}
    txheight = 1196454

    def test_block_info(self):
        self.assertBlockHeadersOK()

    def test_merkle_proof(self):
        self.assertMerkleProofOK()

    def test_block_height(self):
        self.assertBlockHeightOK()
        self.assertLatestBlockHeightOK()

    def test_fetchtx(self):
        self.assertGetTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_transaction(self):
        self.assertTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()