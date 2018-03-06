from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestLitecoinTestnet(BaseCoinTestCase):
    name = "Litecoin Testnet"
    coin = coins.Litecoin
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu", "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_addresses = ["2N3CxTkwr7uSh6AaZKLjWeR8WxC43bQ2QRZ", "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU", "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    min_latest_height = 336741
    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000,}]

    num_merkle_siblings = 2
    txid = "2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93"
    txheight = 296568
    txinputs = [{'output': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984:0', 'value': 17984768},
                {'output': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984:1', 'value': 161862912},
                {'output': 'f27a53b9433eeb9d011a8c77439edb7a582a01166756e00ea1076699bfa58371:1', 'value': 17941248}]
    tx = {'txid': '2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93'}

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

    def test_transaction_segwit(self):
        self.assertSegwitTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()
