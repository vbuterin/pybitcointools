from unittest import skip
import time
from cryptos import coins
from cryptos.transaction import serialize
from cryptos.testing.testcases import BaseCoinTestCase

class TestBitcoinTestnet(BaseCoinTestCase):
    name = "Bitcoin Testnet"
    coin = coins.Bitcoin
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu","mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_addresses = ["2N3CxTkwr7uSh6AaZKLjWeR8WxC43bQ2QRZ", "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU", "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    new_segwit_addresses = ["tb1qcwzf2q6zedhcma23wk6gtp5r3vp3xradjc23st", "tb1qfuvnn87p787z7nqv9seu4e8fqel83yacg7yf2r", "tb1qg237zx5qkf0lvweqwnz36969zv4uewapph2pws"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    fee = 54400
    blockcypher_coin_symbol = "btc-testnet"
    testnet = True

    num_merkle_siblings = 5
    min_latest_height = 1258030
    multisig_address = "2ND6ptW19yaFEmBa5LtEDzjKc2rSsYyUvqA"
    unspent_address = ["ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA", "2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy",
                       "tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq"]
    unspent = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'tx_pos': 0, 'height': 1238008,
         'value': 180000000, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'tx_pos': 1, 'height': 1275633,
         'value': 173980000, 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'tx_pos': 0, 'height': 1275633,
         'value': 6000000, 'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    balances = [
        {'confirmed': 180000000, 'unconfirmed': 0, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA', 'total': 180000000},
        {'confirmed': 173980000, 'unconfirmed': 0, 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy',
         'total': 173980000},
        {'confirmed': 6000000, 'unconfirmed': 0, 'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq',
         'total': 6000000}]
    history = [{'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'height': 1238008,
                'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
                {'tx_hash': 'e25d8f4036e44159b0364b45867e08ae47a57dda68ba800ba8abe1fb2dc54a40', 'height': 1275633,
                 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
                    {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'height': 1275633,
                     'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
                    {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'height': 1275633,
                     'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    txid = "1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c"
    txheight = 1238008
    txinputs = [{'output': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33:1', 'value': 190453372316}]
    tx = {'txid': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c'}

    @skip('Takes too long')
    def test_subscribe_block_headers(self):
        self.assertSubscribeBlockHeadersOK()

    def test_subscribe_address(self):
        self.assertSubscribeAddressOK()

    def test_balance(self):
        self.assertBalancesOK()

    def test_unspent(self):
        self.assertUnspentOK()

    def test_history(self):
        self.assertHistoryOK()

    def test_block_headers(self):
        self.assertBlockHeadersOK()

    @skip("Not working")
    def test_merkle_proof(self):
        self.assertMerkleProofOK()

    def test_gettx(self):
        self.assertGetSegwitTXOK()

    def test_transaction(self):
        self.assertTransactionOK()

    def test_transaction_mixed_segwit(self):
        self.assertMixedSegwitTransactionOK()

    def test_transaction_segwit(self):
        self.assertSegwitTransactionOK()

    def test_transacton_new_segwit(self):
        self.assertNewSegwitTransactionOK()

    def test_transaction_multisig(self):
        self.assertMultiSigTransactionOK()

    def test_sendmultitx(self):
        self.assertSendMultiTXOK()

    def test_send(self):
        self.assertSendOK()