from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestBitcoinGoldRegtest(BaseCoinTestCase):
    name = "Bitcoin Cash Testnet"
    coin = coins.BitcoinGold
    testnet = True

    def test_transaction(self):
        tx = {'locktime': 0, 'version': 1, 'ins': [{'script': '', 'sequence': 0xffffffff, 'outpoint': {
            'hash': 'cc58ce5e96c06294e2e498d061c9652e1981232e160b491cb73e205d411a7ea9', 'index': 1},
                                                      'amount': 800000000}],
              'outs': [{'script': '76a914839cd17bb373d7732ce9537c4821be656e5d0e6188ac', 'value': 400000000},
                       {'script': '76a914fc839d8c0b80176ef6dab3223aa64882eb1b2c8a88ac', 'value': 399000000}]}
        priv = 'cP7Dp4xr3RuYPa9tcwFE7VueUMAm1G7Y4M3ANd2NnRLMYh7Ggo4k'
        coin = self.coin(testnet=self.testnet)
        tx = coin.sign(tx, 0, priv)
        self.assertEqual(serialize(tx),
                         "0100000001a97e1a415d203eb71c490b162e2381192e65c961d098e4e29462c0965ece58cc010000006a473044022059c249ce08f1453e0cd015b409098ee185049aaf9c5ba414d9b106234aca72eb02202ae0eb60af44f062b9d3ec8d5f3d8e8b01541888d1b65ecd9485e7a7657d72b14121039565b145956ccd9f100d72beb700b9e4fd307e14a0a3349b4a48384b41b29094ffffffff020084d717000000001976a914839cd17bb373d7732ce9537c4821be656e5d0e6188acc041c817000000001976a914fc839d8c0b80176ef6dab3223aa64882eb1b2c8a88ac00000000")
