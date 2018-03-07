from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase

class TestBitcoin(BaseCoinTestCase):
    name = "Bitcoin"
    coin = coins.Bitcoin
    addresses = ["1Ba7UmguphMX1g8ibyWQL62qzNu7mrXLVz", "16mBWqf9zefiZcKrKSf6uo3He9ipzPyuTb", "15pXUHkdBXFeUUetZJnJqNoD7dyCzaJFUn"]
    fee = 54400
    blockcypher_coin_symbol = "btc"
    testnet = False

    balances = [
        {'confirmed': 16341000000, 'unconfirmed': 0, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR', 'total': 16341000000},
        {'confirmed': 8000100000, 'unconfirmed': 0, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT', 'total': 8000100000}]
    history = [{'tx_hash': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34', 'height': 114743,
                     'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
                    {'tx_hash': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f', 'height': 116768,
                     'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
                    {'tx_hash': 'fd232fe21b6ad7f096f3012e935467a7f2177258cdcd07c748502a5b1f31ccd5', 'height': 187296,
                     'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'},
                    {'tx_hash': 'a146923df9579f7c7b9a8f5ddf27e230e8d838117379bdf6b57113ce31bf52e0', 'height': 248365,
                     'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'}]
    unspent_address = ["12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR", "1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT"]
    unspent = [
        {'tx_hash': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34', 'tx_pos': 1, 'height': 114743,
         'value': 5000000, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'tx_hash': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f', 'tx_pos': 1, 'height': 116768,
         'value': 16336000000, 'address': '12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR'},
        {'tx_hash': 'fd232fe21b6ad7f096f3012e935467a7f2177258cdcd07c748502a5b1f31ccd5', 'tx_pos': 0, 'height': 187296,
         'value': 8000000000, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'},
        {'tx_hash': 'a146923df9579f7c7b9a8f5ddf27e230e8d838117379bdf6b57113ce31bf52e0', 'tx_pos': 41, 'height': 248365,
         'value': 100000, 'address': '1A7hMTCfHbQJ1RAtBAVNcUtVsh8i8yFdmT'}]
    min_latest_height = 503351
    txid = "fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690"
    merkle_txhash = "8b712b86b4882a61b1031b828a3e1cde5c62ee8896961a513c744588486cc903"
    merkle_txheight = 509045
    txheight = 509045
    txinputs = [{"output": "7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583:1", 'value': 1000000},
                {"output": "da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf:1", 'value': 100000}]
    tx = {'txid': 'fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690'}
    num_merkle_siblings = 6

    @skip('Takes too long')
    def test_subscribe_block_headers(self):
        self.assertSubscribeBlockHeadersOK()

    def test_balance(self):
        self.assertBalancesOK()

    def test_block_headers(self):
        self.assertBlockHeadersOK()

    @skip("Not working")
    def test_merkle_proof(self):
        self.assertMerkleProofOK()

    def test_gettx(self):
        self.assertGetTXOK()

    def test_history(self):
        self.assertHistoryOK()

    @skip("very high fees")
    def test_transaction(self):
        self.assertTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()

    @skip
    def test_asyncio_concurrent_times(self):
        self.check_asyncio_concurrent_times()
