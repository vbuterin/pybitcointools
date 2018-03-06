from unittest import skip
from cryptos import coins
from cryptos.testing.testcases import BaseCoinTestCase


class TestDogeTestnet(BaseCoinTestCase):
    name = "Doge Testnet"
    coin = coins.Doge
    addresses = ['nn1xreE17QZVwuxxVY3N497SygcBPsm15j', 'nbQPs6XNsA2NzndkhpLDASy4Khg8ZfhUfj', 'naGXBTzJbwp4QRNzZJAjx651T6duZy2kgV']
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above address_derivations in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "ncst7MzasMBQFwx2LuCwj8Z6F4pCRppzBP"
    unspent = [{'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000}]

    def test_transaction(self):
        self.assertTransactionOK()