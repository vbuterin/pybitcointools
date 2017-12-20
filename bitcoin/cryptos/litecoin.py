from .bitcoin import Bitcoin

class Litecoin(Bitcoin):
    display_name = "Litecoin"
    coin_symbol = "LTC"
    magicbyte = 48

class LitecoinTestnet(Bitcoin):
    display_name = "Litecoin Testnet"
    coin_symbol = "LTCTEST"
    magicbyte = 111