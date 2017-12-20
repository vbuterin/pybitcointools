from .bitcoin import Bitcoin

class Doge(Bitcoin):
    display_name = "Dogecoin"
    coin_symbol = "DOGE"
    magicbyte = 30

class DogeTestNet(Doge):
    display_name = "Dogecoin Testnet"
    coin_symbol = "DOGETEST"
    magicbyte = 113
