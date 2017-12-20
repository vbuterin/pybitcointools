from .bitcoin import Bitcoin

class Dash(Bitcoin):
    display_name = "Dash"
    coin_symbol = "DASH"
    magicbyte = 76

class DashTestNet(Dash):
    display_name = "Dash Testnet"
    coin_symbol = "DASHTEST"
    magicbyte = 140