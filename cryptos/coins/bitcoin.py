from cryptos.coins_async.bitcoin import Bitcoin as AsyncBitcoin
from mixins import BaseCoin


class Bitcoin(AsyncBitcoin, BaseCoin):
    pass
