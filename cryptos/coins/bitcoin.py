from cryptos.coins_async.bitcoin import Bitcoin as AsyncBitcoin
from .base import BaseSyncCoin


class Bitcoin(BaseSyncCoin):
    coin_class = AsyncBitcoin
