from cryptos.coins_async.bitcoin import Bitcoin as AsyncDash
from .base import BaseSyncCoin


class Bitcoin(BaseSyncCoin):
    coin_class = AsyncDash
