from cryptos.coins_async.bitcoin import Litecoin as AsyncLitecoin
from .base import BaseSyncCoin


class Bitcoin(BaseSyncCoin):
    coin_class = AsyncLitecoin
