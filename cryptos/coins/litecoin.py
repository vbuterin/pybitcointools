from cryptos.coins_async.litecoin import Litecoin as AsyncLitecoin
from .base import BaseSyncCoin


class Litecoin(BaseSyncCoin):
    coin_class = AsyncLitecoin
