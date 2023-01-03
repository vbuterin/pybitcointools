from cryptos.coins_async.dogecoin import Doge as AsyncDoge
from .base import BaseSyncCoin


class Doge(BaseSyncCoin):
    coin_class = AsyncDoge
