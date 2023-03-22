from cryptos.coins_async.dash import Dash as AsyncDash
from .base import BaseSyncCoin


class Dash(BaseSyncCoin):
    coin_class = AsyncDash
