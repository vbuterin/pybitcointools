from cryptos.coins_async.bitcoin_cash import BitcoinCash as AsyncBitcoinCash
from .base import BaseSyncCoin


class BitcoinCash(BaseSyncCoin):
    coin_class = AsyncBitcoinCash
