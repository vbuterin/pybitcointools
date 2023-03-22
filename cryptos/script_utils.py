from cryptos.coins_async import BaseCoin, Bitcoin, BitcoinCash, Dash, Litecoin, Doge


coins = {c.coin_symbol: c for c in (Bitcoin, Litecoin, BitcoinCash, Dash, Doge)}


def get_coin(coin_symbol: str, testnet: bool) -> BaseCoin:
    symbol = coin_symbol.upper()
    return coins[symbol](testnet=testnet)


coin_list = [c.lower() for c in coins.keys()]
