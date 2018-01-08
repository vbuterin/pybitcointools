from . import base_insight as insight

def get_url(coin_symbol):
    if coin_symbol == "DASH":
        return "https://insight.dash.siampm.com/api"
    return "https://test.insight.dash.siampm.com/api"

def unspent(*args, coin_symbol="DASH"):
    base_url = get_url(coin_symbol)
    return insight.unspent(base_url, *args)

def fetchtx(tx, coin_symbol="DASH"):
    base_url = get_url(coin_symbol)
    return insight.fetchtx(base_url, tx)

def txinputs(tx, coin_symbol="DASH"):
    base_url = get_url(coin_symbol)
    return insight.txinputs(base_url, tx)

def pushtx(tx, coin_symbol="DASH"):
    base_url = get_url(coin_symbol)
    return insight.pushtx(base_url, coin_symbol, tx)

def history(*args,  coin_symbol="DASH"):
    base_url = get_url(coin_symbol)
    return insight.history(base_url, *args)
