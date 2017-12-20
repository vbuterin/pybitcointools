from . import base_insight as insight

base_url = "http://%s.blockdozer.com/insight-api"

def unspent(*args, coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.unspent(base_url_for_coin, *args)

def pushtx(tx,  coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.pushtx(base_url_for_coin, coin_symbol, tx)

def history(*args,  coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.history(base_url_for_coin, *args)
