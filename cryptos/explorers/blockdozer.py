from . import base_insight as insight

base_url = "https://%s.blockdozer.com/insight-api"

def unspent(*args, coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.unspent(base_url_for_coin, *args)

def pushtx(tx,  coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.pushtx(base_url_for_coin, coin_symbol, tx)

def fetchtx(txhash, coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.fetchtx(base_url_for_coin, txhash)

def txinputs(txhash, coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.txinputs(base_url_for_coin, txhash)

def history(*args,  coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.history(base_url_for_coin, *args)

def block_height(tx, coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.block_height(base_url_for_coin, tx)

def current_block_height(coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.current_block_height(base_url_for_coin)

def block_info(height, coin_symbol="bcc"):
    base_url_for_coin = base_url % coin_symbol
    return insight.block_info(base_url_for_coin, height)