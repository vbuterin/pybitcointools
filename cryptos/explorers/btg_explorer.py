from . import base_insight as insight

def get_url(is_test):
    if is_test:
        return "https://testnet.btgexplorer.com/api"
    return "https://btgexplorer.com/api"

def unspent(*args, testnet=False):
    base_url = get_url(testnet)
    return insight.unspent(base_url, *args)

def fetchtx(txhash, testnet=False):
    base_url = get_url(testnet)
    return insight.fetchtx(base_url, txhash)

def txinputs(txhash, testnet=False):
    base_url = get_url(testnet)
    return insight.txinputs(base_url, txhash)

def pushtx(tx, testnet=False):
    base_url = get_url(testnet)
    return insight.pushtx(base_url, "BTGTEST" if testnet else "BTG", tx)

def history(*args,  testnet=False):
    base_url = get_url(testnet)
    return insight.history(base_url, *args)
