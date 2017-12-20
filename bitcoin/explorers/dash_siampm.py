from . import base_insight as insight

def get_url(is_test):
    if is_test:
        return "https://test.insight.dash.siampm.com/api"
    return "https://insight.dash.siampm.com/api"

def unspent(*args, testnet=False):
    base_url = get_url(testnet)
    return insight.unspent(base_url, *args)

def pushtx(tx, testnet=False):
    base_url = get_url(testnet)
    return insight.pushtx(base_url, "DASHTEST" if testnet else "DASH", tx)

def history(*args,  testnet=False):
    base_url = get_url(testnet)
    return insight.history(base_url, *args)
