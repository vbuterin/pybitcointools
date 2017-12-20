from . import base_insight as insight

#Docs: https://github.com/bitpay/insight-api

base_url = "https://bch-insight.bitpay.com/api"

def unspent(*args):
    return insight.unspent(base_url, *args)

def pushtx(*args):
    return insight.pushtx(base_url, *args)

def history(*args):
    return insight.history(base_url, *args)