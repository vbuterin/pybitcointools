#!/usr/bin/python
import re
import requests

#https://github.com/bitpay/insight-api

base_url = "https://bch-insight.bitpay.com/api"
sendtx_url = base_url + "/tx/send"
address_url = base_url + "/addrs/%s/txs"
utxo_url = base_url + "/addrs/%s/utxo"

def parse_addr_args(*args):
    # Valid input formats: unspent([addr1, addr2, addr3])
    #                      unspent([addr1, addr2, addr3], coin_symbol="btc")
    #                      unspent(addr1, addr2, addr3)
    #                      unspent(addr1, addr2, addr3, coin_symbol="btc")
    addr_args = args
    if len(args) == 0:
        return []
    if len(addr_args) == 1 and isinstance(addr_args[0], list):
        addr_args = addr_args[0]
    elif isinstance(addr_args, tuple):
        addr_args = list(addr_args)
    return addr_args

def unspent(*args, **kwargs):

    addrs = parse_addr_args(*args)

    if len(addrs) == 0:
        return []

    response = requests.post(utxo_url % addrs.join(','))
    return response.json()

def pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    response = requests.post(sendtx_url, {'rawtx': tx})
    return response.json()

# Gets the transaction output history of a given set of addresses,
# including whether or not they have been spent
def history(*args):
    # Valid input formats: history([addr1, addr2,addr3])
    #                      history(addr1, addr2, addr3)

    addrs = parse_addr_args(*args)

    if len(addrs) == 0:
        return []

    response = requests.post(address_url % addrs.join(','))
    return response.json()
