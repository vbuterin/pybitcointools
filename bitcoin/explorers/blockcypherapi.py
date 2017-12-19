#!/usr/bin/python
import re
from blockcypher import api

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

def unspent(*addrs, coin_symbol=None, **kwargs):

    if len(addrs) == 0:
        return []

    addrs = parse_addr_args(*addrs)

    return api.get_addresses_details(addrs, coin_symbol=coin_symbol, unspent_only=True, **kwargs)


def pushtx(tx, coin_symbol=None):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    return api.pushtx(tx, coin_symbol=coin_symbol)

# Gets the transaction output history of a given set of addresses,
# including whether or not they have been spent
def history(*addrs, coin_symbol=None, **kwargs):
    # Valid input formats: history([addr1, addr2,addr3])
    #                      history(addr1, addr2, addr3)


    if len(addrs) == 0:
        return []

    addrs = parse_addr_args(*addrs)

    return api.get_address_full(addrs, coin_symbol=coin_symbol, **kwargs)