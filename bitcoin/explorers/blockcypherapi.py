#!/usr/bin/python
import re
from blockcypher import api


from bitcoin.main import string_or_bytes_types


def is_testnet(inp):
    '''Checks if inp is a testnet address or if UTXO is a known testnet TxID''' 
    if isinstance(inp, (list, tuple)) and len(inp) >= 1:
        return any([is_testnet(x) for x in inp])
    elif not isinstance(inp, string_or_bytes_types):    # sanity check
        raise TypeError("Input must be str/unicode, not type %s" % str(type(inp)))

    if not inp or (inp.lower() in ("btc", "btc-testnet")):
        pass

    ## ADDRESSES
    if inp[0] in "123mn":
        if re.match("^[2mn][a-km-zA-HJ-NP-Z0-9]{26,33}$", inp):
            return True
        elif re.match("^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$", inp):
            return False
        raise TypeError("{0} is unknown input".format(inp))


def set_network(*args):
    '''Decides if args for unspent/fetchtx/pushtx are mainnet or testnet'''
    if all(not is_testnet(arg) for arg in args):
        return "btc"
    if all(is_testnet(arg) for arg in args):
        return "btc-testnet"
    raise Exception("Mixed Testnet/Mainnet queries")

def parse_addr_args(*args, coin_symbol=None):
    # Valid input formats: unspent([addr1, addr2, addr3])
    #                      unspent([addr1, addr2, addr3], coin_symbol="btc")
    #                      unspent(addr1, addr2, addr3)
    #                      unspent(addr1, addr2, addr3, coin_symbol="btc")
    addr_args = args
    if len(args) == 0:
        return [], coin_symbol
    if len(addr_args) == 1 and isinstance(addr_args[0], list):
        addr_args = addr_args[0]
    elif isinstance(addr_args, tuple):
        addr_args = list(addr_args)
    if not coin_symbol:
        coin_symbol = set_network(addr_args)
    return coin_symbol, addr_args

def unspent(*args, coin_symbol=None, **kwargs):

    coin, addrs = parse_addr_args(*args, coin_symbol=coin_symbol)

    if len(addrs) == 0:
        return []

    return api.get_addresses_details(addrs, coin_symbol=coin, unspent_only=True, **kwargs)


def pushtx(tx, coin_symbol='btc'):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    return api.pushtx(tx, coin_symbol=coin_symbol)

# Gets the transaction output history of a given set of addresses,
# including whether or not they have been spent
def history(addr, **kwargs):
    # Valid input formats: history([addr1, addr2,addr3])
    #                      history(addr1, addr2, addr3)

    coin, addrs = parse_addr_args(addr)

    return api.get_address_full(addr, coin_symbol=coin, **kwargs)