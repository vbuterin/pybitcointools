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

def unspent(*addrs, coin_symbol=None, api_key=None, **kwargs):

    if len(addrs) == 0:
        return []

    addrs = parse_addr_args(*addrs)

    if len(addrs) == 1:
        txs = api.get_address_details(addrs[0], coin_symbol=coin_symbol, unspent_only=True, **kwargs)['txrefs']
        for tx in txs:
            tx['output'] = "%s:%s" % (tx['tx_hash'], tx['tx_output_n'])
        return txs
    result = api.get_addresses_details(addrs, coin_symbol=coin_symbol, api_key=None, unspent_only=True, **kwargs)['txrefs']
    return result

def pushtx(tx, coin_symbol=None, api_key=None):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    return api.pushtx(tx, coin_symbol=coin_symbol, api_key=None)

# Gets the transaction output history of an address,
# including whether or not they have been spent
def history(addr, coin_symbol=None, api_key=None, **kwargs):
    return api.get_address_full(addr, coin_symbol=coin_symbol, api_key=None, **kwargs)