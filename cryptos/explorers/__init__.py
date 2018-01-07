from . import base_insight, bitpay, blockcypher, blockdozer, dash_siampm, sochain

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