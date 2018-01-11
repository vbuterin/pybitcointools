import re
import requests
import datetime
from .utils import parse_addr_args

#Base module for all insight-based explorers

sendtx_url = "%s/tx/send"
address_url = "%s/addrs/%s/txs"
utxo_url = "%s/addrs/%s/utxo"
fetchtx_url = "%s/tx/%s"
current_block_height_url = "%s/status?q=getInfo"
block_hash_by_height_url = "%s/block-index/%s"
block_info_url = "%s/block/%s"

def unspent(base_url, *args):

    addrs = parse_addr_args(*args)

    if len(addrs) == 0:
        return []

    url = utxo_url % (base_url, ','.join(addrs))

    response = requests.get(url)
    txs = response.json()
    for i, tx in enumerate(txs):
        if 'satoshis' in tx.keys():
            txs[i] = {
                'output': "%s:%s" % (tx['txid'], tx['vout']),
                'value': tx['satoshis'],
            }
        else:
            txs[i] = {
                'output': "%s:%s" % (tx['txid'], tx['vout']),
                'value': int(tx['amount'] * 100000000),
            }
    return txs

def fetchtx(base_url, txhash):
    url = fetchtx_url % (base_url, txhash)
    response = requests.get(url)
    return response.json()

def txinputs(base_url, txhash):
    result = fetchtx(base_url, txhash)
    inputs = result['vin']
    unspents = [{'output': "%s:%s" % (i['txid'], i['vout']), 'value': i['valueSat']} for i in inputs]
    return unspents

def pushtx(base_url, network, tx):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')

    url = sendtx_url % base_url
    response = requests.post(url, {'rawtx': tx})
    if response.status_code == 200:
        result = response.json()
        return {'status': 'success',
                'data': {
                    'txid': result['txid'],
                    'network': network
                    }
                }
    return response

# Gets the transaction output history of a given set of addresses,
# including whether or not they have been spent
def history(base_url, *args):
    # Valid input formats: history([addr1, addr2,addr3])
    #                      history(addr1, addr2, addr3)

    addrs = parse_addr_args(*args)

    if len(addrs) == 0:
        return []

    url = address_url % (base_url, ','.join(addrs))
    response = requests.get(url)
    return response.json()

def block_height(base_url, txhash):
    tx = fetchtx(base_url, txhash)
    return tx.get('blockheight', None) or tx.get('height', None)

def block_info(base_url, height):
    url = block_hash_by_height_url % (base_url, height)
    response = requests.get(url)
    blockhash = response.json()['blockHash']
    url = block_info_url % (base_url, blockhash)
    response = requests.get(url)
    data = response.json()
    return {
        'version': data['version'],
        'hash': data['hash'],
        'prevhash': data['previousblockhash'],
        'timestamp': data['time'],
        'merkle_root': data['merkleroot'],
        'bits': data['bits'],
        'nonce': data['nonce'],
        'tx_hashes': data['tx']
    }


def current_block_height(base_url):
    url = current_block_height_url % base_url
    response = requests.get(url)
    result = response.json()
    return result['info']['blocks']