import re
import requests
from cryptos.transaction import public_txhash
from .utils import parse_addr_args

def get_url(coin_symbol):
    if coin_symbol == "BTC":
        return "https://blockchain.info"
    return "https://testnet.blockchain.info"

sendtx_url = "%s/pushtx"
address_url = "%s/address/%s?format=json"
utxo_url = "%s/unspent?active=%s&limit=1000&format=json"
fetchtx_url = "%s/rawtx/%s?format=json"
block_height_url = "%s/block-height/%s?format=json"
latest_block_url = "%s/latestblock"
block_info_url = "%s/rawblock/%s"

def unspent(*args, coin_symbol="BTC"):

    addrs = parse_addr_args(*args)

    if len(addrs) == 0:
        return []

    base_url = get_url(coin_symbol)
    url = utxo_url % (base_url, '|'.join(addrs))
    response = requests.get(url)
    if response.text == "No free outputs to spend":
        return []
    try:

        outputs = response.json()['unspent_outputs']
        for i, o in enumerate(outputs):
            outputs[i] = {
                        "output": o['tx_hash_big_endian']+':'+str(o['tx_output_n']),
                        "value": o['value']
                    }
        return outputs
    except (ValueError, KeyError):
        raise Exception("Unable to decode JSON from result: %s" % response.text)

def fetchtx(txhash, coin_symbol="BTC"):
    base_url = get_url(coin_symbol)
    url = fetchtx_url % (base_url, txhash)
    response = requests.get(url)
    try:
        return response.json()
    except ValueError:
        raise Exception("Unable to decode JSON from result: %s" % response.text)

def tx_hash_from_index(index, coin_symbol="BTC"):
    result = fetchtx(index, coin_symbol=coin_symbol)
    return result['hash']

def txinputs(txhash, coin_symbol="BTC"):
    result = fetchtx(txhash, coin_symbol=coin_symbol)
    inputs = result['inputs']
    unspents = [{'output': "%s:%s" % (
    tx_hash_from_index(i["prev_out"]['tx_index'], coin_symbol=coin_symbol), i["prev_out"]['n']),
                 'value': i["prev_out"]['value']} for i in inputs]
    return unspents

def pushtx(tx, coin_symbol="BTC"):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')

    base_url = get_url(coin_symbol)
    url = sendtx_url % base_url
    hash = public_txhash(tx)
    response = requests.post(url, {'tx': tx})
    if response.status_code == 200:
        return {'status': 'success',
                'data': {
                    'txid': hash,
                    'network': coin_symbol
                    }
                }
    return response

# Gets the transaction output history of a given set of addresses,
# including whether or not they have been spent
def history(*args, coin_symbol="BTC"):
    # Valid input formats: history([addr1, addr2,addr3])
    #                      history(addr1, addr2, addr3)

    addrs = parse_addr_args(*args)

    if len(addrs) == 0:
        return []

    base_url = get_url(coin_symbol)
    url = address_url % (base_url, '|'.join(addrs))
    response = requests.get(url)
    return response.json()

def block_height(txhash, coin_symbol="BTC"):
    tx = fetchtx(txhash,coin_symbol=coin_symbol)
    return tx['block_height']

def block_info(height, coin_symbol="BTC"):
    base_url = get_url(coin_symbol)
    url = block_height_url % (base_url, height)
    response = requests.get(url)
    blocks = response.json()['blocks']
    data = list(filter(lambda d: d['main_chain'], blocks))[0]
    return {
        'version': data['ver'],
        'hash': data['hash'],
        'prevhash': data['prev_block'],
        'timestamp': data['time'],
        'merkle_root': data['mrkl_root'],
        'bits': data['bits'],
        'nonce': data['nonce'],
        'tx_hashes': [t['hash'] for t in data['tx']]
    }

def current_block_height(coin_symbol="BTC"):
    base_url = get_url(coin_symbol)
    url = latest_block_url % base_url
    response = requests.get(url)
    return response.json()["height"]