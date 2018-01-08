import re
import requests

#Docs: https://chain.so/api

base_url = "https://chain.so/api/v2/"
sendtx_url = base_url + "send_tx/%s"
address_url = base_url + "address/%s/%s"
utxo_url = base_url + "get_tx_unspent/%s/%s"
tx_url = base_url + "get_tx/%s/%s"
tx_inputs_url = base_url + "get_tx_inputs/%s/%s"
transaction_html_url = ""

def unspent(addr, coin_symbol="BTC"):
    url = utxo_url % (coin_symbol, addr)
    response = requests.get(url)
    try:
        result = response.json()
        if 'data' in result.keys() and 'txs' in result['data'].keys():
            txs = response.json()['data']['txs']
            for i, tx in enumerate(txs):
                txs[i] = {
                    'output': "%s:%s" % (tx['txid'], tx['output_no']),
                    'value': int(tx['value'].replace('.', '')),
                }
            return txs
        else:
            raise Exception(response.text)
    except ValueError:
        raise Exception("Unable to decode JSON from result: %s" % response.text)

def fetchtx(txhash, coin_symbol="BTC"):
    url = tx_url % (coin_symbol, txhash)
    response = requests.get(url)
    result = response.json()
    return result['data']

def txinputs(txhash, coin_symbol="BTC"):
    url = tx_inputs_url % (coin_symbol, txhash)
    response = requests.get(url)
    result = response.json()
    inputs = result['data']['inputs']
    unspents = [{'output': (i['from_output']['txid'] + ":" + str(i['from_output']['output_no'])), 'value': int(float(i['value']) * 100000000)} for i in inputs]
    return unspents

def pushtx(tx, coin_symbol="BTC"):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    url = sendtx_url % coin_symbol
    response = requests.post(url, {'tx_hex': tx})
    return response.json()

def history(addr, coin_symbol="BTC"):
    url = address_url % (coin_symbol, addr)
    response = requests.get(url)
    return response.json()
