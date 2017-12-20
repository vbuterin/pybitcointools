import re
import requests
import datetime

#Docs: https://chain.so/api

base_url = "https://chain.so/api/v2/"
sendtx_url = base_url + "send_tx/%s"
address_url = base_url + "address/%s/%s"
utxo_url = base_url + "get_tx_unspent/%s/%s"
transaction_html_url = ""

def unspent(addr, coin_symbol="BTC"):
    url = utxo_url % (coin_symbol, addr)
    response = requests.get(url)
    txs = response.json()['data']['txs']
    for i, tx in enumerate(txs):
        txs[i] = {
            'output': "%s:%s" % (tx['txid'], tx['output_no']),
            'value': int(tx['value'].replace('.', '')),
            'time': datetime.datetime.fromtimestamp(tx['time']).strftime('%c')
        }
    return txs

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
