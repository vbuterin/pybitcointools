#!/usr/bin/python
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
    response = requests.get(utxo_url % (coin_symbol, addr))
    txs = response.json()['data']['txs']
    for i, tx in enumerate(txs):
        txs[i] = {
            'output': "%s:%s" % (tx['txid'], tx['output_no']),
            'value': int(tx['value'].replace('.', '')),
            'time': datetime.datetime.fromtimestamp(1347517370).strftime('%c')
        }
    return txs

def pushtx(tx, coin_symbol="BTC"):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    response = requests.post(sendtx_url % coin_symbol, {'tx_hex': tx})
    return response.json()

def history(addr, coin_symbol="BTC"):
    response = requests.get(address_url % (coin_symbol, addr))
    return response.json()
