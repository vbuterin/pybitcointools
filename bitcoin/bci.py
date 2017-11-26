#!/usr/bin/python
import json, re
import random
import sys
import requests

from bitcoin.main import from_string_to_bytes, string_or_bytes_types, bin_dbl_sha256, bytes_to_hex_string, safe_from_hex

try:
    from urllib.request import build_opener
except:
    from urllib2 import build_opener


# Makes a request to a given URL (first arg) and optional params (second arg)
def make_request(*args):
    opener = build_opener()
    opener.addheaders = [('User-agent',
                          'Mozilla/5.0'+str(random.randrange(1000000)))]
    try:
        return opener.open(*args).read().strip()
    except Exception as e:
        try:
            p = e.read().strip()
        except:
            p = e
        raise Exception(p)

def is_testnet(inp):
    '''Checks if inp is a testnet address or if UTXO is a known testnet TxID''' 
    if isinstance(inp, (list, tuple)) and len(inp) >= 1:
        return any([is_testnet(x) for x in inp])
    elif not isinstance(inp, string_or_bytes_types):    # sanity check
        raise TypeError("Input must be str/unicode, not type %s" % str(type(inp)))

    if not inp or (inp.lower() in ("btc", "testnet")): 
        pass

    ## ADDRESSES
    if inp[0] in "123mn":
        if re.match("^[2mn][a-km-zA-HJ-NP-Z0-9]{26,33}$", inp):
            return True
        elif re.match("^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$", inp):
            return False
        else:
            #sys.stderr.write("Bad address format %s")
            return None

    ## TXID
    elif re.match('^[0-9a-fA-F]{64}$', inp):
        base_url = "http://api.blockcypher.com/v1/btc/{network}/txs/{txid}?includesHex=false"
        try:
            # try testnet fetchtx
            make_request(base_url.format(network="test3", txid=inp.lower()))
            return True
        except:
            # try mainnet fetchtx
            make_request(base_url.format(network="main", txid=inp.lower()))
            return False
        sys.stderr.write("TxID %s has no match for testnet or mainnet (Bad TxID)")
        return None
    else:
        raise TypeError("{0} is unknown input".format(inp))


def set_network(*args):
    '''Decides if args for unspent/fetchtx/pushtx are mainnet or testnet'''
    if all(not is_testnet(arg) for arg in args):
        return "btc"
    if all(is_testnet(arg) for arg in args):
        return "testnet"
    raise Exception("Mixed Testnet/Mainnet queries")

def parse_addr_args(*args):
    # Valid input formats: unspent([addr1, addr2, addr3])
    #                      unspent([addr1, addr2, addr3], network)
    #                      unspent(addr1, addr2, addr3)
    #                      unspent(addr1, addr2, addr3, network)
    addr_args = args
    network = "btc"
    if len(args) == 0:
        return [], 'btc'
    elif len(args) >= 1 and args[-1] in ('testnet', 'btc', 'bcy_test'):
        network = args[-1]
        if isinstance(args[0], (list)):
            addr_args = args[0]
        else:
            addr_args = list(args[:-1])
    elif len(addr_args) == 1 and isinstance(addr_args[0], list):
        addr_args = addr_args[0]
        network = set_network(addr_args)
    elif isinstance(addr_args, tuple):
        addr_args = list(addr_args)
        network = set_network(addr_args)
    return network, addr_args

def make_unspent(o):
    return {
                    "output": o['tx_hash_big_endian']+':'+str(o['tx_output_n']),
                    "value": o['value']
                }

# Gets the unspent outputs of one or more addresses
def bci_unspent(*args):

    network, addrs = parse_addr_args(*args)

    if len(addrs) == 0:
        return []

    if network == 'btc':
        url = 'https://blockchain.info/unspent?active=%s&limit=1000' % '|'.join(addrs)
    else:
        raise Exception(
            'Unsupported network {0} for blockchain.info'.format(network))

    data = make_request(url)
    outputs = json.loads(data.decode("utf-8"))["unspent_outputs"]
    u = [make_unspent(o) for o in outputs]
    return u

blockcypher_net_to_urls = {'testnet': 'btc/test3', 'bcy_test': 'bcy/test', 'btc': 'btc/main'}

def blockcypher_unspent(*args):

    network, addrs = parse_addr_args(*args)

    if len(addrs) == 0:
        return []
    try:
        url = 'https://api.blockcypher.com/v1/%s/addrs/%s?unspentOnly=true&limit=2000' % (blockcypher_net_to_urls[network], ';'.join(addrs))
    except KeyError:
        raise Exception(
            'Unsupported network {0} for blockcypher'.format(network))

    response = make_request(url)
    data = json.loads(response.decode("utf-8"))
    if isinstance(data, dict):
        outputs = data.get('txrefs', [])
    else:
        outputs = []
        for a in data:
            outputs += a.get('txrefs', [])
    for o in outputs:
        o['tx_hash_big_endian'] = o['tx_hash']
    u = [make_unspent(o) for o in outputs]
    return u

unspent_getters = {
    'bci': bci_unspent,
    'blockcypher': blockcypher_unspent,
}


def unspent(*args, **kwargs):
    f = unspent_getters.get(kwargs.get('source', ''), blockcypher_unspent)
    return f(*args)


# Gets the transaction output history of a given set of addresses,
# including whether or not they have been spent
def history(*args):
    # Valid input formats: history([addr1, addr2,addr3])
    #                      history(addr1, addr2, addr3)
    if len(args) == 0:
        return []
    elif isinstance(args[0], list):
        addrs = args[0]
    else:
        addrs = args

    txs = []
    for addr in addrs:
        offset = 0
        while 1:
            gathered = False
            while not gathered:
                try:
                    data = make_request(
                        'https://blockchain.info/address/%s?format=json&offset=%s' %
                        (addr, offset))
                    gathered = True
                except Exception as e:
                    try:
                        sys.stderr.write(e.read().strip())
                    except:
                        sys.stderr.write(str(e))
                    gathered = False
            try:
                jsonobj = json.loads(data.decode("utf-8"))
            except:
                raise Exception("Failed to decode data: "+data)
            txs.extend(jsonobj["txs"])
            if len(jsonobj["txs"]) < 50:
                break
            offset += 50
            sys.stderr.write("Fetching more transactions... "+str(offset)+'\n')
    outs = {}
    for tx in txs:
        for o in tx["out"]:
            if o.get('addr', None) in addrs:
                key = str(tx["tx_index"])+':'+str(o["n"])
                outs[key] = {
                    "address": o["addr"],
                    "value": o["value"],
                    "output": tx["hash"]+':'+str(o["n"]),
                    "block_height": tx.get("block_height", None)
                }
    for tx in txs:
        for i, inp in enumerate(tx["inputs"]):
            if "prev_out" in inp:
                if inp["prev_out"].get("addr", None) in addrs:
                    key = str(inp["prev_out"]["tx_index"]) + \
                        ':'+str(inp["prev_out"]["n"])
                    if outs.get(key):
                        outs[key]["spend"] = tx["hash"]+':'+str(i)
    return [outs[k] for k in outs]

# Pushes a transaction to the network using https://blockchain.info/pushtx
def bci_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    return make_request(
        'https://blockchain.info/pushtx',
        from_string_to_bytes('tx='+tx)
    )


def eligius_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    s = make_request(
        'http://eligius.st/~wizkid057/newstats/pushtxn.php',
        'transaction='+tx+'&send=Push')
    strings = re.findall('string[^"]*"[^"]*"', s)
    for string in strings:
        quote = re.findall('"[^"]*"', string)[0]
        if len(quote) >= 5:
            return quote[1:-1]

def blockcypher_pushtx(tx, network='btc'):
    try:
        url = 'https://api.blockcypher.com/v1/%s/txs/push' % blockcypher_net_to_urls[network]
    except KeyError:
        raise Exception(
            'Unsupported network {0} for blockcypher'.format(network))

    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    return requests.post(url, json={'tx': tx})


pushtx_getters = {
    'bci': bci_pushtx,
    'blockcypher': blockcypher_pushtx,
}


def pushtx(*args, **kwargs):
    f = pushtx_getters.get(kwargs.pop('source', ''), blockcypher_pushtx)
    return f(*args, **kwargs)

def last_block_height_bci(network="btc"):
    if network != "btc":
        raise Exception(
            'Unsupported network {0} for blockchain.info'.format(network))
    data = make_request('https://blockchain.info/latestblock')
    jsonobj = json.loads(data.decode("utf-8"))
    return jsonobj["height"]

def last_block_height_blockcypher(network='btc'):
    try:
        url = "https://api.blockcypher.com/v1/%s" % blockcypher_net_to_urls[network]
    except KeyError:
        raise Exception(
            'Unsupported network {0} for blockcypher'.format(network))
    data = make_request(url)
    jsonobj = json.loads(data.decode("utf-8"))
    return jsonobj['height']

block_height_getters = {
    'bci': last_block_height_bci,
    'blockcypher': last_block_height_blockcypher,
}

def last_block_height(*args, source="blockcypher", **kwargs):
    return block_height_getters[source](*args, **kwargs)


def encode_tx_hashes(txhashes):
    for i, txhash in enumerate(txhashes):
        if not re.match('^[0-9a-fA-F]*$', txhash):
            txhash = txhash.encode('hex')
            txhashes[i] = txhash
    return txhashes

# Gets a specific transaction
def bci_fetchtx(txhash):
    if isinstance(txhash, list):
        return [bci_fetchtx(h) for h in txhash]
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = txhash.encode('hex')
    data = make_request('https://blockchain.info/rawtx/'+txhash+'?format=hex')
    return data


def blockcypher_fetchtx(txhash, network='btc'):
    if not isinstance(txhash, (list, tuple)):
        txhash = [txhash]
    txhash = encode_tx_hashes(txhash)
    try:
        url = "https://api.blockcypher.com/v1/%s/txs/%s" % (blockcypher_net_to_urls[network], ';'.join(txhash))
    except KeyError:
        raise Exception(
            'Unsupported network {0} for blockcypher'.format(network))
    response = make_request("%s?includeHex=true" % url)
    data = json.loads(response.decode("utf-8"))
    if isinstance(data, dict):
        return from_string_to_bytes(data['hex'])
    return [from_string_to_bytes(d['hex']) for d in data]

fetchtx_getters = {
    'bci': bci_fetchtx,
    'blockcypher': blockcypher_fetchtx,
}

def fetchtx(*args, **kwargs):
    f = fetchtx_getters.get(kwargs.get('source', ''), blockcypher_fetchtx)
    return f(*args)

def firstbits(address):
    if len(address) >= 25:
        return make_request('https://blockchain.info/q/getfirstbits/'+address)
    else:
        return make_request(
            'https://blockchain.info/q/resolvefirstbits/'+address)


def get_block_at_height(height):
    j = json.loads(make_request("https://blockchain.info/block-height/" +
                   str(height)+"?format=json").decode("utf-8"))
    for b in j['blocks']:
        if b['main_chain'] is True:
            return b
    raise Exception("Block at this height not found")


def _get_block(inp):
    if len(str(inp)) < 64:
        return get_block_at_height(inp)
    else:
        return json.loads(make_request(
                          'https://blockchain.info/rawblock/'+inp).decode("utf-8"))


def bci_get_block_header_data(inp):
    j = _get_block(inp)
    return {
        'version': j['ver'],
        'hash': j['hash'],
        'prevhash': j['prev_block'],
        'timestamp': j['time'],
        'merkle_root': j['mrkl_root'],
        'bits': j['bits'],
        'nonce': j['nonce'],
    }

def blockcypher_get_block_header_data(height, network='btc'):
    try:
        url = "https://api.blockcypher.com/v1/%s/blocks/%s" % (blockcypher_net_to_urls[network], height)
    except KeyError:
        raise Exception(
            'Unsupported network {0} for blockcypher'.format(network))

    j = json.loads(make_request(url).decode("utf-8"))
    return {
        'version': j['ver'],
        'hash': j['hash'],
        'prevhash': j['prev_block'],
        'timestamp': j['time'],
        'merkle_root': j['mrkl_root'],
        'bits': j['bits'],
        'nonce': j['nonce'],
    }

"""blockr api no longer working, timestamp can be got from block header data above??
def get_block_timestamp(height, network='btc'):
    if network == 'testnet':
        blockr_url = "http://tbtc.blockr.io/api/v1/block/info/"
    elif network == 'btc':
        blockr_url = "http://btc.blockr.io/api/v1/block/info/"
    else:
        raise Exception(
            'Unsupported network {0} for get_block_timestamp'.format(network))

    import time, calendar
    if isinstance(height, list):
        k = json.loads(make_request(blockr_url + ','.join([str(x) for x in height])).decode("utf-8"))
        o = {x['nb']: calendar.timegm(time.strptime(x['time_utc'],
             "%Y-%m-%dT%H:%M:%SZ")) for x in k['data']}
        return [o[x] for x in height]
    else:
        k = json.loads(make_request(blockr_url + str(height)).decode("utf-8"))
        j = k['data']['time_utc']
        return calendar.timegm(time.strptime(j, "%Y-%m-%dT%H:%M:%SZ"))"""


block_header_data_getters = {
    'bci': bci_get_block_header_data,
    'blockcypher': blockcypher_get_block_header_data
}


def get_block_header_data(inp, **kwargs):
    f = block_header_data_getters.get(kwargs.get('source', ''),
                                      blockcypher_get_block_header_data)
    return f(inp, **kwargs)


def get_txs_in_block(inp):
    j = _get_block(inp)
    hashes = [t['hash'] for t in j['tx']]
    return hashes


def get_block_height(txhash):
    j = json.loads(make_request('https://blockchain.info/rawtx/'+txhash).decode("utf-8"))
    return j['block_height']

# fromAddr, toAddr, 12345, changeAddress
def get_tx_composite(inputs, outputs, output_value, change_address=None, network=None):
    """mktx using blockcypher API"""
    inputs = [inputs] if not isinstance(inputs, list) else inputs
    outputs = [outputs] if not isinstance(outputs, list) else outputs
    network = set_network(change_address or inputs) if not network else network.lower()
    url = "https://api.blockcypher.com/v1/btc/{network}/txs/new?includeToSignTx=true".format(
                  network=('test3' if network=='testnet' else 'main'))
    is_address = lambda a: bool(re.match("^[123mn][a-km-zA-HJ-NP-Z0-9]{26,33}$", a))
    if any([is_address(x) for x in inputs]):
        inputs_type = 'addresses'        # also accepts UTXOs, only addresses supported presently
    if any([is_address(x) for x in outputs]):
        outputs_type = 'addresses'       # TODO: add UTXO support
    data = {
            'inputs':  [{inputs_type:  inputs}], 
            'confirmations': 0,
            'preference': 'high',
            'outputs': [{outputs_type: outputs, "value": output_value}]
            }
    if change_address:
        data["change_address"] = change_address    # 
    jdata = json.loads(make_request(url, data))
    hash, txh = jdata.get("tosign")[0], jdata.get("tosign_tx")[0]
    assert bytes_to_hex_string(bin_dbl_sha256(safe_from_hex(txh))) == hash, "checksum mismatch %s" % hash
    return txh

blockcypher_mktx = get_tx_composite
