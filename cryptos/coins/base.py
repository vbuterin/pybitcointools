from ..transaction import *
from ..blocks import mk_merkle_proof
from .. import segwit_addr
from ..explorers import blockchain
from ..electrumx_client.rpc import ElectrumXClient
from ..keystore import *
from ..wallet import *
from ..py3specials import *
from ..py2specials import *

class BaseCoin(object):
    """
    Base implementation of crypto coin class
    All child coins must follow same pattern.
    """

    coin_symbol = None
    display_name = None
    enabled = True
    segwit_supported = None
    magicbyte = None
    script_magicbyte = None
    segwit_hrp = None
    explorer = blockchain
    client = ElectrumXClient
    client_kwargs = {
        'server_file': 'bitcoin.json',
        'servers': (),
        'host': None,
        'port': 50001,
        'timeout': 15,
        'max_servers': 5,
        'loop': None
    }
    is_testnet = False
    address_prefixes = ()
    testnet_overrides = {}
    hashcode = SIGHASH_ALL
    secondary_hashcode = None
    hd_path = 0
    wif_prefix = 0x80
    wif_script_types = {
        'p2pkh': 0,
        'p2wpkh': 1,
        'p2wpkh-p2sh': 2,
        'p2sh': 5,
        'p2wsh': 6,
        'p2wsh-p2sh': 7
    }
    xprv_headers = {
        'p2pkh': 0x0488ade4,
        'p2wpkh-p2sh': 0x049d7878,
        'p2wsh-p2sh': 0x295b005,
        'p2wpkh': 0x4b2430c,
        'p2wsh': 0x2aa7a99
    }
    xpub_headers = {
        'p2pkh': 0x0488b21e,
        'p2wpkh-p2sh': 0x049d7cb2,
        'p2wsh-p2sh': 0x295b43f,
        'p2wpkh': 0x4b24746,
        'p2wsh': 0x2aa7ed3
    }
    electrum_xprv_headers = xprv_headers
    electrum_xpub_headers = xpub_headers


    def __init__(self, testnet=False, **kwargs):
        if testnet:
            self.is_testnet = True
            for k, v in self.testnet_overrides.items():
                setattr(self, k, v)
        # override default attributes from kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)
        if not self.enabled:
            if self.is_testnet:
                raise NotImplementedError("Due to explorer limitations, testnet support for this coin has not been implemented yet!")
            else:
                raise NotImplementedError("Support for this coin has not been implemented yet!")
        self.address_prefixes = magicbyte_to_prefix(magicbyte=self.magicbyte)
        if self.script_magicbyte:
            self.script_prefixes = magicbyte_to_prefix(magicbyte=self.script_magicbyte)
        else:
            self.script_prefixes = ()
        self.secondary_hashcode = self.secondary_hashcode or self.hashcode
        self._rpc_client = None

    @property
    def rpc_client(self):
        """
        Connect to remove server
        """
        if not self._rpc_client:
            self._rpc_client = self.client(**self.client_kwargs)
        return self._rpc_client


    def unspent(self, *addrs):
        """
        Get unspent transactions for addresses
        """
        return self.rpc_client.unspent(*addrs)

    def history(self, *addrs, **kwargs):
        """
        Get transaction history for addresses
        """
        return self.explorer.history(*addrs, coin_symbol=self.coin_symbol)

    def fetchtx(self, tx):
        """
        Fetch a tx from the blockchain
        """
        return self.explorer.fetchtx(tx, coin_symbol=self.coin_symbol)

    def txinputs(self, tx):
        """
        Fetch inputs of a transaction on the blockchain
        """
        return self.explorer.txinputs(tx, coin_symbol=self.coin_symbol)

    def pushtx(self, tx):
        """
        Push/ Broadcast a transaction to the blockchain
        """
        return self.explorer.pushtx(tx, coin_symbol=self.coin_symbol)

    def privtopub(self, privkey):
        """
        Get public key from private key
        """
        return privtopub(privkey)

    def pubtoaddr(self, pubkey):
        """
        Get address from a pubic key
        """
        return pubtoaddr(pubkey, magicbyte=self.magicbyte)

    def privtoaddr(self, privkey):
        """
        Get address from a private key
        """
        return privtoaddr(privkey, magicbyte=self.magicbyte)

    def electrum_address(self, masterkey, n, for_change=0):
        """
        For old electrum seeds
        """
        pubkey = electrum_pubkey(masterkey, n, for_change=for_change)
        return self.pubtoaddr(pubkey)

    def is_address(self, addr):
        """
        Check if addr is a valid address for this chain
        """
        all_prefixes = ''.join(list(self.address_prefixes) + list(self.script_prefixes))
        return any(str(i) == addr[0] for i in all_prefixes)

    def is_p2sh(self, addr):
        """
        Check if addr is a a pay to script address
        """
        return not any(str(i) == addr[0] for i in self.address_prefixes)

    def output_script_to_address(self, script):
        """
        Convert an output script to an address
        """
        return output_script_to_address(script, self.magicbyte)

    def scripttoaddr(self, script):
        """
        Convert an input public key hash to an address
        """
        if re.match('^[0-9a-fA-F]*$', script):
            script = binascii.unhexlify(script)
        if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(script) == 25:
            return bin_to_b58check(script[3:-2], self.magicbyte)  # pubkey hash addresses
        else:
            # BIP0016 scripthash addresses
            return bin_to_b58check(script[2:-1], self.script_magicbyte)

    def p2sh_scriptaddr(self, script):
        """
        Convert an output p2sh script to an address
        """
        if re.match('^[0-9a-fA-F]*$', script):
            script = binascii.unhexlify(script)
        return hex_to_b58check(hash160(script), self.script_magicbyte)

    def addrtoscript(self, addr):
        """
        Convert an output address to a script
        """
        if self.segwit_hrp:
            witver, witprog = segwit_addr.decode(self.segwit_hrp, addr)
            if witprog is not None:
                return mk_p2w_scripthash_script(witver, witprog)
        if self.is_p2sh(addr):
            return mk_scripthash_script(addr)
        else:
            return mk_pubkey_script(addr)

    def pubtop2w(self, pub):
        """
        Convert a public key to a pay to witness public key hash address (P2WPKH, required for segwit)
        """
        if not self.segwit_supported:
            raise Exception("Segwit not supported for this coin")
        compressed_pub = compress(pub)
        return self.scripttoaddr(mk_p2wpkh_script(compressed_pub))

    def privtop2w(self, priv):
        """
        Convert a private key to a pay to witness public key hash address
        """
        return self.pubtop2w(privtopub(priv))

    def hash_to_segwit_addr(self, hash):
        """
        Convert a hash to the new segwit address format outlined in BIP-0173
        """
        return segwit_addr.encode(self.segwit_hrp, 0, hash)

    def privtosegwit(self, privkey):
        """
        Convert a private key to the new segwit address format outlined in BIP01743
        """
        return self.pubtosegwit(self.privtopub(privkey))

    def pubtosegwit(self, pubkey):
        """
        Convert a public key to the new segwit address format outlined in BIP01743
        """
        return self.hash_to_segwit_addr(pubkey_to_hash(pubkey))

    def script_to_p2wsh(self, script):
        """
        Convert a script to the new segwit address format outlined in BIP01743
        """
        return self.hash_to_segwit_addr(sha256(safe_from_hex(script)))

    def mk_multsig_address(self, *args):
        """
        :param args: List of public keys to used to create multisig and M, the number of signatures required to spend
        :return: multisig script
        """
        script = mk_multisig_script(*args)
        address = self.p2sh_scriptaddr(script)
        return script, address

    def is_segwit(self, priv, addr):
        """
        Check if addr was generated from priv using segwit script
        """
        if not self.segwit_supported:
            return False
        if self.segwit_hrp and addr.startswith(self.segwit_hrp):
            return True
        segwit_addr = self.privtop2w(priv)
        return segwit_addr == addr

    def sign(self, txobj, i, priv):
        """
        Sign a transaction input with index using a private key
        """

        i = int(i)
        if not isinstance(txobj, dict):
            txobj = deserialize(txobj)
        if len(priv) <= 33:
            priv = safe_hexlify(priv)
        pub = self.privtopub(priv)
        if txobj['ins'][i].get('segwit', False) or txobj['ins'][i].get('new_segwit', False):
            if not self.segwit_supported:
                raise Exception("Segregated witness is not supported for %s" % self.display_name)
            pub = compress(pub)
            script = mk_p2wpkh_scriptcode(pub)
            signing_tx = signature_form(txobj, i, script, self.hashcode)
            sig = ecdsa_tx_sign(signing_tx, priv, self.secondary_hashcode)
            if txobj['ins'][i].get('new_segwit', False):
                txobj["ins"][i]["script"] = ''
            else:
                txobj["ins"][i]["script"] = mk_p2wpkh_redeemscript(pub)
            txobj["witness"].append({"number": 2, "scriptCode": serialize_script([sig, pub])})
        else:
            address = self.pubtoaddr(pub)
            script = mk_pubkey_script(address)
            signing_tx = signature_form(txobj, i, script, self.hashcode)
            sig = ecdsa_tx_sign(signing_tx, priv, self.hashcode)
            txobj["ins"][i]["script"] = serialize_script([sig, pub])
            if "witness" in txobj.keys():
                txobj["witness"].append({"number": 0, "scriptCode": ''})
        return txobj

    def signall(self, txobj, priv):
        """
        Sign all inputs to a transaction using a private key
        """
        if not isinstance(txobj, dict):
            txobj = deserialize(txobj)
        if isinstance(priv, dict):
            for e, i in enumerate(txobj["ins"]):
                k = priv["%s:%d" % (i["outpoint"]["hash"], i["outpoint"]["index"])]
                txobj = self.sign(txobj, e, k)
        else:
            for i in range(len(txobj["ins"])):
                txobj = self.sign(txobj, i, priv)
        return serialize(txobj)

    def multisign(self, tx, i, script, pk):
        return multisign(tx, i, script, pk, self.hashcode)

    def mktx(self, *args):
        """[in0, in1...],[out0, out1...] or in0, in1 ... out0 out1 ...

        Make an unsigned transaction from inputs and outputs. Change is not automatically included so any difference
        in value between inputs and outputs will be given as a miner's fee (transactions with too high fees will
        normally be blocked by the explorers)

        For Bitcoin Cash and other hard forks using SIGHASH_FORKID,
        ins must be a list of dicts with each containing the outpoint and value of the input.

        Inputs originally received with segwit must be a dict in the format: {'outpoint': "txhash:index", value:0, "segwit": True}

        For other transactions, inputs can be dicts containing only outpoints or strings in the outpoint format.
        Outpoint format: txhash:index
        """
        ins, outs = [], []
        for arg in args:
            if isinstance(arg, list):
                for a in arg: (ins if is_inp(a) else outs).append(a)
            else:
                (ins if is_inp(arg) else outs).append(arg)

        txobj = {"locktime": 0, "version": 1, "ins": [], "outs": []}
        if any(isinstance(i, dict) and (i.get("segwit", False) or i.get("new_segwit", False)) for i in ins):
            if not self.segwit_supported:
                raise Exception("Segregated witness is not allowed for %s" % self.display_name)
            txobj.update({"marker": 0, "flag": 1, "witness": []})
        for i in ins:
            input = {'script': "", "sequence": 4294967295}
            if isinstance(i, dict) and "output" in i:
                input["outpoint"] = {"hash": i["output"][:64], "index": int(i["output"][65:])}
                input['amount'] = i.get("value", 0)
                if i.get("segwit", False):
                    input["segwit"] = True
                elif i.get("new_segwit", False):
                    input["new_segwit"] = True
            else:
                input["outpoint"] = {"hash": i[:64], "index": int(i[65:])}
                input['amount'] = 0
            txobj["ins"].append(input)
        for o in outs:
            if isinstance(o, string_or_bytes_types):
                addr = o[:o.find(':')]
                val = int(o[o.find(':')+1:])
                o = {}
                if re.match('^[0-9a-fA-F]*$', addr):
                    o["script"] = addr
                else:
                    o["address"] = addr
                o["value"] = val

            outobj = {}
            if "address" in o:
                outobj["script"] = self.addrtoscript(o["address"])
            elif "script" in o:
                outobj["script"] = o["script"]
            else:
                raise Exception("Could not find 'address' or 'script' in output.")
            outobj["value"] = o["value"]
            txobj["outs"].append(outobj)
        return txobj

    def mksend(self, *args, segwit=False):
        """[in0, in1...],[out0, out1...] or in0, in1 ... out0 out1 ...

        Make an unsigned transaction from inputs, outputs change address and fee. A change output will be added with
        change sent to the change address.

        For Bitcoin Cash and other hard forks using SIGHASH_FORKID and segwit,
        ins must be a list of dicts with each containing the outpoint and value of the input.

        For other transactions, inputs can be dicts containing only outpoints or strings in the outpoint format.
        Outpoint format: txhash:index
        """
        argz, change, fee = args[:-2], args[-2], int(args[-1])
        ins, outs = [], []
        for arg in argz:
            if isinstance(arg, list):
                for a in arg:
                    (ins if is_inp(a) else outs).append(a)
            else:
                (ins if is_inp(arg) else outs).append(arg)
            if segwit:
                for i in ins:
                    i['segwit'] = True
        isum = sum([i["value"] for i in ins])
        osum, outputs2 = 0, []
        for o in outs:
            if isinstance(o, string_types):
                o2 = {
                    "address": o[:o.find(':')],
                    "value": int(o[o.find(':') + 1:])
                }
            else:
                o2 = o
            outputs2.append(o2)
            osum += o2["value"]

        if isum < osum + fee:
            raise Exception("Not enough money")
        elif isum > osum + fee + 5430:
            outputs2 += [{"address": change, "value": isum - osum - fee}]

        return self.mktx(ins, outputs2)

    def preparesignedtx(self, privkey, to, value, fee=10000, change_addr=None, segwit=False, addr=None):
        """
        Prepare a tx with a specific amount from address belonging to private key to another address, returning change to the
        from address or change address, if set.
        Requires private key, target address, value and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey, to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        return self.preparesignedmultitx(privkey, to + ":" + str(value), fee, change_addr=change_addr, segwit=segwit, addr=addr)

    def send(self, privkey, to, value, fee=10000, change_addr=None, segwit=False, addr=None):
        """
        Send a specific amount from address belonging to private key to another address, returning change to the
        from address or change address, if set.
        Requires private key, target address, value and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey, to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        return self.sendmultitx(privkey, to + ":" + str(value), fee, change_addr=change_addr, segwit=segwit, addr=addr)

    def preparesignedmultitx(self, privkey, *args, change_addr=None, segwit=False, addr=None):
        """
        Prepare transaction with multiple outputs, with change sent back to from addrss
        Requires private key, address:value pairs and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        if addr:
            frm =  addr
            if self.segwit_supported:
                segwit = self.is_segwit(privkey, addr)
        elif segwit:
            frm = self.privtop2w(privkey)
        else:
            frm = self.privtoaddr(privkey)
        tx = self.preparemultitx(frm, *args, change_addr=change_addr, segwit=segwit)
        tx2 = self.signall(tx, privkey)
        return tx2

    def sendmultitx(self, privkey, *args, change_addr=None, segwit=False, addr=None):
        """
        Send transaction with multiple outputs, with change sent back to from addrss
        Requires private key, address:value pairs and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        tx = self.preparesignedmultitx(privkey, *args, change_addr=change_addr, segwit=segwit, addr=addr)
        return self.pushtx(tx)

    def preparetx(self, frm, to, value, fee, change_addr=None, segwit=False):
        """
        Prepare a transaction using from and to addresses, value and a fee, with change sent back to from address
        """
        tovalues = to + ":" + str(value)
        return self.preparemultitx(frm, tovalues, fee, change_addr=change_addr, segwit=segwit)

    def preparemultitx(self, frm, *args, change_addr=None, segwit=False):
        """
        Prepare transaction with multiple outputs, with change sent to from address
        Requires from address, to_address:value pairs and fees
        """
        tv, fee = args[:-1], int(args[-1])
        outs = []
        outvalue = 0
        for a in tv:
            outs.append(a)
            outvalue += int(a.split(":")[1])

        u = self.unspent(frm)
        u2 = select(u, int(outvalue) + int(fee))
        change_addr = change_addr or frm
        argz = u2 + outs + [change_addr, fee]
        return self.mksend(*argz, segwit=segwit)

    def block_height(self, txhash):
        return self.explorer.block_height(txhash, coin_symbol=self.coin_symbol)

    def current_block_height(self):
        return self.explorer.current_block_height(coin_symbol=self.coin_symbol)

    def block_info(self, height):
        return self.explorer.block_info(height, coin_symbol=self.coin_symbol)

    def inspect(self, tx):
        if not isinstance(tx, dict):
            tx = deserialize(tx)
        isum = 0
        ins = {}
        for _in in tx['ins']:
            h = _in['outpoint']['hash']
            i = _in['outpoint']['index']
            prevout = deserialize(self.fetchtx(h))['outs'][i]
            isum += prevout['value']
            a = self.scripttoaddr(prevout['script'])
            ins[a] = ins.get(a, 0) + prevout['value']
        outs = []
        osum = 0
        for _out in tx['outs']:
            outs.append({'address': self.scripttoaddr(_out['script']),
                         'value': _out['value']})
            osum += _out['value']
        return {
            'fee': isum - osum,
            'outs': outs,
            'ins': ins
        }

    def merkle_prove(self, txhash):
        """
        Prove that information an explorer returns about a transaction in the blockchain is valid. Only run on a
        tx with at least 1 confirmation.
        """
        blocknum = self.block_height(txhash)
        blockinfo = self.block_info(blocknum)
        hashes = blockinfo.pop('tx_hashes')
        try:
            i = hashes.index(txhash)
        except ValueError:
            raise Exception("Merkle proof failed because transaction %s is not part of the main chain" % txhash)
        return mk_merkle_proof(blockinfo, hashes, i)

    def encode_privkey(self, privkey, formt, script_type="p2pkh"):
        return encode_privkey(privkey, formt=formt, vbyte=self.wif_prefix + self.wif_script_types[script_type])

    def wallet(self, seed, passphrase=None, **kwargs):
        if not bip39_is_checksum_valid(seed) == (True, True):
            raise Exception("BIP39 Checksum failed. This is not a valid BIP39 seed")
        ks = standard_from_bip39_seed(seed, passphrase, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_wallet(self, xpub, **kwargs):
        ks = from_xpub(xpub, self, 'p2pkh')
        return HDWallet(ks, **kwargs)

    def p2wpkh_p2sh_wallet(self, seed, passphrase=None, **kwargs):
        if not self.segwit_supported:
            raise Exception("P2WPKH-P2SH segwit not enabled for this coin")
        if not bip39_is_checksum_valid(seed) == (True, True):
            raise Exception("BIP39 Checksum failed. This is not a valid BIP39 seed")
        ks = p2wpkh_p2sh_from_bip39_seed(seed, passphrase, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_p2wpkh_p2sh_wallet(self, xpub,**kwargs):
        ks = from_xpub(xpub, self, 'p2wpkh-p2sh')
        return HDWallet(ks, **kwargs)

    def p2wpkh_wallet(self, seed, passphrase=None, **kwargs):
        if not bip39_is_checksum_valid(seed) == (True, True):
            raise Exception("BIP39 Checksum failed. This is not a valid BIP39 seed")
        ks = p2wpkh_from_bip39_seed(seed, passphrase, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_p2wpkh_wallet(self, xpub, **kwargs):
        ks = from_xpub(xpub, self, 'p2wpkh')
        return HDWallet(ks, **kwargs)

    def electrum_wallet(self, seed, passphrase=None, **kwargs):
        ks = from_electrum_seed(seed, passphrase, False, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_electrum_wallet(self, xpub, **kwargs):
        ks = from_xpub(xpub, self, 'p2pkh', electrum=True)
        return HDWallet(ks, **kwargs)

    def watch_electrum_p2wpkh_wallet(self, xpub, **kwargs):
        ks = from_xpub(xpub, self, 'p2wpkh', electrum=True)
        return HDWallet(ks, **kwargs)
