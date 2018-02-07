from ..transaction import *
from ..blocks import mk_merkle_proof
from .. import segwit_addr
from ..electrumx_client.rpc import ElectrumXClient
from ..keystore import *
from ..wallet import *
from ..py3specials import *


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
    client = ElectrumXClient
    client_kwargs = {
        'server_file': 'bitcoin.json',
        'servers': (),
        'host': None,
        'port': 50001,
        'timeout': 15,
        'max_servers': 5,
        'use_ssl': True
    }
    is_testnet = False
    address_prefixes = ()
    testnet_overrides = {}
    hashcode = SIGHASH_ALL
    secondary_hashcode = None
    hd_path = 0
    block_interval = 10
    signature_sizes = {
        'p2pkh': 213,
        'p2w_p2sh': 46 + (213 / 4),
        'p2wpkh': (214 / 4),
    }
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
        self.fees = {}

    @property
    def rpc_client(self):
        """
        Connect to remove server
        """
        if not self._rpc_client:
            self._rpc_client = self.client(**self.client_kwargs)
        return self._rpc_client

    def estimate_fee_per_kb(self, numblocks=1, cache=None):
        """
        Get estimated fee kb to get transaction confirmed within numblocks number of blocks
        """
        if cache is None:
            cache = self.block_interval
        return self.rpc_client.estimate_fee_cached(numblocks, cache=cache)

    def tx_size(self, txobj):
        """
        Get transaction size in bytes
        """
        tx = serialize(txobj)
        size = len(tx) / 2
        for input in txobj['inputs']:
            if input.get('new_segwit', False):
                size += self.signature_sizes['p2wpkh']
            elif input.get('segwit', False):
                size += self.signature_sizes['p2w_p2sh']
            else:
                size += self.signature_sizes['p2pkh']
        return size

    def estimate_fee(self, txobj, numblocks=1, cache=None):
        """
        Get estimated fee to get transaction confirmed within numblocks number of blocks.
        txobj is a pre-signed transaction object
        """
        num_bytes = self.tx_size(txobj)
        per_kb = self.estimate_fee_per_kb(numblocks=numblocks, cache=cache)
        return num_bytes / 1000 * per_kb

    def block_header(self, *heights):
        """
        Return block header data for the given heights
        """
        return self.rpc_client.block_header(*heights)

    def get_balance(self, *addrs):
        """
        Get address balances
        """
        addrs_scripthashes = {self.addrtoscripthash(addr):addr for addr in addrs}
        return self.rpc_client.get_balance(addrs_scripthashes)

    def filter_by_proof(self, *txs):
        """
        Return only transactions with verified merkle proof
        """
        proven = [proof['tx_hash'] for proof in self.merkle_prove(*txs)]
        return filter(lambda tx: tx['tx_hash'] in proven, txs)

    def unspent(self, *addrs, merkle_proof=False):
        """
        Get unspent transactions for address_derivations
        """
        addrs_scripthashes = {self.addrtoscripthash(addr):addr for addr in addrs}
        unspents = self.rpc_client.unspent(addrs_scripthashes)
        if merkle_proof:
            return self.filter_by_proof(*unspents)
        return unspents

    def history(self, *addrs, merkle_proof=False):
        """
        Get transaction history for address_derivations
        """
        addrs_scripthashes = {self.addrtoscripthash(addr):addr for addr in addrs}
        txs = self.rpc_client.history(addrs_scripthashes)
        if merkle_proof:
            return self.filter_by_proof(*txs)
        return txs

    def get_raw_txs(self, *tx_hashes):
        """
        Fetch transactions from the blockchain
        """
        return self.rpc_client.get_txs(*tx_hashes)

    def get_txs(self, *tx_hashes):
        """
        Fetch transactions from the blockchain and deserialise each one to a dictionary
        """
        txs = self.get_raw_txs(*tx_hashes)
        return [deserialize(tx) for tx in txs]

    def get_merkle(self, *txs):
        return self.rpc_client.get_merkle(*txs)

    def get_all_merkle_info(self, *txinfos):
        return self.rpc_client.get_all_merkle_data(txinfos)

    def merkle_prove(self, *txinfos):
        """
        Prove that information returned from server about a transaction in the blockchain is valid. Only run on a
        tx with at least 1 confirmation.
        """
        merkles = self.get_all_merkle_info(*txinfos)
        proofs = []
        for merkle_info in merkles:
            proof = mk_merkle_proof(merkle_info['merkle_root'], merkle_info['merkle'], merkle_info['pos'])
            if proof['proven']:
                proofs.append(proof)
        return proofs

    def txinputs(self, tx_hash):
        """
        Fetch inputs of a transaction on the blockchain
        """
        return self.get_tx(tx_hash)[0]['ins']

    def pushtx(self, tx):
        """
        Push/ Broadcast a transaction to the blockchain
        """
        return self.rpc_client.broadcast_transaction(tx)

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

    def encode_privkey(self, privkey, formt, script_type="p2pkh"):
        return encode_privkey(privkey, formt=formt, vbyte=self.wif_prefix + self.wif_script_types[script_type])

    def is_p2pkh(self, addr):
        return any(str(i) == addr[0] for i in self.address_prefixes)

    def is_p2sh(self, addr):
        """
        Check if addr is a a pay to script address
        """
        return any(str(i) == addr[0] for i in self.script_prefixes)

    def is_new_segwit(self, addr):
        return self.segwit_hrp and addr.startswith(self.segwit_hrp)

    def is_address(self, addr):
        """
        Check if addr is a valid address for this chain
        """
        return self.is_p2sh(addr) or self.is_p2sh(addr) or self.is_new_segwit(addr)

    def is_segwit(self, priv, addr):
        """
        Check if addr was generated from priv using segwit script
        """
        if not self.segwit_supported:
            return False
        if self.is_new_segwit(addr):
            return True
        segwit_addr = self.privtop2w(priv)
        return segwit_addr == addr

    def output_script_to_address(self, script):
        """
        Convert an output script to an address
        """
        return output_script_to_address(script, self.magicbyte, self.script_magicbyte, self.segwit_hrp)

    def scripttoaddr(self, script):
        """
        Convert an input public key hash to an address
        """
        if re.match('^[0-9a-fA-F]*$', script):
            script = binascii.unhexlify(script)
        if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(script) == 25:
            return bin_to_b58check(script[3:-2], self.magicbyte)  # pubkey hash address_derivations
        else:
            # BIP0016 scripthash address_derivations
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

    def addrtoscripthash(self, addr):
        """
        For electrumx requests
        """
        script = self.addrtoscript(addr)
        return script_to_scripthash(script)

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
        if txobj['ins'][i].get('segwit', False) or self.is_segwit(priv, txobj['ins'][i].get('address', 'xxxxxxx')):
            if not self.segwit_supported:
                raise Exception("Segregated witness is not supported for %s" % self.display_name)
            if 'witness' not in txobj.keys():
                txobj.update({"marker": 0, "flag": 1, "witness": []})
                for j in range(0, i):
                    txobj["witness"].append({"number": 0, "scriptCode": ''})
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
        Sign all inputs to a transaction using a private key.
        Priv is either a private key or a dictionary of address keys and private key values
        """
        if not isinstance(txobj, dict):
            txobj = deserialize(txobj)
        if isinstance(priv, dict):
            for i, inp in enumerate(txobj["ins"]):
                k = priv[inp['address']]
                txobj = self.sign(txobj, i, k)
        else:
            for i in range(len(txobj["ins"])):
                txobj = self.sign(txobj, i, priv)
        return serialize(txobj)

    def multisign(self, tx, i, script, pk):
        return multisign(tx, i, script, pk, self.hashcode)

    def mktx(self, ins, outs, locktime=0, sequence=0xFFFFFFFF):
        """[in0, in1...],[out0, out1...]

        Make an unsigned transaction from inputs and outputs. Change is not automatically included so any difference
        in value between inputs and outputs will be given as a miner's fee (transactions with too high fees will
        normally be blocked by Electrumx)

        For Bitcoin Cash and other hard forks using SIGHASH_FORKID,
        ins must be a list of dicts with each containing the outpoint and value of the input.

        Inputs on a segwit address must be a dict in the format: {'outpoint': "txhash:index", value:0, "segwit": True}
        """

        txobj = {"locktime": locktime, "version": 1, "ins": [], "outs": []}
        for inp in ins:
            if self.segwit_supported and 'segwit' not in inp.keys() or 'new_segwit' not in inp.keys():
                address = inp.get('address', None)
                if address:
                    if self.is_new_segwit(address):
                       inp['new_segwit'] = True
                    elif self.is_p2pkh(address):
                        inp['new_segwit'] = False
                        inp['segwit'] = False
                    elif self.is_p2sh(address):
                        inp['new_segwit'] = False   #Segwit needs to be explicitly set for p2wpkh-p2sh
                if inp['new_segwit']:
                    inp['segwit'] = True
            inp.update({
                'script': '',
                'sequence': int(inp.get('sequence', sequence))
            })

        segwit = any(inp.get('segwit', False) for inp in ins)

        if segwit:
            if not self.segwit_supported:
                raise Exception("Segregated witness is not allowed for %s" % self.display_name)
            txobj.update({"marker": 0, "flag": 1, "witness": []})

        for out in outs:
            address = out.get('address', None)
            script = out.get('script', None)
            if address:
                out["script"] = self.addrtoscript(address)
            elif "script" in out:
                out["script"] = script
            else:
                raise Exception("Could not find 'address' or 'script' in output.")
        return txobj

    def mktx_with_change(self, ins, outs, change=None, fee=50000, fee_for_blocks=0, locktime=0, sequence=0xFFFFFFFF):
        """[in0, in1...],[out0, out1...]

        Make an unsigned transaction from inputs, outputs change address and fee. A change output will be added with
        change sent to the change address..
        """
        change = change or ins[0]['address']
        isum = sum(inp['value'] for inp in ins)
        osum = sum(out['value'] for out in outs)
        if isum < osum + fee:
            raise Exception("Not enough money")
        elif isum > osum + fee + 5430:
            outs += [{"address": change, "value": isum - osum - fee}]

        txobj = self.mktx(ins, outs, locktime=locktime, sequence=sequence)

        if fee_for_blocks:
            fee = self.estimate_fee(txobj, numblocks=fee_for_blocks)
            for out in txobj['outs']:
                if out['address'] == change:
                    out['value'] = isum - osum - fee

        return self.mktx(ins, outs)

    def preparemultitx(self, frm, outs, fee=50000, change_addr=None, fee_for_blocks=0, segwit=False):
        """
        Prepare transaction with multiple outputs, with change sent to from address
        """
        outvalue = sum(out['value'] for out in outs)
        unspents = self.unspent(frm)
        unspents2 = select(unspents, int(outvalue) + int(fee))
        if segwit:
            for unspent in unspents2:
                unspent['segwit'] = segwit
        change_addr = change_addr or frm
        return self.mktx_with_change(unspents2, outs, fee=fee, change=change_addr, fee_for_blocks=fee_for_blocks)

    def preparetx(self, frm, to, value, fee=50000, change_addr=None, segwit=False):
        """
        Prepare a transaction using from and to address_derivations, value and a fee, with change sent back to from address
        """
        outs = [{'address': to, 'value': value}]
        return self.preparemultitx(frm, outs, fee=fee, change_addr=change_addr, segwit=segwit)

    def preparesignedmultitx(self, privkey, frm, outs, fee=50000, change_addr=None, fee_for_blocks=0):
        """
        Prepare transaction with multiple outputs, with change sent back to from addrss
        Requires private key, address:value pairs and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        segwit =  self.is_segwit(privkey, frm)
        tx = self.preparemultitx(frm, outs, fee=fee, change_addr=change_addr, segwit=segwit, fee_for_blocks=fee_for_blocks)
        tx2 = self.signall(tx, privkey)
        return tx2

    def preparesignedtx(self, privkey, frm, to, value, fee=50000, change_addr=None, fee_for_blocks=0):
        """
        Prepare a tx with a specific amount from address belonging to private key to another address, returning change to the
        from address or change address, if set.
        Requires private key, target address, value and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey, to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        outs = [{'address': to, 'value': value}]
        return self.preparesignedmultitx(privkey, frm, outs, fee=fee, change_addr=change_addr,
                                         fee_for_blocks=fee_for_blocks)

    def sendmultitx(self, privkey, addr, outs, change_addr=None, fee=50000, fee_for_blocks=0):
        """
        Send transaction with multiple outputs, with change sent back to from addrss
        Requires private key, address:value pairs and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        tx = self.preparesignedmultitx(privkey, addr, outs, fee=fee, change_addr=change_addr, fee_for_blocks=fee_for_blocks)
        return self.pushtx(tx)

    def send(self, privkey, frm, to, value, fee=50000, change_addr=None, fee_for_blocks=0):
        """
        Send a specific amount from address belonging to private key to another address, returning change to the
        from address or change address, if set.
        Requires private key, target address, value and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey, to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        outs = [{'address': to, 'value': value}]
        return self.sendmultitx(privkey, frm, outs, fee=fee, change_addr=change_addr, fee_for_blocks=fee_for_blocks)

    def inspect(self, tx):
        if not isinstance(tx, dict):
            tx = deserialize(tx)
        isum = 0
        ins = {}
        for _in in tx['ins']:
            h = _in['tx_hash']
            i = _in['tx_pos']
            prevout = self.get_txs(h)[0]['outs'][i]
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
