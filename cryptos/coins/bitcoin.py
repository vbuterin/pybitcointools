from ..explorers import sochain
from ..transaction import *
from ..main import *
from .base import BaseCoin


class Bitcoin(BaseCoin):
    coin_symbol = "BTC"
    display_name = "Bitcoin"
    segwit_supported = True
    hashcode = SIGHASH_ALL
    magicbyte = 0
    script_magicbyte = 5
    testnet_overrides = {
        'display_name': "Bitcoin Testnet",
        'coin_symbol': "BTCTEST",
        'magicbyte': 111,
        'script_magicbyte': 196
    }

    def privtopub(self, privkey):
        return privtopub(privkey)

    def pubtoaddr(self, pubkey):
        return pubtoaddr(pubkey, magicbyte=self.magicbyte)

    def privtoaddr(self, privkey):
        return privtoaddr(privkey, magicbyte=self.magicbyte)

    def scripttoaddr(self, script):
        if re.match('^[0-9a-fA-F]*$', script):
            script = binascii.unhexlify(script)
        if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(script) == 25:
            return bin_to_b58check(script[3:-2], self.magicbyte)  # pubkey hash addresses
        else:
            # BIP0016 scripthash addresses
            return bin_to_b58check(script[2:-1], self.script_magicbyte)

    def p2sh_scriptaddr(self, script):
        if re.match('^[0-9a-fA-F]*$', script):
            script = binascii.unhexlify(script)
        return hex_to_b58check(hash160(script), self.script_magicbyte)

    def pubtop2sh(self, pub):
        compressed_pub = compress(pub)
        return self.scripttoaddr(mk_p2wpkh_script(compressed_pub))

    def privtop2sh(self, priv):
        return self.pubtop2sh(privtopub(priv))

    def is_address(self, addr):
        all_prefixes = ''.join(list(self.address_prefixes) + list(self.script_prefixes))
        return any(str(i) == addr[0] for i in all_prefixes)

    def is_p2sh(self, addr):
        return not any(str(i) == addr[0] for i in self.address_prefixes)

    def addrtoscript(self, addr):
        if self.is_p2sh(addr):
            return mk_scripthash_script(addr)
        else:
            return mk_pubkey_script(addr)

    def sign(self, txobj, i, priv):
        i = int(i)
        if not isinstance(txobj, dict):
            txobj = deserialize(txobj)
        if len(priv) <= 33:
            priv = safe_hexlify(priv)
        pub = self.privtopub(priv)
        if txobj['ins'][i].get('segwit', False):
            if not self.segwit_supported:
                raise Exception("Segregated witness is not supported for %s" % self.display_name)
            pub = compress(pub)
            script = mk_p2wpkh_scriptcode(pub)
            signing_tx = signature_form(txobj, i, script, self.hashcode)
            sig = ecdsa_tx_sign(signing_tx, priv, self.hashcode)
            txobj["ins"][i]["script"] = mk_p2wpkh_redeemscript(pub)
            txobj["witness"].append({"number": 2, "scriptCode": serialize_script([sig, pub])})
        else:
            address = self.pubtoaddr(pub)
            script = mk_pubkey_script(address)
            signing_tx = signature_form(txobj, i, script, self.hashcode)
            sig = ecdsa_tx_sign(signing_tx, priv, self.hashcode)
            txobj["ins"][i]["script"] = serialize_script([sig, pub])
            if "witness" in txobj.keys():
                txobj["witness"].append({"number":0, "scriptCode": ''})
        return txobj

    def signall(self, txobj, priv):
        # if priv is a dictionary, assume format is
        # { 'txinhash:txinidx' : privkey }
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

    def unspent(self, *addrs, **kwargs):
        return sochain.unspent(*addrs, coin_symbol=self.coin_symbol, **kwargs)

    def history(self, *addrs, **kwargs):
        return sochain.history(*addrs, coin_symbol=self.coin_symbol, **kwargs)

    def fetchtx(self, tx):
        return sochain.fetchtx(tx, coin_symbol=self.coin_symbol)

    def txinputs(self, tx):
        return sochain.txinputs(tx, coin_symbol=self.coin_symbol)

    def pushtx(self, tx):
        return sochain.pushtx(tx, coin_symbol=self.coin_symbol)

    # Takes privkey, address, value (satoshis), fee (satoshis)
    def send(self, privkey, to, value, fee=10000, segwit=False):
        return self.sendmultitx(privkey, to + ":" + str(value), fee, segwit=segwit)

    # Takes privkey, address1:value1,address2:value2 (satoshis), fee (satoshis)
    def sendmultitx(self, privkey, *args, segwit=False):
        if segwit:
            frm = self.privtop2sh(privkey)
        else:
            frm = self.privtoaddr(privkey)
        tx = self.preparemultitx(frm, *args, segwit=segwit)
        tx2 = self.signall(tx, privkey)
        return self.pushtx(tx2)

    # Takes address, address, value (satoshis), fee(satoshis)
    def preparetx(self, frm, to, value, fee=10000, segwit=False):
        tovalues = to + ":" + str(value)
        return self.preparemultitx(frm, tovalues, fee, segwit=segwit)

    # Takes address, address:value, address:value ... (satoshis), fee(satoshis)
    def preparemultitx(self, frm, *args, segwit=False):
        tv, fee = args[:-1], int(args[-1])
        outs = []
        outvalue = 0
        for a in tv:
            outs.append(a)
            outvalue += int(a.split(":")[1])

        u = self.unspent(frm)
        u2 = select(u, int(outvalue) + int(fee))
        argz = u2 + outs + [frm, fee]
        return self.mksend(*argz, segwit=segwit)

    def mktx(self, *args):
        """[in0, in1...],[out0, out1...] or in0, in1 ... out0 out1 ...

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
        if any(isinstance(i, dict) and i.get("segwit", False) for i in ins):
            segwit = True
            if not self.segwit_supported:
                raise Exception("Segregated witness is not allowed for %s" % self.display_name)
            txobj.update({"marker": 0, "flag": 1, "witness": []})
        else:
            segwit = False
        for i in ins:
            input = {'script': "", "sequence": 4294967295}
            if isinstance(i, dict) and "output" in i:
                input["outpoint"] = {"hash": i["output"][:64], "index": int(i["output"][65:])}
                input['amount'] = i.get("value", None)
                if i.get("segwit", False):
                    input["segwit"] = True
                elif segwit:
                    input.update({'segwit': False, 'amount': 0})
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
