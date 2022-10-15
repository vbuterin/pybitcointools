import asyncio
from ..transaction import *
from ..blocks import mk_merkle_proof, deserialize_header
from .. import segwit_addr
from ..electrumx_client import ElectrumXClient
from ..keystore import *
from ..wallet import *
from ..py3specials import *
from ..constants import SATOSHI_PER_BTC
from typing import Dict, Any, Tuple, Optional, Union, Iterable, Type, Callable, Generator, AsyncGenerator
from ..types import Tx, Witness, TxInput, TxOut
from ..electrumx_client.types import ElectrumXBlockCPResponse, BlockHeaderNotificationCallback, AddressNotificationCallback, ElectrumXBalanceResponse, ElectrumXUnspentResponse, ElectrumXTx, ElectrumXMerkleResponse, ElectrumXMultiBalanceResponse, ElectrumXMultiTxResponse


class BaseCoin:
    """
    Base implementation of crypto coin class
    All child coins_async must follow same pattern.
    """

    coin_symbol: str = None
    display_name: str = None
    enabled: bool = True
    segwit_supported: bool = None
    magicbyte: int = None
    script_magicbyte: int = None
    segwit_hrp: str = None
    explorer: Type[ElectrumXClient] = ElectrumXClient
    explorer_kwargs: Dict[str, Any] = {
        'server_file': 'bitcoin.json',
        'use_ssl': True
    }
    _client: ElectrumXClient = None
    is_testnet: bool = False
    testnet_overrides: Dict[str, Any] = {}
    hashcode: int = SIGHASH_ALL
    secondary_hashcode: Optional[int] = None
    hd_path: int = 0
    block_interval: int = 10
    signature_sizes: Dict[str, int] = {
        'p2pkh': 213,
        'p2w_p2sh': 46 + (213 / 4),
        'p2wpkh': (214 / 4),
    }
    wif_prefix: int = 0x80
    wif_script_types: Dict[str, int] = {
        'p2pkh': 0,
        'p2wpkh': 1,
        'p2wpkh-p2sh': 2,
        'p2sh': 5,
        'p2wsh': 6,
        'p2wsh-p2sh': 7
    }
    xprv_headers: Dict[str, int] = {
        'p2pkh': 0x0488ade4,
        'p2wpkh-p2sh': 0x049d7878,
        'p2wsh-p2sh': 0x295b005,
        'p2wpkh': 0x4b2430c,
        'p2wsh': 0x2aa7a99
    }
    xpub_headers: Dict[str, int] = {
        'p2pkh': 0x0488b21e,
        'p2wpkh-p2sh': 0x049d7cb2,
        'p2wsh-p2sh': 0x295b43f,
        'p2wpkh': 0x4b24746,
        'p2wsh': 0x2aa7ed3
    }
    electrum_xprv_headers: Dict[str, int] = xprv_headers
    electrum_xpub_headers: Dict[str, int] = xpub_headers

    def __init__(self, testnet: bool = False, use_ssl: bool = None, **kwargs):
        if use_ssl is not None:
            self.explorer_kwargs['use_ssl'] = use_ssl
        if testnet:
            self.is_testnet = True
            for k, v in self.testnet_overrides.items():
                setattr(self, k, v)
        # override default attributes from kwargs
        for key, value in kwargs.items():
            if isinstance(value, dict):
                getattr(self, key).update(value)
            else:
                setattr(self, key, value)
        if not self.enabled:
            if self.is_testnet:
                raise NotImplementedError(
                    f"Due to explorer limitations, testnet support for {self.display_name} has not been implemented yet!")
            else:
                raise NotImplementedError(f"Support for {self.display_name} has not been implemented yet!")
        self.address_prefixes: List[str] = magicbyte_to_prefix(magicbyte=self.magicbyte)
        self.script_prefixes: List[str] = []
        if self.script_magicbyte:
            self.script_prefixes = magicbyte_to_prefix(magicbyte=self.script_magicbyte)
        self.secondary_hashcode = self.secondary_hashcode or self.hashcode
        self.fees = {}

    @property
    def client(self):
        """
        Connect to remote server
        """
        if not self._client:
            self._client = self.explorer(**self.explorer_kwargs)
        return self._client

    async def close(self) -> None:
        await self._client.close()

    async def estimate_fee_per_kb(self, numblocks: int = 6) -> float:
        """
        Get estimated fee kb to get transaction confirmed within numblocks number of blocks
        """
        return await self.client.estimate_fee(numblocks)

    def tx_size(self, txobj: Tx) -> float:
        """
        Get transaction size in bytes
        """
        tx = serialize(txobj)
        size = len(tx) / 2
        addresses = txobj.get('addresses', [])
        for i, input in enumerate(txobj['ins']):
            if addresses and self.is_new_segwit(addresses[i]):
                size += self.signature_sizes['p2wpkh']
            elif input.get('segwit', False):
                size += self.signature_sizes['p2w_p2sh']
            else:
                size += self.signature_sizes['p2pkh']
        return size

    async def estimate_fee(self, txobj: Tx, numblocks: int = 6) -> int:
        """
        Get estimated fee to get transaction confirmed within numblocks number of blocks.
        txobj is a pre-signed transaction object
        """
        num_bytes = self.tx_size(txobj)
        btc_fee_per_kb = await self.estimate_fee_per_kb(numblocks=numblocks)
        btc_fee_per_byte = btc_fee_per_kb / 1024
        satoshi_fee_per_byte = btc_fee_per_byte * SATOSHI_PER_BTC
        return int(num_bytes * satoshi_fee_per_byte)

    @staticmethod
    async def tasks_with_inputs(coro: Callable, *args: Any, **kwargs) -> Generator[Tuple[str, Any], None, None]:
        for i, result in enumerate(await asyncio.gather(*[coro(arg, **kwargs) for arg in args])):
            arg = args[i]
            yield arg, result

    async def block_header(self, height: int) -> Dict[str, Any]:
        """
        Return block header data for the given height
        """
        header = await self.client.block_header(height)
        return deserialize_header(header.encode())

    async def block_headers(self, *args: int) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Return block header data for the given heights
        """
        for header in await asyncio.gather(*[self.block_header(h) for h in args]):
            yield deserialize_header(header.encode())

    async def subscribe_to_block_headers(self, callback: BlockHeaderNotificationCallback) -> None:
        """
        Run callback when a new block is added to the blockchain
        Callback should be in the format:

        def on_block_headers(header):
            pass

        """
        return await self.client.subscribe_to_block_headers(callback)

    async def unsubscribe_from_block_headers(self) -> None:
        """
        Unsubscribe from running callbacks when a new block is added
        """
        return await self.client.unsubscribe_from_block_headers()

    async def subscribe_to_address(self, callback: AddressNotificationCallback, addr: str) -> None:
        """
        Run callback when an address changes (e.g. a new transaction)
        Callback should be in the format:

        def on_address_event(scripthash, status):
            pass
        """

        if self.client.requires_scripthash:
            addr = self.addrtoscripthash(addr)
        return await self.client.subscribe_to_address(callback, addr)

    async def unsubscribe_from_address(self, addr: str):
        """
        Unsubscribe from running callbacks when an address changes
        """
        if self.client.requires_scripthash:
            addr = self.addrtoscripthash(addr)
        return await self.client.unsubscribe_from_address(addr)

    async def get_balance(self, addr: str) -> ElectrumXBalanceResponse:
        """
        Get address balance
        """
        if self.client.requires_scripthash:
            addr = self.addrtoscripthash(addr)
        return await self.client.get_balance(addr)

    async def get_balances(self, *args: str) -> AsyncGenerator[ElectrumXMultiBalanceResponse, None]:
        async for addr, result in self.tasks_with_inputs(self.get_balance, *args):
            result['address'] = addr
            yield result

    async def get_merkle(self, tx: ElectrumXTx) -> ElectrumXMerkleResponse:
        return await self.client.get_merkle(tx['tx_hash'], tx['height'])

    async def merkle_prove(self, tx: ElectrumXTx) -> Optional[Dict[str, Any]]:
        """
        Prove that information returned from server about a transaction in the blockchain is valid. Only run on a
        tx with at least 1 confirmation.
        """

        """Not all these tasks are needed"""

        merkle, block_header, tsc_merkle = await asyncio.gather(self.get_merkle(tx), self.block_header(tx['height']))
        proof = mk_merkle_proof(block_header['merkle_root'], merkle['merkle'], merkle['pos'])
        return proof

    async def merkle_prove_txid(self, tx_hash: str):
        tx = await self.get_tx(tx_hash)
        return await self.merkle_prove(tx)

    def _filter_by_proof(self, *txs: ElectrumXTx) -> Iterable[ElectrumXTx]:
        """
        Return only transactions with verified merkle proof
        """
        results = asyncio.gather(*[self.merkle_prove(tx) for tx in txs])
        proven = [r['tx_hash'] for r in results if r['proof']]
        return filter(lambda tx: tx['tx_hash'] in proven, txs)

    async def unspent(self, addr: str, merkle_proof: bool = False) -> ElectrumXUnspentResponse:
        """
        Get unspent transactions for address
        """
        if self.client.requires_scripthash:
            addr = self.addrtoscripthash(addr)
        unspents = await self.client.unspent(addr)
        if merkle_proof:
            return list(self._filter_by_proof(*unspents))
        return unspents

    async def get_unspents(self, *args: str, merkle_proof: bool = False) -> AsyncGenerator[ElectrumXMultiTxResponse, None]:
        async for addr, result in self.tasks_with_inputs(self.unspent, *args, merkle_proof=merkle_proof):
            for tx in result:
                tx['address'] = addr
                yield tx

    async def history(self, addr: str, merkle_proof: bool = False) -> List[ElectrumXTx]:
        """
        Get transaction history for address
        """
        if self.client.requires_scripthash:
            addr = self.addrtoscripthash(addr)
        txs = await self.client.get_history(addr)
        if merkle_proof:
            return list(self._filter_by_proof(*txs))
        return txs

    async def get_histories(self, *args: str, merkle_proof: bool = False) -> AsyncGenerator[ElectrumXMultiTxResponse, None]:
        async for addr, result in self.tasks_with_inputs(self.history, *args, merkle_proof=merkle_proof):
            for tx in result:
                tx['address'] = addr
                yield tx

    async def get_raw_tx(self, tx_hash: str) -> str:
        """
        Fetch transaction from the blockchain
        """
        return await self.client.get_tx(tx_hash)

    async def get_tx(self, tx_hash: str) -> Tx:
        """
        Fetch transaction from the blockchain and deserialise each one to a dictionary
        """
        tx = await self.get_raw_tx(tx_hash)
        deserialized_tx = deserialize(tx)
        return deserialized_tx

    async def pushtx(self, tx: Union[str, Tx]):
        """
        Push/ Broadcast a transaction to the blockchain
        """
        if isinstance(tx, Tx):
            tx = serialize(tx)
        return await self.client.broadcast_tx(tx)

    def privtopub(self, privkey) -> str:
        """
        Get public key from private key
        """
        return privtopub(privkey)

    def pubtoaddr(self, pubkey):
        """
        Get address from a pubic key
        """
        return pubtoaddr(pubkey, magicbyte=self.magicbyte)

    def privtoaddr(self, privkey) -> str:
        """
        Get address from a private key
        """
        return privtoaddr(privkey, magicbyte=self.magicbyte)

    def electrum_address(self, masterkey, n, for_change: int = 0) -> str:
        """
        For old electrum seeds
        """
        pubkey = electrum_pubkey(masterkey, n, for_change=for_change)
        return self.pubtoaddr(pubkey)

    def encode_privkey(self, privkey, formt, script_type: str ="p2pkh"):
        return encode_privkey(privkey, formt=formt, vbyte=self.wif_prefix + self.wif_script_types[script_type])

    def is_p2pkh(self, addr: str) -> bool:
        return any(str(i) == addr[0] for i in self.address_prefixes)

    def is_p2sh(self, addr: str) -> bool:
        """
        Check if addr is a a pay to script address
        """
        return any(str(i) == addr[0] for i in self.script_prefixes)

    def is_new_segwit(self, addr: str) -> bool:
        return self.segwit_hrp and addr.startswith(self.segwit_hrp)

    def is_address(self, addr: str) -> bool:
        """
        Check if addr is a valid address for this chain
        """
        return self.is_p2sh(addr) or self.is_p2sh(addr) or self.is_new_segwit(addr)

    def is_segwit(self, priv, addr: str) -> bool:
        """
        Check if addr was generated from priv using segwit script
        """
        if not self.segwit_supported:
            return False
        if self.is_new_segwit(addr):
            return True
        segwit_addr = self.privtop2w(priv)
        return segwit_addr == addr

    def output_script_to_address(self, script: str) -> str:
        """
        Convert an output script to an address
        """
        return output_script_to_address(script, self.magicbyte, self.script_magicbyte, self.segwit_hrp)

    def scripttoaddr(self, script: str) -> str:
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

    def p2sh_scriptaddr(self, scrip: str) -> str:
        """
        Convert an output p2sh script to an address
        """
        if re.match('^[0-9a-fA-F]*$', script):
            script = binascii.unhexlify(script)
        return hex_to_b58check(hash160(script), self.script_magicbyte)

    def addrtoscript(self, addr: str) -> str:
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

    def addrtoscripthash(self, addr: str) -> str:
        """
        For electrumx requests
        """
        script = self.addrtoscript(addr)
        return script_to_scripthash(script)

    def pubtop2w(self, pub) -> str:
        """
        Convert a public key to a pay to witness public key hash address (P2WPKH, required for segwit)
        """
        if not self.segwit_supported:
            raise Exception("Segwit not supported for this coin")
        compressed_pub = compress(pub)
        return self.scripttoaddr(mk_p2wpkh_script(compressed_pub))

    def privtop2w(self, priv) -> str:
        """
        Convert a private key to a pay to witness public key hash address
        """
        return self.pubtop2w(privtopub(priv))

    def hash_to_segwit_addr(self, hash: str) -> str:
        """
        Convert a hash to the new segwit address format outlined in BIP-0173
        """
        return segwit_addr.encode(self.segwit_hrp, 0, hash)

    def privtosegwit(self, privkey) -> str:
        """
        Convert a private key to the new segwit address format outlined in BIP01743
        """
        return self.pubtosegwit(self.privtopub(privkey))

    def pubtosegwit(self, pubkey) -> str:
        """
        Convert a public key to the new segwit address format outlined in BIP01743
        """
        return self.hash_to_segwit_addr(pubkey_to_hash(pubkey))

    def script_to_p2wsh(self, script) -> str:
        """
        Convert a script to the new segwit address format outlined in BIP01743
        """
        return self.hash_to_segwit_addr(sha256(safe_from_hex(script)))

    def mk_multsig_address(self, *args) -> Tuple[str, str]:
        """
        :param args: List of public keys to used to create multisig and M, the number of signatures required to spend
        :return: multisig script
        """
        script = mk_multisig_script(*args)
        address = self.p2sh_scriptaddr(script)
        return script, address

    def sign(self, txobj: Union[Tx, AnyStr], i: int, priv) -> Tx:
        """
        Sign a transaction input with index using a private key
        """

        i = int(i)
        if not isinstance(txobj, dict):
            txobj = deserialize(txobj)
        if len(priv) <= 33:
            priv = safe_hexlify(priv)
        pub = self.privtopub(priv)
        try:
            if address := txobj['addresses'][i]:
                new_segwit = self.is_new_segwit(address)
                segwit = new_segwit or self.is_segwit(priv, address)
            else:
                new_segwit = segwit = False
        except KeyError:
            new_segwit = segwit = False
        if segwit:
            if not self.segwit_supported:
                raise Exception("Segregated witness is not supported for %s" % self.display_name)
            if 'witness' not in txobj.keys():
                txobj.update({"marker": 0, "flag": 1, "witness": []})
                for _ in range(0, i):
                    witness: Witness = {"number": 0, "scriptCode": ''}
                    txobj["witness"].append(witness)
            pub = compress(pub)
            script = mk_p2wpkh_scriptcode(pub)
            signing_tx = signature_form(txobj, i, script, self.hashcode, segwit=True)
            sig = ecdsa_tx_sign(signing_tx, priv, self.secondary_hashcode)
            if new_segwit:
                txobj["ins"][i]["script"] = ''
            else:
                txobj["ins"][i]["script"] = mk_p2wpkh_redeemscript(pub)
                witness: Witness = {"number": 2, "scriptCode": serialize_script([sig, pub])}
            txobj["witness"].append(witness)
        else:
            address = self.pubtoaddr(pub)
            script = mk_pubkey_script(address)
            signing_tx = signature_form(txobj, i, script, self.hashcode)
            sig = ecdsa_tx_sign(signing_tx, priv, self.hashcode)
            txobj["ins"][i]["script"] = serialize_script([sig, pub])
            if "witness" in txobj.keys():
                witness: Witness = {"number": 0, "scriptCode": ''}
                txobj["witness"].append(witness)
        return txobj

    def signall(self, txobj: Union[str, Tx], priv) -> Tx:
        """
        Sign all inputs to a transaction using a private key.
        Priv is either a private key or a dictionary of address keys and private key values
        """
        if not isinstance(txobj, dict):
            txobj = deserialize(txobj)
        if isinstance(priv, dict):
            for i, inp in enumerate(txobj["ins"]):
                addr = txobj['addresses']
                k = priv[addr]
                txobj = self.sign(txobj, i, k)
        else:
            for i in range(len(txobj["ins"])):
                txobj = self.sign(txobj, i, priv)
        return serialize(txobj)

    def multisign(self, tx: Union[str, Tx], i: int, script: str, pk) -> Tx:
        return multisign(tx, i, script, pk, self.hashcode)

    def mktx(self, ins: List[Union[TxInput, AnyStr]], outs: List[Union[TxOut, AnyStr]], locktime: int =0,
             sequence: int =0xFFFFFFFF) -> Tx:
        """[in0, in1...],[out0, out1...]

        Make an unsigned transaction from inputs and outputs. Change is not automatically included so any difference
        in value between inputs and outputs will be given as a miner's fee (transactions with too high fees will
        normally be blocked by Electrumx)

        Ins and outs are both lists of dicts.
        """

        txobj = {"locktime": locktime, "version": 1}
        addresses = []
        segwit = False
        for i, inp in enumerate(ins):
            if isinstance(inp, string_or_bytes_types):
                real_inp: TxInput = {"tx_hash": inp[:64], "tx_pos": int(inp[65:]), 'amount': 0}
                ins[i] = real_inp
                inp = real_inp
            if address := inp.pop('address', ''):
                addresses.append(address)
            if self.segwit_supported:
                if (address and self.is_new_segwit(address)) or inp.pop('segwit', False):
                    segwit = True
                elif address and self.is_p2pkh(address):
                    segwit = False
            inp.update({
                'script': '',
                'sequence': int(inp.get('sequence', sequence))
            })

        if segwit:
            if not self.segwit_supported:
                raise Exception("Segregated witness is not allowed for %s" % self.display_name)
            txobj.update({"marker": 0, "flag": 1, "witness": []})

        for i, out in enumerate(outs):
            if isinstance(out, string_or_bytes_types):
                o = out
                addr = o[:o.find(':')]
                val = int(o[o.find(':') + 1:])
                out = {}
                if re.match('^[0-9a-fA-F]*$', addr):
                    out["script"] = addr
                else:
                    out["address"] = addr
                out["value"] = val
                outs[i] = out
            address = out.pop('address', None)
            if address:
                out["script"] = self.addrtoscript(address)
            elif "script" not in out.keys():
                raise Exception("Could not find 'address' or 'script' in output.")
        txobj.update({'ins': ins, 'outs': outs, 'addresses': addresses})
        return txobj

    def mktx_with_change(self, ins: List[Union[TxInput, AnyStr]], outs: List[Union[TxOut, AnyStr]],
                         change: str  =None, fee: int = 50000, fee_for_blocks: int = 0, locktime: int = 0,
                         sequence: int =0xFFFFFFFF) -> Tx:
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
        orig_outs = [out.copy() for out in outs]
        orig_ins = [inp.copy() for inp in ins]
        txobj = self.mktx(ins, outs, locktime=locktime, sequence=sequence)

        if fee_for_blocks:
            fee = self.estimate_fee(txobj, numblocks=fee_for_blocks)
            for out in orig_outs:
                if out['address'] == change:
                    out['value'] = isum - osum - fee

        return self.mktx(orig_ins, orig_outs, locktime=locktime, sequence=sequence)

    def preparemultitx(self, frm: str, outs: List[TxOut], fee: int = 50000, change_addr: str = None,
                       fee_for_blocks: int = 0, segwit: bool = False) -> Tx:
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

    def preparetx(self, frm: str, to: str, value: int, fee=50000, fee_for_blocks: int = 0,
                  change_addr: str = None, segwit: bool = False) -> Tx:
        """
        Prepare a transaction using from and to address_derivations, value and a fee, with change sent back to from address
        """
        outs: List[TxOut] = [{'address': to, 'value': value}]
        return self.preparemultitx(frm, outs, fee=fee, fee_for_blocks=fee_for_blocks,
                                   change_addr=change_addr, segwit=segwit)

    def preparesignedmultitx(self, privkey, frm: str, outs: List[TxOut], fee: int = 50000, change_addr: str = None,
                             fee_for_blocks: int = 0) -> Tx:
        """
        Prepare transaction with multiple outputs, with change sent back to from addrss
        Requires private key, address:value pairs and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey to automatically detect a segwit transaction for coins_async
        which support segwit, overriding the segwit kw
        """
        segwit = self.is_segwit(privkey, frm)
        tx = self.preparemultitx(frm, outs, fee=fee, change_addr=change_addr, segwit=segwit, fee_for_blocks=fee_for_blocks)
        tx2 = self.signall(tx, privkey)
        return tx2

    def preparesignedtx(self, privkey, frm: str, to: str, value: int, fee: int = 50000, change_addr: str = None,
                        fee_for_blocks: int =0) -> Tx:
        """
        Prepare a tx with a specific amount from address belonging to private key to another address, returning change to the
        from address or change address, if set.
        Requires private key, target address, value and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey, to automatically detect a segwit transaction for coins_async
        which support segwit, overriding the segwit kw
        """
        outs = [{'address': to, 'value': value}]
        return self.preparesignedmultitx(privkey, frm, outs, fee=fee, change_addr=change_addr,
                                         fee_for_blocks=fee_for_blocks)

    async def sendmultitx(self, privkey, addr: str, outs: List[TxOut], change_addr: str = None, fee: int = 50000,
                    fee_for_blocks: int =0):
        """
        Send transaction with multiple outputs, with change sent back to from addrss
        Requires private key, address:value pairs and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey to automatically detect a segwit transaction for coins_async
        which support segwit, overriding the segwit kw
        """
        tx = self.preparesignedmultitx(privkey, addr, outs, fee=fee, change_addr=change_addr, fee_for_blocks=fee_for_blocks)
        return await self.pushtx(tx)

    async def send(self, privkey, frm: str, to: str, value: int, fee: int =50000, change_addr: str =None,
             fee_for_blocks: int =0):
        """
        Send a specific amount from address belonging to private key to another address, returning change to the
        from address or change address, if set.
        Requires private key, target address, value and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey, to automatically detect a segwit transaction for coins_async
        which support segwit, overriding the segwit kw
        """
        outs = [{'address': to, 'value': value}]
        return await self.sendmultitx(privkey, frm, outs, fee=fee, change_addr=change_addr, fee_for_blocks=fee_for_blocks)

    def inspect(self, tx: Union[str, Tx]):
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

    def wallet(self, seed: str, passphrase: str =None, **kwargs) -> HDWallet:
        if not bip39_is_checksum_valid(seed) == (True, True):
            raise Exception("BIP39 Checksum failed. This is not a valid BIP39 seed")
        ks = standard_from_bip39_seed(seed, passphrase, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_wallet(self, xpub, **kwargs) -> HDWallet:
        ks = from_xpub(xpub, self, 'p2pkh')
        return HDWallet(ks, **kwargs)

    def p2wpkh_p2sh_wallet(self, seed: str, passphrase: str =None, **kwargs) -> HDWallet:
        if not self.segwit_supported:
            raise Exception("P2WPKH-P2SH segwit not enabled for this coin")
        if not bip39_is_checksum_valid(seed) == (True, True):
            raise Exception("BIP39 Checksum failed. This is not a valid BIP39 seed")
        ks = p2wpkh_p2sh_from_bip39_seed(seed, passphrase, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_p2wpkh_p2sh_wallet(self, xpub,**kwargs) -> HDWallet:
        ks = from_xpub(xpub, self, 'p2wpkh-p2sh')
        return HDWallet(ks, **kwargs)

    def p2wpkh_wallet(self, seed: str, passphrase: str =None, **kwargs) -> HDWallet:
        if not bip39_is_checksum_valid(seed) == (True, True):
            raise Exception("BIP39 Checksum failed. This is not a valid BIP39 seed")
        ks = p2wpkh_from_bip39_seed(seed, passphrase, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_p2wpkh_wallet(self, xpub, **kwargs) -> HDWallet:
        ks = from_xpub(xpub, self, 'p2wpkh')
        return HDWallet(ks, **kwargs)

    def electrum_wallet(self, seed, passphrase=None, **kwargs) -> HDWallet:
        ks = from_electrum_seed(seed, passphrase, False, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_electrum_wallet(self, xpub, **kwargs) -> HDWallet:
        ks = from_xpub(xpub, self, 'p2pkh', electrum=True)
        return HDWallet(ks, **kwargs)

    def watch_electrum_p2wpkh_wallet(self, xpub, **kwargs) -> HDWallet:
        ks = from_xpub(xpub, self, 'p2wpkh', electrum=True)
        return HDWallet(ks, **kwargs)
