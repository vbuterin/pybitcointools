import asyncio
from ..transaction import *
from binascii import unhexlify
from ..blocks import verify_merkle_proof, deserialize_header
from .. import segwit_addr
from ..electrumx_client import ElectrumXClient
from ..keystore import *
from ..wallet import *
from ..py3specials import *
from ..constants import SATOSHI_PER_BTC
from functools import partial
from typing import Dict, Any, Tuple, Optional, Union, Iterable, Type, Callable, Generator, AsyncGenerator
from ..types import (Tx, Witness, TxInput, TxOut, BlockHeader, MerkleProof, AddressBalance, BlockHeaderCallback,
                     AddressCallback, AddressTXCallback)
from ..electrumx_client.types import (ElectrumXBlockHeaderNotification, ElectrumXHistoryResponse,
                                      ElectrumXBalanceResponse, ElectrumXUnspentResponse, ElectrumXTxOut,
                                      ElectrumXMerkleResponse, ElectrumXMultiBalanceResponse, ElectrumXMultiTxResponse)


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
    p2wpkh_prefix = 'a914'
    p2wpkh_suffix = '87'
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
        if self._client:
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
        for inp in txobj['ins']:
            address = inp.get('address')
            if address and self.is_new_segwit(address):
                pass        # Segwit signatures not included in tx size for fee purposes?
            elif address and self.is_legacy_segwit_or_multisig(address):
                size += self.signature_sizes['p2w_p2sh']    # Not sure if segwit or not
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

    async def raw_block_header(self, height: int) -> str:
        return await self.client.block_header(height)

    async def block_header(self, height: int) -> BlockHeader:
        """
        Return block header data for the given height
        """
        header = await self.raw_block_header(height)
        return deserialize_header(unhexlify(header))

    async def block_headers(self, *args: int) -> AsyncGenerator[BlockHeader, None]:
        """
        Return block header data for the given heights
        """
        for header in await asyncio.gather(*[self.block_header(h) for h in args]):
            yield header

    @staticmethod
    def _get_block_header_notification_params(header: ElectrumXBlockHeaderNotification) -> Tuple[int, str, BlockHeader]:
        height = header['height']
        hex_header = header['hex']
        header = deserialize_header(unhexlify(hex_header))
        return height, hex_header, header

    @staticmethod
    async def await_or_in_executor(func: Callable, *args):
        f = func
        is_coro = asyncio.iscoroutinefunction(f)
        while not is_coro and isinstance(f, partial):
            f = f.func
            is_coro = asyncio.iscoroutinefunction(f)
        if is_coro:
            await func(*args)
        else:
            await asyncio.get_running_loop().run_in_executor(None, func, *args)

    async def _block_header_callback(self, callback: BlockHeaderCallback,
                                     header: ElectrumXBlockHeaderNotification) -> None:
        height, hex_header, header = self._get_block_header_notification_params(header)
        await self.await_or_in_executor(callback, height, hex_header, header)

    async def subscribe_to_block_headers(self, callback: BlockHeaderCallback) -> None:
        """
        Run callback when a new block is added to the blockchain
        Callback should be in the format:

        from cryptos.types import BlockHeader

        async def on_block_headers(height: int, hex_header: str, header:BlockHeader) -> None:
            pass

        or

        def on_block_headers(height: int, hex_header: str, header:BlockHeader) -> None:
            pass

        """

        callback = partial(self._block_header_callback, callback)
        return await self.client.subscribe_to_block_headers(callback)

    async def unsubscribe_from_block_headers(self) -> None:
        """
        Unsubscribe from running callbacks when a new block is added
        """
        return await self.client.unsubscribe_from_block_headers()

    async def _address_status_callback(self, callback: AddressCallback, address: str,
                                       scripthash: str, status: str) -> None:
        await self.await_or_in_executor(callback, address, status)

    async def subscribe_to_address(self, callback: AddressCallback, addr: str) -> None:
        """
        Run callback when an address changes (e.g. a new transaction)
        Callback should be in the format:

        def on_address_event(address: str, status: str) -> None:
            pass
        """

        orig_addr = addr
        if self.client.requires_scripthash:
            addr = self.addrtoscripthash(addr)
        callback = partial(self._address_status_callback, callback, orig_addr)
        return await self.client.subscribe_to_address(callback, addr)

    async def unsubscribe_from_address(self, addr: str):
        """
        Unsubscribe from running callbacks when an address changes
        """
        if self.client.requires_scripthash:
            addr = self.addrtoscripthash(addr)
        return await self.client.unsubscribe_from_address(addr)

    async def _address_transaction_callback(self, callback: AddressTXCallback, history: ElectrumXHistoryResponse,
                                            address: str, status: str) -> None:
        updated_history, balance, merkle_proven = await asyncio.gather(self.history(address), self.get_balance(address),
                                                                       self.balance_merkle_proven(address))
        if history == ["-"]:
            # First response
            new_txs = []
            history.clear()
            history += updated_history
        else:
            new_txs = [t for t in updated_history if t not in history]

        prev_history = history.copy()
        history += new_txs
        await self.await_or_in_executor(callback, address, new_txs, prev_history, balance['confirmed'],
                                        balance['unconfirmed'], merkle_proven)

    async def subscribe_to_address_transactions(self, callback: AddressTXCallback, addr: str) -> None:
        """
        When an address changes retrieve transactions and balances and run a callback
        Callback should be in the format:

        def on_address_change(address: str, txs: List[Txs], history: List[txs], confirmed: int, unconfirmed: int, proven: int) -> None:
            pass

        Any transactions since the last notification are in Txs. All previous transactions are in history.
        Balances according to the network are in confirmed and unconfirmed.
        Balances confirmed locally is in proven.
        """

        history = ["-"]

        callback = partial(self._address_transaction_callback, callback, history)

        return await self.subscribe_to_address(callback, addr)

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

    async def get_merkle(self, tx: ElectrumXTxOut) -> Optional[ElectrumXMerkleResponse]:
        return await self.client.get_merkle(tx['tx_hash'], tx['height'])

    async def merkle_prove(self, tx: ElectrumXTxOut) -> MerkleProof:
        """
        Prove that information returned from server about a transaction in the blockchain is valid. Only run on a
        tx with at least 1 confirmation.
        """

        merkle, block_header = await asyncio.gather(self.get_merkle(tx), self.block_header(tx['height']))
        if not merkle:
            # Can happen if request if run immediately after pushing a transaction
            return {
                "tx_hash": tx['tx_hash'],
                'proven': False
            }
        proof = verify_merkle_proof(tx['tx_hash'], block_header['merkle_root'], merkle['merkle'], merkle['pos'])
        return proof

    async def merkle_prove_by_txid(self, tx_hash: str) -> MerkleProof:
        tx = await self.get_tx(tx_hash)
        return await self.merkle_prove(tx)

    async def _filter_by_proof(self, *txs: ElectrumXTxOut) -> Iterable[ElectrumXTxOut]:
        """
        Return only transactions with verified merkle proof
        """
        results = await asyncio.gather(*[self.merkle_prove(tx) for tx in txs])
        proven = [r['tx_hash'] for r in results if r['proven']]
        return filter(lambda tx: tx['tx_hash'] in proven, txs)

    async def unspent(self, addr: str, merkle_proof: bool = False) -> ElectrumXUnspentResponse:
        """
        Get unspent transactions for address
        """
        value = addr
        if self.client.requires_scripthash:
            value = self.addrtoscripthash(value)
        unspents = await self.client.unspent(value)
        for u in unspents:
            u['address'] = addr
        if merkle_proof:
            return list(await self._filter_by_proof(*unspents))
        return unspents

    async def balance_merkle_proven(self, addr: str) -> int:
        return sum(u['value'] for u in await self.unspent(addr, merkle_proof=True))

    async def get_unspents(self, *args: str, merkle_proof: bool = False
                           ) -> AsyncGenerator[ElectrumXMultiTxResponse, None]:
        async for addr, result in self.tasks_with_inputs(self.unspent, *args, merkle_proof=merkle_proof):
            for tx in result:
                tx['address'] = addr
                yield tx

    async def balances_merkle_proven(self, *args: str) -> AsyncGenerator[AddressBalance, None]:
        async for addr, result in self.tasks_with_inputs(self.unspent, *args, merkle_proof=True):
            yield {'address': addr, 'balance': sum(tx['value'] for tx in result)}

    async def history(self, addr: str, merkle_proof: bool = False) -> List[ElectrumXTxOut]:
        """
        Get transaction history for address
        """
        if self.client.requires_scripthash:
            addr = self.addrtoscripthash(addr)
        txs = await self.client.get_history(addr)
        if merkle_proof:
            return list(await self._filter_by_proof(*txs))
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
        Fetch transaction from the blockchain and deserialise it to a dictionary
        """
        tx = await self.get_raw_tx(tx_hash)
        deserialized_tx = deserialize(tx)
        return deserialized_tx

    async def get_verbose_tx(self, tx_hash: str) -> Dict[str, Any]:
        """
        Fetch transaction from the blockchain in verbose form
        """
        return await self.client.get_tx(tx_hash, verbose=True)

    async def get_txs(self, *args: str) -> AsyncGenerator[Tx, None]:
        for tx in await asyncio.gather(*[self.get_tx(tx_hash) for tx_hash in args]):
            yield tx

    async def pushtx(self, tx: Union[str, Tx]):
        """
        Push/ Broadcast a transaction to the blockchain
        """
        if not isinstance(tx, str):
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

    def is_legacy_segwit_or_multisig(self, addr: str) -> bool:
        script = self.addrtoscript(addr)
        return script.startswith(self.p2wpkh_prefix) and script.endswith(self.p2wpkh_suffix)

    def is_segwit_or_multisig(self, addr: str) -> bool:
        """
        Check if addr was generated from priv using segwit script
        """
        return self.segwit_supported and (self.is_new_segwit(addr) or self.is_legacy_segwit_or_multisig(addr))

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
            return bin_to_b58check(script[3:-2], self.magicbyte)  # pubkey hash address
        else:
            # BIP0016 scripthash address
            return bin_to_b58check(script[2:-1], self.script_magicbyte)

    def p2sh_scriptaddr(self, script: str) -> str:
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

    def pubtop2w(self, pub: str) -> str:
        """
        Convert a public key to a pay to witness public key hash address (P2WPKH, required for segwit)
        """
        if not self.segwit_supported:
            raise Exception("Segwit not supported for this coin")
        compressed_pub = compress(pub)
        return self.scripttoaddr(mk_p2wpkh_script(compressed_pub, prefix=self.p2wpkh_prefix, suffix=self.p2wpkh_suffix))

    def privtop2w(self, priv: str) -> str:
        """
        Convert a private key to a pay to witness public key hash address
        """
        return self.pubtop2w(privtopub(priv))

    def hash_to_segwit_addr(self, hash: str) -> str:
        """
        Convert a hash to the new segwit address format outlined in BIP-0173
        """
        return segwit_addr.encode(self.segwit_hrp, 0, hash)

    def privtosegwitaddress(self, privkey) -> str:
        """
        Convert a private key to the new segwit address format outlined in BIP01743
        """
        return self.pubtosegwitaddress(self.privtopub(privkey))

    def pubtosegwitaddress(self, pubkey) -> str:
        """
        Convert a public key to the new segwit address format outlined in BIP01743
        """
        return self.hash_to_segwit_addr(pubkey_to_hash(pubkey))

    def script_to_p2wsh(self, script) -> str:
        """
        Convert a script to the new segwit address format outlined in BIP01743
        """
        return self.hash_to_segwit_addr(sha256(safe_from_hex(script)))

    def mk_multsig_address(self, *args: str, num_required: int = None) -> Tuple[str, str]:
        """
        :param args: List of public keys to used to create multisig
        :param num_required: The number of signatures required to spend (defaults to number of public keys provided)
        :return: multisig script
        """
        num_required = num_required or len(args)
        script = mk_multisig_script(*args, num_required)
        address = self.p2sh_scriptaddr(script)
        return script, address

    def sign(self, txobj: Union[Tx, AnyStr], i: int, priv: bytes) -> Tx:
        """
        Sign a transaction input with index using a private key
        """

        i = int(i)
        if not isinstance(txobj, dict):
            txobj = deserialize(txobj)
        if len(priv) <= 33:
            priv = safe_hexlify(priv)
        pub = self.privtopub(priv)
        inp = txobj['ins'][i]
        try:
            if address := inp['address']:
                segwit = new_segwit = self.is_new_segwit(address)
                segwit = segwit or self.is_legacy_segwit_or_multisig(address)
            else:
                new_segwit = segwit = False
        except (IndexError, KeyError):
            new_segwit = segwit = False
        if segwit:
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

    def signall(self, txobj: Union[str, Tx], priv: Union[Dict[str, bytes], bytes]) -> Tx:
        """
        Sign all inputs to a transaction using a private key.
        Priv is either a private key or a dictionary of address keys and private key values
        """
        if not isinstance(txobj, dict):
            txobj = deserialize(txobj)
        if isinstance(priv, dict):
            for i, inp in enumerate(txobj["ins"]):
                addr = inp['address']
                k = priv[addr]
                txobj = self.sign(txobj, i, k)
        else:
            for i in range(len(txobj["ins"])):
                txobj = self.sign(txobj, i, priv)
        return txobj

    def multisign(self, tx: Union[str, Tx], i: int, script: str, pk) -> Tx:
        return multisign(tx, i, script, pk, self.hashcode)

    def mktx(self, ins: List[Union[TxInput, AnyStr]], outs: List[Union[TxOut, AnyStr]], locktime: int =0,
             sequence: int = 0xFFFFFFFF) -> Tx:
        """[in0, in1...],[out0, out1...]

        Make an unsigned transaction from inputs and outputs. Change is not automatically included so any difference
        in value between inputs and outputs will be given as a miner's fee (transactions with too high fees will
        normally be blocked by Electrumx)

        Ins and outs are both lists of dicts.
        """

        txobj = {"locktime": locktime, "version": 1}
        for i, inp in enumerate(ins):
            if isinstance(inp, string_or_bytes_types):
                real_inp: TxInput = {"tx_hash": inp[:64], "tx_pos": int(inp[65:]), 'amount': 0}
                ins[i] = real_inp
                inp = real_inp
            if address := inp.get('address', ''):
                if self.segwit_supported and self.is_new_segwit(address):
                    txobj.update({"marker": 0, "flag": 1, "witness": []})
            inp.update({
                'script': '',
                'sequence': int(inp.get('sequence', sequence))
            })

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
            if address := out.pop('address', None):
                out["script"] = self.addrtoscript(address)
            elif "script" not in out.keys():
                raise Exception("Could not find 'address' or 'script' in output.")
        txobj.update({'ins': ins, 'outs': outs})
        return txobj

    async def mktx_with_change(self, ins: List[Union[TxInput, AnyStr]], outs: List[Union[TxOut, AnyStr]],
                               change: str = None, fee: int = None, estimate_fee_blocks: int = 6, locktime: int = 0,
                               sequence: int = 0xFFFFFFFF) -> Tx:
        """[in0, in1...],[out0, out1...]

        Make an unsigned transaction from inputs, outputs change address and fee. A change output will be added with
        change sent to the change address..
        """
        change = change or ins[0]['address']
        isum = sum(inp['value'] for inp in ins)
        osum = sum(out['value'] for out in outs)
        change_out = {"address": change, "value": isum - osum}
        outs += [change_out]
        txobj = self.mktx(ins, outs, locktime=locktime, sequence=sequence)

        if fee is None:
            fee = await self.estimate_fee(txobj, numblocks=estimate_fee_blocks)
        if isum < osum + fee:
            raise Exception(f"Not enough money. You have {isum} but need {osum+fee} ({osum} + fee of {fee}).")

        change_out['value'] = isum - osum - fee

        return txobj

    async def preparemultitx(self, frm: str, outs: List[TxOut], change_addr: str = None,
                             fee: int = None, estimate_fee_blocks: int = 6) -> Tx:
        """
        Prepare transaction with multiple outputs, with change sent to from address
        """
        outvalue = int(sum(out['value'] for out in outs))
        unspents = await self.unspent(frm)
        if not fee:
            unspents2 = select(unspents, outvalue)
            tx = await self.mktx_with_change(unspents2, deepcopy(outs), fee=0, change=change_addr)
            fee = await self.estimate_fee(tx, estimate_fee_blocks)
        unspents2 = select(unspents, outvalue + fee)
        change_addr = change_addr or frm
        return await self.mktx_with_change(unspents2, outs, fee=fee, change=change_addr,
                                           estimate_fee_blocks=estimate_fee_blocks)

    async def preparetx(self, frm: str, to: str, value: int, fee: int = None, estimate_fee_blocks: int = 6,
                        change_addr: str = None) -> Tx:
        """
        Prepare a transaction using from and to addresses, value and a fee, with change sent back to from address
        """
        outs: List[TxOut] = [{'address': to, 'value': value}]
        return await self.preparemultitx(frm, outs, fee=fee, estimate_fee_blocks=estimate_fee_blocks,
                                         change_addr=change_addr)

    async def preparesignedmultirecipienttx(self, privkey, frm: str, outs: List[TxOut], change_addr: str = None,
                                            fee: int = None, estimate_fee_blocks: int = 6) -> Tx:
        """
        Prepare transaction with multiple outputs, with change sent back to from address or given change_addr
        Requires private key, address:value pairs and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey to automatically detect a segwit transaction for coins
        which support segwit, overriding the segwit kw
        """
        tx = await self.preparemultitx(frm, outs, fee=fee, change_addr=change_addr,
                                       estimate_fee_blocks=estimate_fee_blocks)
        tx2 = self.signall(tx, privkey)
        return tx2

    async def preparesignedtx(self, privkey, frm: str, to: str, value: int, change_addr: str = None,
                              fee: int = None, estimate_fee_blocks: int = 6) -> Tx:
        """
        Prepare a tx with a specific amount from address belonging to private key to another address, returning change
        to the from address or change address, if set.
        Requires private key, target address, value and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey, to automatically detect a segwit transaction for
        coins which support segwit, overriding the segwit kw
        """
        outs = [{'address': to, 'value': value}]
        return await self.preparesignedmultirecipienttx(privkey, frm, outs, change_addr=change_addr,
                                                        fee=fee, estimate_fee_blocks=estimate_fee_blocks)

    async def send_to_multiple_receivers_tx(self, privkey, addr: str, outs: List[TxOut], change_addr: str = None,
                                            fee: int = None, estimate_fee_blocks: int = 6):
        """
        Send transaction with multiple outputs, with change sent back to from addrss
        Requires private key, address:value pairs and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey to automatically detect a segwit transaction for
        coins which support segwit, overriding the segwit kw
        """
        tx = await self.preparesignedmultirecipienttx(privkey, addr, outs, change_addr=change_addr,
                                                      fee=fee, estimate_fee_blocks=estimate_fee_blocks)
        return await self.pushtx(tx)

    async def send(self, privkey, frm: str, to: str, value: int, change_addr: str = None,
                   fee: int = None, estimate_fee_blocks: int = 6):
        """
        Send a specific amount from address belonging to private key to another address, returning change to the
        from address or change address, if set.
        Requires private key, target address, value and optionally the change address and fee
        segwit paramater specifies that the inputs belong to a segwit address
        addr, if provided, will explicity set the from address, overriding the auto-detection of the address from the
        private key.It will also be used, along with the privkey, to automatically detect a segwit transaction for
        coins which support segwit, overriding the segwit kw
        """
        outs = [{'address': to, 'value': value}]
        return await self.send_to_multiple_receivers_tx(privkey, frm, outs, change_addr=change_addr,
                                                        fee=fee, estimate_fee_blocks=estimate_fee_blocks)

    async def inspect(self, tx: Union[str, Tx]):
        if not isinstance(tx, dict):
            tx = deserialize(tx)
        isum = 0
        ins = {}
        for _in in tx['ins']:
            h = _in['tx_hash']
            i = _in['tx_pos']
            prevout = await anext(self.get_txs(h))['outs'][i]
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

    def wallet(self, seed: str, passphrase: str = None, **kwargs) -> HDWallet:
        if not bip39_is_checksum_valid(seed) == (True, True):
            raise Exception("BIP39 Checksum failed. This is not a valid BIP39 seed")
        ks = standard_from_bip39_seed(seed, passphrase, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_wallet(self, xpub, **kwargs) -> HDWallet:
        ks = from_xpub(xpub, self, 'p2pkh')
        return HDWallet(ks, **kwargs)

    def p2wpkh_p2sh_wallet(self, seed: str, passphrase: str = None, **kwargs) -> HDWallet:
        if not self.segwit_supported:
            raise Exception("P2WPKH-P2SH segwit not enabled for this coin")
        if not bip39_is_checksum_valid(seed) == (True, True):
            raise Exception("BIP39 Checksum failed. This is not a valid BIP39 seed")
        ks = p2wpkh_p2sh_from_bip39_seed(seed, passphrase, coin=self)
        return HDWallet(ks, **kwargs)

    def watch_p2wpkh_p2sh_wallet(self, xpub,**kwargs) -> HDWallet:
        ks = from_xpub(xpub, self, 'p2wpkh-p2sh')
        return HDWallet(ks, **kwargs)

    def p2wpkh_wallet(self, seed: str, passphrase: str = None, **kwargs) -> HDWallet:
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
