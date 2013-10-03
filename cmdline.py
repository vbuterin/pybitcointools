from main import *
from transaction import *

funs = {
    "pub_to_addr": pub_to_addr,
    "priv_to_pub": priv_to_pub,
    "add": add,
    "multiply": multiply,
    "bin_to_b58check": bin_to_b58check,
    "b58check_to_bin": b58check_to_bin,
    "hex_to_b58check": hex_to_b58check,
    "b58check_to_hex": b58check_to_hex,
    "sha256": sha256,
    "hash160": hash160,
    "compress": compress,
    "decompress": decompress,
    "encode_sig": encode_sig,
    "decode_sig": decode_sig,
    "ecdsa_sign": ecdsa_sign,
    "ecdsa_verify": ecdsa_verify,
    "ecdsa_recover": ecdsa_recover,
    "electrum_stretch": electrum_stretch,
    "electrum_mpk": electrum_mpk,
    "electrum_privkey": electrum_privkey,
    "electrum_pubkey": electrum_pubkey,
    "deserialize": deserialize,
    "serialize": serialize,
    "tx_hash": tx_hash,
    "deserialize_script": deserialize_script,
    "serialize_script": serialize_script,
    "sign": sign,
    "multisign": multisign,
    "apply_multisignatures": apply_multisignatures,
    "verify_tx_input": verify_tx_input,
    "mktx": mktx,
    "scriptaddr": scriptaddr,
    "mk_pubkey_script": mk_pubkey_script,
    "mk_scripthash_script": mk_scripthash_script,
    "ecdsa_tx_sign": ecdsa_tx_sign,
    "ecdsa_tx_verify": ecdsa_tx_verify,
    "ecdsa_tx_recover": ecdsa_tx_recover
}
if len(sys.argv) > 1:
    f = funs.get(sys.argv[1],None)
    if not f:
        if sys.argv[0] != 'test.py': sys.stderr.write( "Invalid argument" )
    else: print f(*sys.argv[2:])
