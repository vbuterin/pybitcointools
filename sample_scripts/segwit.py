import asyncio
from binascii import unhexlify, hexlify
from cryptos.coins_async import Bitcoin
from cryptos.constants import SATOSHI_PER_BTC
from cryptos.transaction import deserialize, ecdsa_tx_sign, signature_form, SIGHASH_ALL, mk_p2wpkh_scriptcode, serialize_script, serialize
from cryptos.main import privtopub, compress, pubkey_to_hash

b = Bitcoin()

unsigned_tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
tx = deserialize(unsigned_tx)

private_keys = [
    "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866",
    "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"
]


expected_pubs = [
    "03c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432",
    "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
]


pubs = [privtopub(p) for p in private_keys]
compressed_pubs = [compress(p) for p in pubs]

assert compressed_pubs == expected_pubs


expected_scriptPubKeys = ["2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
                          "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"]


def pub_key_len(pub: str) -> str:
    return hex(int(len(pub) / 2)).split('0x')[1]


scriptPubKeyLen = pub_key_len(compressed_pubs[0])
scriptPubKey1 = scriptPubKeyLen + compressed_pubs[0] + "ac"

pubkey_hash = hexlify(pubkey_to_hash(compressed_pubs[1])).decode()
pubkey_hash_len = pub_key_len(pubkey_hash)
scriptPubKey2 = '00' + pubkey_hash_len + pubkey_hash

assert [scriptPubKey1, scriptPubKey2] == expected_scriptPubKeys

address2 = b.pub_to_segwit_address(compressed_pubs[1])
assert address2 == 'bc1qr583w2swedy2acd7rung055k8t3n7udp7vyzyg'
tx['ins'][0].update({'address': compressed_pubs[0], 'value': 6.25 * SATOSHI_PER_BTC})
tx['ins'][1].update({'address': address2, 'value': 6 * SATOSHI_PER_BTC})
tx['outs'][0].update({'value': 112340000})
tx['outs'][1].update({'value': 223450000})
tx.update({"marker": 0, "flag": 1, "witness": []})

tx = b.sign(tx, 0, private_keys[0])
sig = tx['ins'][0]['script']
expected_sign = "494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01"
# assert sig == expected_sign


nVersion = "01000000"
hashPrevouts = "96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b"
outpoint = "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000"
scriptCode = "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
amount = "0046c32300000000"
nSequence = "ffffffff"
hashOutputs = "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5"
nLockTime = "11000000"
nHashType = "01000000"

sigHash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
signature = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"

signed_tx = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"

#nVersion
marker = "00"
flag = "01"
txin = "02fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff"
txout = "02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
witness = "000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
# nLockTime


hashcode = SIGHASH_ALL
scriptcode = mk_p2wpkh_scriptcode(compressed_pubs[1])


inputs_hashed = '96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37'
sequences = '52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b'
assert inputs_hashed + sequences == hashPrevouts
tx_hash = "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"
tx_pos = '01000000'
assert tx_hash + tx_pos == outpoint
script = '1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac'
assert script == scriptCode
inp_value = "0046c32300000000"
assert inp_value == amount
input_sequence = 'ffffffff'
assert input_sequence == nSequence
outs_hashed = "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5"
assert outs_hashed == hashOutputs
locktime = '11000000'
assert locktime == nLockTime


breakdown_hash_preimage = """
01000000
96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37
52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b
ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a
01000000
1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
0046c32300000000
ffffffff
863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5
11000000
01000000"""


signing_tx = hexlify(signature_form(tx, 1, scriptcode, hashcode, segwit=True)).decode()
expected_hash_preimage = "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000"

#assert signing_tx == expected_hash_preimage

expected_signature = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"

sig = ecdsa_tx_sign(signing_tx, private_keys[1], SIGHASH_ALL)

assert sig == expected_signature + "01"


expected_script_code = "47304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01" + "21025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
witness2 = {"number": 2, "scriptCode": serialize_script([sig, compressed_pubs[1]])}
assert witness2["scriptCode"] == expected_script_code
tx["witness"].append(witness2)

expected_tx = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
serialized = serialize(tx)
print(serialized)
assert serialized == expected_tx

asyncio.run(b.pushtx(expected_tx))

