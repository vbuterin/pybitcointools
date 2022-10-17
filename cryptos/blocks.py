from .main import *
from .transaction import deserialize
from .types import BlockHeader, MerkleProof
from binascii import hexlify


def serialize_header(inp: BlockHeader) -> bytes:
    o = encode(inp['version'], 256, 4)[::-1] + \
        inp['prevhash'].decode('hex')[::-1] + \
        inp['merkle_root'].decode('hex')[::-1] + \
        encode(inp['timestamp'], 256, 4)[::-1] + \
        encode(inp['bits'], 256, 4)[::-1] + \
        encode(inp['nonce'], 256, 4)[::-1]
    h = bin_sha256(bin_sha256(o))[::-1].encode('hex')
    assert h == inp['hash'], (sha256(o), inp['hash'])
    return o.encode('hex')


def deserialize_header(inp: bytes) -> BlockHeader:
    return {
        "version": decode(inp[:4][::-1], 256),
        "prevhash": hexlify(inp[4:36][::-1]),
        "merkle_root": hexlify(inp[36:68][::-1]),
        "timestamp": decode(inp[68:72][::-1], 256),
        "bits": decode(inp[72:76][::-1], 256),
        "nonce": decode(inp[76:80][::-1], 256),
        "hash": bin_sha256(bin_sha256(inp))[::-1]
    }


def mk_merkle_proof(merkle_root: bytes, hashes: List[str], index: int) -> MerkleProof:
    """
    This function requires all transaction hashes in a block to be provided
    """
    tx_hash = hashes[index]
    try:
        nodes = [safe_from_hex(h)[::-1] for h in hashes]
        if len(nodes) % 2 and len(nodes) > 2:
            nodes.append(nodes[-1])
        layers = [nodes]
        while len(nodes) > 1:
            newnodes = []
            for i in range(0, len(nodes) - 1, 2):
                newnodes.append(bin_sha256(bin_sha256(nodes[i] + nodes[i+1])))
            if len(newnodes) % 2 and len(newnodes) > 2:
                newnodes.append(newnodes[-1])
            nodes = newnodes
            layers.append(nodes)
        # Sanity check, make sure merkle root is valid
        assert bytes_to_hex_string(nodes[0][::-1]) == merkle_root
        merkle_siblings = \
            [layers[i][(index >> i) ^ 1] for i in range(len(layers)-1)]
        return {
            "tx_hash": tx_hash,
            "siblings": [bytes_to_hex_string(x[::-1]) for x in merkle_siblings],
            'proven': True
        }
    except:
        return {
            "tx_hash": tx_hash,
            "siblings": [],
            'proven': False
        }


def verify_merkle_proof(tx_hash: str, merkle_root: bytes, hashes: List[str], index: int) -> MerkleProof:
    h = safe_from_hex(tx_hash)[::-1]
    nodes = [safe_from_hex(h)[::-1] for h in hashes]
    proven = True
    for item in nodes:
        inner_node = (item + h) if (index & 1) else (h + item)
        try:
            deserialize(inner_node)
        except Exception as e:
            pass
        else:
            proven = False          # If a node serializes as a transaction, could be an attack
            break
        h = bin_sha256(bin_sha256(inner_node))
        index >>= 1
    if index != 0:
        proven = False
    h = bytes_to_hex_string(h[::-1]).encode()
    return {
            "tx_hash": tx_hash,
            'proven': proven and h == merkle_root
    }
