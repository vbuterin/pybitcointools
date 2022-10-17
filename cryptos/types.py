from typing import TypedDict
from typing import List, AnyStr
from typing_extensions import NotRequired


class TxInput(TypedDict):
    tx_hash: str
    tx_pos: int
    script: str
    sequence: int
    segwit: NotRequired[bool]


class TxOut(TypedDict):
    value: int
    address: NotRequired[str]
    script: NotRequired[str]


class Witness(TypedDict):
    number: int
    scriptCode: AnyStr


class Tx(TypedDict):
    ins: List[TxInput]
    outs: List[TxOut]
    version: str
    marker: NotRequired[str]
    flag: NotRequired[str]
    witness: NotRequired[List[Witness]]
    addresses: NotRequired[List[str]]
    tx_hash: NotRequired[str]
    locktime: int


class BlockHeader(TypedDict):
    version: int
    prevhash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int
    hash: bytes


class MerkleProof(TypedDict):
    tx_hash: str
    siblings: List[str]
    proven: bool
