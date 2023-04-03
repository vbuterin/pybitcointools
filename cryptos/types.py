from typing import TypedDict, Dict, Any, AnyStr
from typing import List, AnyStr, Union, Callable, Awaitable
from typing_extensions import NotRequired
from .electrumx_client.types import ElectrumXTx


class TxInput(TypedDict):
    tx_hash: NotRequired[str]
    tx_pos: NotRequired[int]
    output: NotRequired[str]
    script: NotRequired[AnyStr]
    sequence: NotRequired[int]
    value: NotRequired[int]
    address: NotRequired[str]


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
    siblings: NotRequired[List[str]]
    proven: bool


class AddressBalance(TypedDict):
    address: str
    balance: int


class AddressStatusUpdate(TypedDict):
    address: str
    status: str


BlockHeaderCallbackSync = Callable[[int, str, BlockHeader], None]
BlockHeaderCallbackAsync = Callable[[int, str, BlockHeader], Awaitable[None]]
BlockHeaderCallback = Union[BlockHeaderCallbackSync, BlockHeaderCallbackAsync]


AddressCallbackSync = Callable[[str, str], None]
AddressCallbackAsync = Callable[[str, str], Awaitable[None]]
AddressCallback = Union[AddressCallbackSync, AddressCallbackAsync]


AddressTXCallbackSync = Callable[[str, List[ElectrumXTx], List[ElectrumXTx], List[ElectrumXTx], List[ElectrumXTx], int, int, int], None]
AddressTXCallbackAsync = Callable[[str, List[ElectrumXTx], List[ElectrumXTx], List[ElectrumXTx], List[ElectrumXTx], int, int, int], Awaitable[None]]
AddressTXCallback = Union[AddressTXCallbackSync, AddressTXCallbackAsync]


# Either a single private key or a mapping of addresses to private keys
PrivkeyType = Union[int, str, bytes]
PrivateKeySignAllType = Union[Dict[str, PrivkeyType], PrivkeyType]
PubKeyType = Union[list, tuple, str, bytes]


class TXInspectType(TypedDict):
    ins: Dict[str, TxInput]
    outs: List[Dict[str, Any]]
    fee: int
