from typing import TypedDict, Union, Callable, List, Dict, Any, Literal, Awaitable
from typing_extensions import NotRequired


class ElectrumXBlockCPResponse(TypedDict):
    branch: str
    header: str
    root: str


ElectrumXBlockResponse = Union[str, ElectrumXBlockCPResponse]


class ElectrumXBlockHeadersResponse(TypedDict):
    count: int
    hex: str
    max: int
    root: NotRequired[str]
    branch: NotRequired[str]


class ElectrumXBlockHeaderNotification(TypedDict):
    height: int
    hex: str


BlockHeaderNotificationCallback = Callable[[ElectrumXBlockHeaderNotification], Awaitable[None]]


class ElectrumXBalanceResponse(TypedDict):
    confirmed: int
    unconfirmed: int


class ElectrumXMultiBalanceResponse(TypedDict):
    confirmed: int
    unconfirmed: int
    address: str


class ElectrumXTx(TypedDict):
    height: int
    tx_hash: str
    fee: NotRequired[int]
    tx_pos: NotRequired[int]
    value: NotRequired[int]
    address: NotRequired[str]


ElectrumXHistoryResponse = List[ElectrumXTx]


ElectrumXMempoolResponse = List[ElectrumXTx]


ElectrumXUnspentResponse = List[ElectrumXTx]


class ElectrumXTxAddress(TypedDict):
    height: int
    tx_hash: str
    fee: NotRequired[int]
    tx_pos: NotRequired[int]
    value: NotRequired[int]
    address: str


ElectrumXMultiTxResponse = List[ElectrumXTxAddress]


class ElectrumXScripthashNotification(TypedDict):
    scripthash: str
    status: str


AddressNotificationCallback = Callable[[ElectrumXScripthashNotification], Awaitable[None]]


class ElectrumXVerboseTX(TypedDict):
    blockhash: str
    blocktime: int
    confirmations: int
    hash: str
    hex: str
    locktime: int
    size: int
    time: int
    txid: str
    version: int
    vin: List[Dict[str, Any]]
    vout: List[Dict[str, Any]]
    vsize: int
    weight: int


ElectrumXGetTxResponse = Union[str, ElectrumXVerboseTX]


class ElectrumXMerkleResponse(TypedDict):
    block_height: int
    merkle: List[str]
    pos: int


TxidOrTx = Literal['txid', 'tx']
TargetType = Literal['block_hash', 'block_header', "merkle_root"]


class ElectrumXTSCMerkleResponse(TypedDict):
    composite: bool
    index: int
    nodes: List[str]
    proofType: Literal['branch', 'tree']
    target: str
    targetType: TargetType
    txOrId: str
