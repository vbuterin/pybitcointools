from typing import TypedDict, Union, Callable, List, Dict, Any, Literal, Awaitable
from typing_extensions import NotRequired


JsonType = Union[str, int, Dict[str, Any], List[Union[str, int, Dict, List]]]


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


BlockHeaderNotificationCallback = Union[Callable[[ElectrumXBlockHeaderNotification], None], Callable[[ElectrumXBlockHeaderNotification], Awaitable[None]]]


class ElectrumXBalanceResponse(TypedDict):
    confirmed: int
    unconfirmed: int


class ElectrumXTx(TypedDict):
    height: int
    tx_hash: str
    fee: NotRequired[int]
    tx_pos: NotRequired[int]
    value: NotRequired[int]


ElectrumXHistoryResponse = List[ElectrumXTx]


ElectrumXMempoolResponse = List[ElectrumXTx]


ElectrumXUnspentResponse = List[ElectrumXTx]


class ElectrumXScripthashNotification(TypedDict):
    scripthash: str
    status: str


AddressNotificationCallback = Callable[[ElectrumXScripthashNotification], None]


ElectrumXGetTxResponse = Union[str, Dict[str, JsonType]]


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
