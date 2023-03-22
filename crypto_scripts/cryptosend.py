import argparse
import aiorpcx
import asyncio
import sys
from getpass import getpass
from cryptos.main import privtopub, compress
from cryptos.transaction import serialize
from typing import Callable, Any, Optional
from cryptos.script_utils import get_coin, coin_list


async def run_in_executor(func: Callable, *args) -> Any:
    return await asyncio.get_running_loop().run_in_executor(None, func, *args)


async def get_confirmation() -> bool:
    result = await run_in_executor(input, "Send this transaction? (Y/N): ")
    return any(r == result.lower() for r in ("y", "yes"))


async def send(coin: str, testnet: bool, addr: str, to: str, amount: int,
               fee: float = None, change_addr: Optional[str] = None, privkey: Optional[str] = None):
    coin = get_coin(coin, testnet=testnet)
    tx = await coin.preparetx(addr, to, amount, fee=fee, change_addr=change_addr)
    print(serialize(tx))
    print(tx)
    privkey = privkey or await run_in_executor(getpass, "Enter private key to sign this transaction")
    if coin.is_native_segwit(addr):
        expected_addr = coin.privtosegwitaddress(privkey)
    elif coin.is_p2sh(addr):
        expected_addr = coin.privtop2wpkh_p2sh(privkey)
    elif coin.is_p2pkh(addr):
        expected_addr = coin.privtoaddr(privkey)
    elif len(addr) == 66:
        expected_addr = compress(privtopub(privkey))
    else:
        expected_addr = privtopub(privkey)
    try:
        assert expected_addr == addr
    except AssertionError:
        raise AssertionError(f'Private key is for address {expected_addr}, not {addr}')
    tx = coin.signall(tx, privkey)
    print(serialize(tx))
    print(tx)
    if args.yes or await get_confirmation():
        try:
            result = await coin.pushtx(tx)
            print(f'Transaction broadcasted successfully {result}')
        except (aiorpcx.jsonrpc.RPCError, aiorpcx.jsonrpc.ProtocolError) as e:
            sys.stderr.write(e.message.upper())
    else:
        print('Transaction was cancelled')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("addr", help="Send from this address")
    parser.add_argument("to", help="Send to this address")
    parser.add_argument("amount", help="Amount to send", type=int)
    parser.add_argument("-c", "--change", help="Address for change, otherwise from address")
    parser.add_argument("-f", "--fee", help="Fee", type=float)
    parser.add_argument("-x", "--coin", help="Coin",  choices=coin_list, default="btc")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")
    parser.add_argument("-p", "--privkey", help="Private Key")
    parser.add_argument("-y", "--yes", help="Confirm", action="store_true")
    args = parser.parse_args()
    asyncio.run(send(args.coin, args.testnet, args.addr, args.to, args.amount,
                     args.fee, args.change, args.privkey))


if __name__ == "__main__":
    main()
