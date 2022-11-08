from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from typing import List


class TestDogeTestnet(BaseAsyncCoinTestCase):
    name = "Doge Testnet"
    coin = coins_async.Doge
    addresses = ['nptcTdAHaPpEp6BEiCqNHjj1HRgjtFELjM',
                 'nbQPs6XNsA2NzndkhpLDASy4Khg8ZfhUfj',
                 'naGXBTzJbwp4QRNzZJAjx651T6duZy2kgV']
    multisig_addresses: List[str] = ["", ""]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    privkey_standard_wifs: List[str] = ['95YcZiMwUZF3DYW9EHSiC1xEPVdBnFM3dMVBFXkBeMksf8k8F53',
                                       'cf2FrZgQT2Bm5xwhTUvC7VtEiFYJ3YAKeUshG6Y3QXX1dSAZ9s9h',
                                       '96xYaDe9pfeewQb5AosJJLTwVnRyDSbGCRi1yfjGsXyWTNCJpxv']
    fee: int = 250
    max_fee: int = 1500
    testnet = True
    min_latest_height = 4464505

    unspent_addresses = ["ncst7MzasMBQFwx2LuCwj8Z6F4pCRppzBP"]
    unspent = []
    unspents = []
    balance = {'confirmed': 0, 'unconfirmed': 0}
    balances = [{'address': unspent_addresses[0]} | dict(balance)]
    history = []
    histories = history
    txid: str = ""
    txheight: int = 1238008
    block_hash: str = ""
    raw_tx: str = ""

    def test_standard_wif_ok(self):
        self.assertStandardWifOK()


