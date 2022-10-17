from unittest import skip
from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase


class TestBitcoinTestnet(BaseAsyncCoinTestCase):
    name = "Bitcoin Testnet"
    coin = coins_async.Bitcoin
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu","mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_addresses = ["2N3CxTkwr7uSh6AaZKLjWeR8WxC43bQ2QRZ", "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU", "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    new_segwit_addresses = ["tb1qcwzf2q6zedhcma23wk6gtp5r3vp3xradjc23st", "tb1qfuvnn87p787z7nqv9seu4e8fqel83yacg7yf2r", "tb1qg237zx5qkf0lvweqwnz36969zv4uewapph2pws"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  # Private keys for above address_derivations in same order
    #fee = 54400
    fee = 0  # estimate from network
    blockcypher_coin_symbol = "btc-testnet"
    testnet = True

    num_merkle_siblings = 5
    min_latest_height = 1258030
    multisig_address = "2ND6ptW19yaFEmBa5LtEDzjKc2rSsYyUvqA"
    unspent_addresses = ["ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA", "2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy",
                       "tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq"]
    unspent = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'tx_pos': 0, 'height': 1238008,
         'value': 180000000, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'}
    ]
    unspents = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'tx_pos': 0, 'height': 1238008,
         'value': 180000000, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'tx_pos': 1, 'height': 1275633,
         'value': 173980000, 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'tx_pos': 0, 'height': 1275633,
         'value': 6000000, 'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    balance = {'confirmed': 180000000, 'unconfirmed': 0}
    balances = [
        {'confirmed': 180000000, 'unconfirmed': 0, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'confirmed': 173980000, 'unconfirmed': 0, 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'confirmed': 6000000, 'unconfirmed': 0, 'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    history = [{'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'height': 1238008}]
    histories = [{'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'height': 1238008,
                'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
                {'tx_hash': 'e25d8f4036e44159b0364b45867e08ae47a57dda68ba800ba8abe1fb2dc54a40', 'height': 1275633,
                 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
                    {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'height': 1275633,
                     'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
                    {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'height': 1275633,
                     'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    txid = "1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c"
    txheight = 1238008
    txinputs = [{'output': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33:1', 'value': 190453372316}]
    raw_tx = "01000000000101333ae299a6c6353d88e6540c67d8c82281259bc29b3313bcbc9b62a9a7e78a1b0100000017160014ffe21a1b058e7f8dedfcc3f1526f82303cff4fc7ffffffff020095ba0a000000001976a9147e585aa1913cf12e9948e90f67188ee9250d555688acfcb92b4d2c00000017a914e223701f10c2a5e7782ef6e10a2560f4c6e968a2870247304402207f2aa4118eee2ef231eab3afcbf6b01b4c1ca3672bd87a3864cf405741bd2c1d02202ab7502cbc50126f68cb2b366e5b3799d3ec0a3359c6a895a730a6891c7bcae10121023c13734016f27089393f9fc79736e4dca1f27725c68e720e1855202f3fbf037e00000000"

    async def test_balance(self):
        await self.assertBalanceOK()

    async def test_balances(self):
        await self.assertBalancesOK()

    async def test_merkle_proof(self):
        await self.assertMerkleProofOK()

    async def test_unspent(self):
        await self.assertUnspentOK()

    async def test_unspents(self):
        await self.assertUnspentsOK()

    async def test_history(self):
        await self.assertHistoryOK()

    async def test_histories(self):
        await self.assertHistoriesOK()

    async def test_balance_merkle_proven(self):
        await self.assertBalanceMerkleProvenOK()

    async def test_balances_merkle_proven(self):
        await self.assertBalancesMerkleProvenOK()

    async def test_block_header(self):
        await self.assertBlockHeaderOK()

    async def test_block_headers(self):
        await self.assertBlockHeadersOK()

    async def test_gettx(self):
        await self.assertGetSegwitTXOK()

    async def test_gettxs(self):
        await self.assertGetSegwitTxsOK()

    async def test_transaction(self):
        await self.assertTransactionOK()

    async def test_transaction_segwit(self):
        await self.assertSegwitTransactionOK()

    async def test_transaction_new_segwit(self):
        await self.assertNewSegwitTransactionOK()

    async def test_transaction_mixed_segwit(self):
        await self.assertMixedSegwitTransactionOK()

    async def test_transaction_multisig(self):
        await self.assertMultiSigTransactionOK()

    async def test_sendmultitx(self):
        await self.assertSendMultiTXOK()

    async def test_send(self):
        await self.assertSendOK()

    @skip('Takes too long')
    def test_subscribe_block_headers(self):
        self.assertSubscribeBlockHeadersOK()

    def test_subscribe_address(self):
        self.assertSubscribeAddressOK()
