import unittest

from cryptos import coins_async
from cryptos.testing.testcases_async import BaseAsyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from typing import List, Type


class TestBitcoinTestnet(BaseAsyncCoinTestCase):
    name: str = "Bitcoin Testnet"
    coin: Type[coins_async.BaseCoin] = coins_async.Bitcoin
    addresses: List[str] = ["n2DQVQZiA2tVBDu4fNAjKVBS2RArWhfncv",
                            "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu",
                            "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_addresses: List[str] = ["2N74sauceDn2qeHFJuNfJ3c1anxPcDRrVtz",
                                   "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU",
                                   "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    native_segwit_addresses: List[str] = ["tb1q95cgql39zvtc57g4vn8ytzmlvtt43skngdq0ue",
                                          "tb1qfuvnn87p787z7nqv9seu4e8fqel83yacg7yf2r",
                                          "tb1qst3pkm860tjt9y70ugnaluqyqnfa7h54ekyj66"]
    multisig_addresses: List[str] = ["2MvmK6SRDc13BaYbumBbtkCH2fKbViC5XEv",
                                     "2MtT7kkzRDn1kiT9GZoS1zSgh7twP145Qif"]
    native_segwit_multisig_addresses: List[str] = [
        "tb1q7e42a8gmgp5d7kw8myrruj5qnxp8edp7v5y0y95hrjz6t530uehqkj0tl2",
        "tb1qu7fz4uku8kh6tg7qghj7rnf88g858lal258gzfu85kx7vc5h0qpsyxrfnp"
    ]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    public_keys: List[str] = [
        "04de476e251a827e58199ed4d6d7c2177f0a97a2dda150d7a9e59fc5682519eb94d37bc387edff66e7b0f16e92dd045fe968d63e1f203613b76ad733e5cdf8e818",
        "0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0",
        "0415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41eb"
    ]
    privkey_standard_wifs: List[str] = ['91f8DFTsmhtawuLjR8CiHNkgZGPkUqfJ45LxmENPf3k6fuX1m4N',
                                       'cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f',
                                       "9354Dkk67pJCfmRfMedJPhGPfZCXv2uWd9ZoVNMUtDxjUBbCVZK"]
    privkey_segwit_wifs: List[str] = ['cf4XyPZRSdJxnN3dKdaUodCn6HLiaiKUbTRNF8hbytcebJFytuLg',
                                       'cf2FrZgQT2Bm5xwhTUvC7VtEiFYJ3YAKeUshG6Y3QXX1dSAZ9s9h',
                                       "cmJAMcnywPbCT97PQHs1MWuuY3XD7uxE5S43K7wb43iR1Axqeupz"]
    privkey_native_segwit_wifs: List[str] = ["cWUuQECXGUPpor2rmZBb1T7Hqr94kJ3kS1oEggMWVQrwJy3wWMF4",
                                             "cWSdHQKWGsGd7SvvuQXJKKnkTpLeD7tbV3FZheBwv3mJM6yc95xc",
                                             "cciXnTS5mEg4Ud6crDU7ZLpRHcKZHVgVuzRukfbVZZxhiqfSyfBH"]
    fee: int = 1500
    max_fee: int = 3500
    testnet: bool = True
    min_latest_height: int = 1258030

    unspent_addresses: List[str] = ["ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA", "2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy",
                                    "tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq"]
    unspent: List[ElectrumXTx] = [{'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c',
                                   'tx_pos': 0, 'height': 1238008, 'value': 180000000,
                                   'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'}]
    unspents: List[ElectrumXTx] = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'tx_pos': 0, 'height': 1238008,
         'value': 180000000, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'tx_pos': 1, 'height': 1275633,
         'value': 173980000, 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'tx_pos': 0, 'height': 1275633,
         'value': 6000000, 'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    balance: ElectrumXMultiBalanceResponse = {'confirmed': 180000000, 'unconfirmed': 0}
    balances: List[ElectrumXMultiBalanceResponse] = [
        {'confirmed': 180000000, 'unconfirmed': 0, 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'confirmed': 173980000, 'unconfirmed': 0, 'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'confirmed': 6000000, 'unconfirmed': 0, 'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    history: List[ElectrumXTx] = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'height': 1238008}]
    histories: List[ElectrumXTx] = [
        {'tx_hash': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c', 'height': 1238008,
         'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA'},
        {'tx_hash': 'e25d8f4036e44159b0364b45867e08ae47a57dda68ba800ba8abe1fb2dc54a40', 'height': 1275633,
         'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'height': 1275633,
         'address': '2MwHtiGJJqcFgNnbCu1REVy5ooDEeAAFXMy'},
        {'tx_hash': '70bd4ce0e4cf2977ab53e767865da21483977cdb94b1a36eb68d30829c9c392f', 'height': 1275633,
         'address': 'tb1qjap2aae2tsky3ctlh48yltev0sjdmx92yk76wq'}]
    txid: str = "1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c"
    txheight: int = 1238008
    block_hash: str = "00000000000ac694c157a56de45e2f985adefda11d3e2d7375905a03950852df"
    raw_tx: str = "01000000000101333ae299a6c6353d88e6540c67d8c82281259bc29b3313bcbc9b62a9a7e78a1b0100000017160014ffe21a1b058e7f8dedfcc3f1526f82303cff4fc7ffffffff020095ba0a000000001976a9147e585aa1913cf12e9948e90f67188ee9250d555688acfcb92b4d2c00000017a914e223701f10c2a5e7782ef6e10a2560f4c6e968a2870247304402207f2aa4118eee2ef231eab3afcbf6b01b4c1ca3672bd87a3864cf405741bd2c1d02202ab7502cbc50126f68cb2b366e5b3799d3ec0a3359c6a895a730a6891c7bcae10121023c13734016f27089393f9fc79736e4dca1f27725c68e720e1855202f3fbf037e00000000"

    def test_standard_wif_ok(self):
        self.assertStandardWifOK()

    def test_p2wpkh_p2sh_wif_ok(self):
        self.assertP2WPKH_P2SH_WifOK()

    def test_p2wpkh_wif_ok(self):
        self.assertP2WPKH_WIFOK()

    async def test_balance(self):
        await self.assertBalanceOK()

    async def test_balances(self):
        await self.assertBalancesOK()

    async def test_unspent(self):
        await self.assertUnspentOK()

    async def test_unspents(self):
        await self.assertUnspentsOK()

    async def test_merkle_proof(self):
        await self.assertMerkleProofOK()

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

    @unittest.skip('Intermittent failures')
    async def test_getverbosetx(self):
        await self.assertGetVerboseTXOK()

    async def test_gettxs(self):
        await self.assertGetSegwitTxsOK()

    async def test_transaction(self):
        """
        Sample transaction:
        TxID: ef60508ebe9f684fa881ad41ba278365f238a5fca36af78f3f106c30f7020eca
        """
        await self.assertTransactionOK()

    async def test_transaction_p2pk(self):
        """
        Sample transaction:
        TxID:
        """
        await self.assertTransactionToPKOK()

    async def test_transaction_segwit(self):
        """
        Sample transaction:
        TxID: 0494107dea76e27658b245744ffda3766010af347c3dd68abb2686ca080d1cd5
        """
        await self.assertSegwitTransactionOK()

    async def test_transaction_native_segwit(self):
        """
        Sample transaction:
        TxID: b368c55cd8895c561f176645ce418b3e3ac7e3c98aa74f4a7bcf286e53c86515
        """
        await self.assertNativeSegwitTransactionOK()

    async def test_transaction_mixed_segwit(self):
        """
        Sample transaction:
        TxID: 15470f798231153ce9d6427cd223c8bd591b2ebf6c059e19347db4df038d6e86
        """
        await self.assertMixedSegwitTransactionOK()

    async def test_transaction_multisig(self):
        """
        Sample transaction:
        TxID: a555123e8e49e32e8d462705f278c5cd5a3d08ea5e7e738ecc286dae1a1eac38
        """
        await self.assertMultiSigTransactionOK()

    async def test_transaction_native_segwit_multisig(self):
        """
        Sample transaction:
        TxID: b710704a7939e3e0c82e643faaa3a602549c416a2004feba13e2ef7a9e95dddb
        """
        await self.assertNativeSegwitMultiSigTransactionOK()

    async def test_sendmulti_recipient_tx(self):
        """
        Sample transaction:
        TxID: 8b364c9337998c2586350804553f0f66f97372fe99ed0506a279e4e344495fb8
        """
        await self.assertSendMultiRecipientsTXOK()

    async def test_send(self):
        """
        Sample transaction:
        TxID: 21fdea144f28d0cb1da99c5fe7c96268aaa98ddef3a14fd627b44ea31ce0be3e
        """
        await self.assertSendOK()

    async def test_subscribe_block_headers(self):
        await self.assertSubscribeBlockHeadersOK()

    async def test_subscribe_block_headers_sync(self):
        await self.assertSubscribeBlockHeadersSyncCallbackOK()

    async def test_latest_block(self):
        await self.assertLatestBlockOK()

    async def test_confirmations(self):
        await self.assertConfirmationsOK()

    @unittest.skip('Intermittent failures')
    async def test_subscribe_address(self):
        await self.assertSubscribeAddressOK()

    async def test_subscribe_address_sync(self):
        await self.assertSubscribeAddressSyncCallbackOK()

    async def test_subscribe_address_transactions(self):
        await self.assertSubscribeAddressTransactionsOK()

    async def test_subscribe_address_transactions_sync(self):
        await self.assertSubscribeAddressTransactionsSyncOK()
