import unittest

from cryptos import coins
from cryptos.types import TxOut
from cryptos.testing.testcases import BaseSyncCoinTestCase
from cryptos.electrumx_client.types import ElectrumXTx, ElectrumXMultiBalanceResponse
from typing import List


class TestBitcoinTestnet(BaseSyncCoinTestCase):
    name: str = "Bitcoin Testnet"
    coin = coins.Bitcoin
    addresses: List[str] = ["n2DQVQZiA2tVBDu4fNAjKVBS2RArWhfncv", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu",
                            "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    segwit_addresses: List[str] = ["2N74sauceDn2qeHFJuNfJ3c1anxPcDRrVtz", "2NDpBxpK4obuGiFodKtYe3dXx14aPwDBPGU",
                                   "2Mt2f4knFtjLZz9CW2979Hw3tYiAYd6WcA1"]
    native_segwit_addresses: List[str] = ["tb1q95cgql39zvtc57g4vn8ytzmlvtt43skngdq0ue",
                                          "tb1qfuvnn87p787z7nqv9seu4e8fqel83yacg7yf2r",
                                          "tb1qst3pkm860tjt9y70ugnaluqyqnfa7h54ekyj66"]
    multisig_addresses: List[str] = ["2MvmK6SRDc13BaYbumBbtkCH2fKbViC5XEv", "2MtT7kkzRDn1kiT9GZoS1zSgh7twP145Qif"]
    privkeys: List[str] = ["098ddf01ebb71ead01fc52cb4ad1f5cafffb5f2d052dd233b3cad18e255e1db1",
                           "0861e1bb62504f5e9f03b59308005a6f2c12c34df108c6f7c52e5e712a08e91401",
                           "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]
    fee: int = 500
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
    txinputs: List[TxOut] = [
        {'output': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33:1', 'value': 190453372316}]
    raw_tx: str = "01000000000101333ae299a6c6353d88e6540c67d8c82281259bc29b3313bcbc9b62a9a7e78a1b0100000017160014ffe21a1b058e7f8dedfcc3f1526f82303cff4fc7ffffffff020095ba0a000000001976a9147e585aa1913cf12e9948e90f67188ee9250d555688acfcb92b4d2c00000017a914e223701f10c2a5e7782ef6e10a2560f4c6e968a2870247304402207f2aa4118eee2ef231eab3afcbf6b01b4c1ca3672bd87a3864cf405741bd2c1d02202ab7502cbc50126f68cb2b366e5b3799d3ec0a3359c6a895a730a6891c7bcae10121023c13734016f27089393f9fc79736e4dca1f27725c68e720e1855202f3fbf037e00000000"

    def test_balance(self):
        self.assertBalanceOK()

    def test_balances(self):
        self.assertBalancesOK()

    def test_merkle_proof(self):
        self.assertMerkleProofOK()

    def test_unspent(self):
        self.assertUnspentOK()

    def test_unspents(self):
        self.assertUnspentsOK()

    def test_history(self):
        self.assertHistoryOK()

    def test_histories(self):
        self.assertHistoriesOK()

    def test_balance_merkle_proven(self):
        self.assertBalanceMerkleProvenOK()

    def test_balances_merkle_proven(self):
        self.assertBalancesMerkleProvenOK()

    def test_block_header(self):
        self.assertBlockHeaderOK()

    def test_block_headers(self):
        self.assertBlockHeadersOK()

    def test_gettx(self):
        self.assertGetSegwitTXOK()

    def test_gettxs(self):
        self.assertGetSegwitTxsOK()

    def test_getverbosetx(self):
        self.assertGetVerboseTXOK()

    def test_transaction(self):
        """
        Sample transaction:
        TxID: ef60508ebe9f684fa881ad41ba278365f238a5fca36af78f3f106c30f7020eca
        0100000003b85f4944e3e479a20605ed99fe7273f9660f3f5504083586258c9937934c368b020000008b4830450221008ccd05c20f3388bbb647f459533cb94f13a331f9baf2ae95600f1b774be42361022070a2c359e52db844fa0259d490ea633a28ec8828c12c7f8dacc723eeae910a4d01410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41ebffffffffb85f4944e3e479a20605ed99fe7273f9660f3f5504083586258c9937934c368b030000008a47304402201ad45bd5011b4e836404bb0afbe9af19f2499d812d70bc14066ebd8e7539dfaa022011b799349e16159bfa20b408f8c2afd0a2dc3bd0c3190ec829f2b36a26f3600201410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41ebffffffff866e8d03dfb47d34199e056cbf2e1b59bdc823d27c42d6e93c153182790f4715010000008b483045022100ee665897434570fbbd7d1a0c47e9a7691198149f2f900c2c8887ea1f78e5ba910220381d23c48631cfb73d4f5d8df18aba11be97e0212030d6d71d1187af1abbeaca01410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41ebffffffff0259165a00000000001976a914e3090570c277eb0064d435e85b746a21c6badbc488acf3c52a03000000001976a9144f19399fc1f1fc2f4c0c2c33cae4e9067e7893b888ac00000000
        """
        self.assertTransactionOK()

    def test_transaction_segwit(self):
        """
        Sample transaction:
        TxID: 0494107dea76e27658b245744ffda3766010af347c3dd68abb2686ca080d1cd5
        010000000001037bf3a7b1498a16c5d0f071973e7ac78dcd9a66ab932c7036a886b294cae7a2ef0000000017160014c384950342cb6f8df55175b48586838b03130fadffffffff8b335a536ac2974e7d64c7fbb205170e57846aee9ad3a53ec194a5b6d76caa8d0100000017160014c384950342cb6f8df55175b48586838b03130fadffffffff82803530d5e8dc48ee0d47102bce815a10b457a5e59922c1a69b1a115b5269c10000000017160014c384950342cb6f8df55175b48586838b03130fadffffffff02de449f010000000017a914e19e8d416381a3b62cbef81b7e6ca23013b09a4587ec69990e0000000017a9140897a6ce77451d195f940e720bb85ef5ad8073ad8702483045022100f19e3081491ccb0fe4e2869fcc002cfeb23fa97b262852d62a54e3c581324d18022040e3ffba29f3c67d1623c0e8829b1e16bf2d6f04f1cabda75594a4aa38a12994012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c60902473044022069328e4005ab077686dd4e5d2e9bf6016d1770ce372a8e97d082eb8b95bd70e70220368e4342f4f6918e7c0009f66d89fc56a32f6478644f19e4dab9068dad4df89e012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c6090247304402204659ce586cf6835d22e93bb1e790d6b5aada76dd0965288700502286247206f202205a47c0befbcd7b24ff1facb3160cd59555461c8a149c9d4d5cb72fa5820491f9012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c60900000000
        """
        self.assertSegwitTransactionOK()

    def test_transaction_native_segwit(self):
        self.assertNativeSegwitTransactionOK()

    def test_transaction_mixed_segwit(self):
        """
        Sample transaction:
        TxID: 15470f798231153ce9d6427cd223c8bd591b2ebf6c059e19347db4df038d6e86
        010000000001033c29f9a514e4bdcf577f55a0466a50f5ac21fc674218e90d10b9111a614cb38f000000001716001482e21b6cfa7ae4b293cfe227dff00404d3df5e95ffffffffb85f4944e3e479a20605ed99fe7273f9660f3f5504083586258c9937934c368b010000006a47304402203276acb7ed43de8f02b72dff6cdf0970527205aa252389496b0a2a790da09aeb02203e982a80939113ee5dff4cabe6ee3eccc2d5f2acdabcea7100e70868e7e1a9c301210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff3ebee01ca34eb427d64fa1f3de8da9aa6862c9e75f9ca91dcbd0284f14eafd21000000006b48304502210090464564c7bacc24a62578ad187eac2c86c03eb79074c581e0feac87bee338c7022035b1ffb0051ef9227b805b3ae0b36b2c873827e7f4971076c9bdcf766b4106dd01210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff02fc5588020000000017a914979c91dbc51a42a528205d78c592c1612dd51fcc873a538802000000001976a91442a3e11a80b25ff63b2074c51d1745132bccbba188ac0247304402204577454ba521b264e2f91e490b2bea3c57a258e4401009b76bcf0b16d96dbb6802201461a6991856253a1e68d95d8f886e4c921eb585d9592b84043e433b0bf09c7501210315991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35000000000000
        """
        self.assertMixedSegwitTransactionOK()

    def test_transaction_multisig(self):
        """
        Sample transaction:
        TxID: df0f97e9a4c5c8ac18181a0b184e884b1770c0b8256cb396794973131b66f933
        0100000001c7cac1e90d3a2cefd7bfeebd03add3f48a7ae0bf3f759084e8b38c548460109b00000000fd3d0100483045022100d0299522bc9c0bd73169a81fab20116ba4be29f2f459a57bb9377d3a503fd54802207a8d5bab3f407db0ba289f2a03a731565fb693ab382ffc9f14349b226093fb55014730440220014a137a860ff585683da584e26f5ff576085c4ba5aade2af2b73599f5eeefcc022054c705fb38fc41a03f626a1934ea5a2a50a4d31ba42d6a424962251ccb745e81014ca9524104de476e251a827e58199ed4d6d7c2177f0a97a2dda150d7a9e59fc5682519eb94d37bc387edff66e7b0f16e92dd045fe968d63e1f203613b76ad733e5cdf8e818210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41eb53aeffffffff02531000000000000017a9140d37ea041956e3173831caaefc798c49ce3a6a4787569100000000000017a91426991e5b586517a6724614823d10aff500ada4be8700000000
        """
        self.assertMultiSigTransactionOK()

    def test_sendmulti_recipient_tx(self):
        """
        Sample transaction:
        TxID: 8b364c9337998c2586350804553f0f66f97372fe99ed0506a279e4e344495fb8
        01000000013c29f9a514e4bdcf577f55a0466a50f5ac21fc674218e90d10b9111a614cb38f010000008b483045022100a36a58b1ff8fca90894db2e299bdf4298cda92a13aca57d98dec2fa7ae13b6a502201b4c47b1c690716d9db02682949c5def900b530f06e9c777f67fa28e523c2f7901410415991434e628402bebcbaa3261864309d2c6fd10c850462b9ef0258832822d35aa26e62e629d2337e3716784ca6c727c73e9600436ded7417d957318dc7a41ebffffffff04835da800000000001976a914e3090570c277eb0064d435e85b746a21c6badbc488acc8e9a401000000001976a9144f19399fc1f1fc2f4c0c2c33cae4e9067e7893b888ac468cfc00000000001976a91442a3e11a80b25ff63b2074c51d1745132bccbba188ac00000000000000001976a91442a3e11a80b25ff63b2074c51d1745132bccbba188ac00000000
        """
        self.assertSendMultiRecipientsTXOK()

    def test_send(self):
        """
        Sample transaction:
        TxID: 21fdea144f28d0cb1da99c5fe7c96268aaa98ddef3a14fd627b44ea31ce0be3e
        0100000001b85f4944e3e479a20605ed99fe7273f9660f3f5504083586258c9937934c368b000000008b483045022100f9467d35970e1121cb8900e1e45ee0caca0892db25bf0125d70e9e5e1070e94502206fc861b1a7b6023f9bb1cfb2d94a6871105faed5d30636dea1f3a1877af142e7014104de476e251a827e58199ed4d6d7c2177f0a97a2dda150d7a9e59fc5682519eb94d37bc387edff66e7b0f16e92dd045fe968d63e1f203613b76ad733e5cdf8e818ffffffff023ceb2100000000001976a9144f19399fc1f1fc2f4c0c2c33cae4e9067e7893b888ac03718600000000001976a914e3090570c277eb0064d435e85b746a21c6badbc488ac00000000
        """
        self.assertSendOK()

    def test_subscribe_block_headers(self):
        self.assertSubscribeBlockHeadersOK()

    def test_latest_block(self):
        self.assertLatestBlockOK()

    def test_confirmations(self):
        self.assertConfirmationsOK()

    def test_subscribe_address(self):
        self.assertSubscribeAddressOK()

    def test_subscribe_address_transactions(self):
        self.assertSubscribeAddressTransactionsOK()
