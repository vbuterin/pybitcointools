import json
import os
import random
from operator import itemgetter
import unittest

import bitcoin.ripemd as ripemd
from bitcoin import *


class TestECCArithmetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('Starting ECC arithmetic tests')

    def test_all(self):
        for i in range(8):
            print('### Round %d' % (i + 1))
            x, y = random.randrange(2 ** 256), random.randrange(2 ** 256)
            self.assertEqual(
                multiply(multiply(G, x), y)[0],
                multiply(multiply(G, y), x)[0]
            )
            self.assertEqual(

                add_pubkeys(multiply(G, x), multiply(G, y))[0],
                multiply(G, add_privkeys(x, y))[0]
            )

            hx, hy = encode(x % N, 16, 64), encode(y % N, 16, 64)
            self.assertEqual(
                multiply(multiply(G, hx), hy)[0],
                multiply(multiply(G, hy), hx)[0]
            )
            self.assertEqual(
                add_pubkeys(multiply(G, hx), multiply(G, hy))[0],
                multiply(G, add_privkeys(hx, hy))[0]
            )
            self.assertEqual(
                b58check_to_hex(pubtoaddr(privtopub(x))),
                b58check_to_hex(pubtoaddr(multiply(G, hx), 23))
            )

            p = privtopub(sha256(str(x)))
            if i % 2 == 1:
                p = changebase(p, 16, 256)
            self.assertEqual(p, decompress(compress(p)))
            self.assertEqual(G[0], multiply(divide(G, x), x)[0])


class TestBases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('Starting base change tests')

    def test_all(self):
        data = [
            [10, '65535', 16, 'ffff'],
            [16, 'deadbeef', 10, '3735928559'],
            [10, '0', 16, ''],
            [256, b'34567', 10, '219919234615'],
            [10, '444', 16, '1bc'],
            [256, b'\x03\x04\x05\x06\x07', 10, '12952339975'],
            [16, '3132333435', 256, b'12345']
        ]
        for prebase, preval, postbase, postval in data:
            self.assertEqual(changebase(preval, prebase, postbase), postval)

        for i in range(100):
            x = random.randrange(1, 9999999999999999)
            frm = random.choice([2, 10, 16, 58, 256])
            to = random.choice([2, 10, 16, 58, 256])
            self.assertEqual(decode(encode(x, to), to), x)
            self.assertEqual(changebase(encode(x, frm), frm, to), encode(x, to))
            self.assertEqual(decode(changebase(encode(x, frm), frm, to), to), x)


class TestElectrumWalletInternalConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('Starting Electrum wallet internal consistency tests')

    def test_all(self):
        for i in range(3):
            seed = sha256(str(random.randrange(2 ** 40)))[:32]
            mpk = electrum_mpk(seed)
            for i in range(5):
                pk = electrum_privkey(seed, i)
                pub = electrum_pubkey((mpk, seed)[i % 2], i)
                pub2 = privtopub(pk)
                self.assertEqual(
                    pub,
                    pub2,
                    'Does not match! Details:\nseed: %s\nmpk: %s\npriv: %s\npub: %s\npub2: %s' % (
                        seed, mpk, pk, pub, pub2
                    )
                )


class TestRawSignRecover(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Basic signing and recovery tests")

    def test_all(self):
        for i in range(20):
            k = sha256(str(i))
            s = ecdsa_raw_sign('35' * 32, k)
            self.assertEqual(
                ecdsa_raw_recover('35' * 32, s),
                decode_pubkey(privtopub(k))
            )


class TestTransactionSignVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Transaction-style signing and verification tests")

    def test_all(self):
        alphabet = "1234567890qwertyuiopasdfghjklzxcvbnm"
        for i in range(10):
            msg = ''.join([random.choice(alphabet) for i in range(random.randrange(20, 200))])
            priv = sha256(str(random.randrange(2 ** 256)))
            pub = privtopub(priv)
            sig = ecdsa_tx_sign(msg, priv)
            self.assertTrue(
                ecdsa_tx_verify(msg, sig, pub),
                "Verification error"
            )

            self.assertIn(
                pub,
                ecdsa_tx_recover(msg, sig),
                "Recovery failed"
            )


class TestSerialize(unittest.TestCase):
    def test_serialize(self):
        tx = '0100000001239f932c780e517015842f3b02ff765fba97f9f63f9f1bc718b686a56ed9c73400000000fd5d010047304402200c40fa58d3f6d5537a343cf9c8d13bc7470baf1d13867e0de3e535cd6b4354c802200f2b48f67494835b060d0b2ff85657d2ba2d9ea4e697888c8cb580e8658183a801483045022056f488c59849a4259e7cef70fe5d6d53a4bd1c59a195b0577bd81cb76044beca022100a735b319fa66af7b178fc719b93f905961ef4d4446deca8757a90de2106dd98a014cc95241046c7d87fd72caeab48e937f2feca9e9a4bd77f0eff4ebb2dbbb9855c023e334e188d32aaec4632ea4cbc575c037d8101aec73d029236e7b1c2380f3e4ad7edced41046fd41cddf3bbda33a240b417a825cc46555949917c7ccf64c59f42fd8dfe95f34fae3b09ed279c8c5b3530510e8cca6230791102eef9961d895e8db54af0563c410488d618b988efd2511fc1f9c03f11c210808852b07fe46128c1a6b1155aa22cdf4b6802460ba593db2d11c7e6cbe19cedef76b7bcabd05d26fd97f4c5a59b225053aeffffffff0310270000000000001976a914a89733100315c37d228a529853af341a9d290a4588ac409c00000000000017a9142b56f9a4009d9ff99b8f97bea4455cd71135f5dd87409c00000000000017a9142b56f9a4009d9ff99b8f97bea4455cd71135f5dd8700000000'
        self.assertEqual(
            serialize(deserialize(tx)),
            tx,
            "Serialize roundtrip failed"
        )

    def test_serialize_script(self):
        script = '47304402200c40fa58d3f6d5537a343cf9c8d13bc7470baf1d13867e0de3e535cd6b4354c802200f2b48f67494835b060d0b2ff85657d2ba2d9ea4e697888c8cb580e8658183a801483045022056f488c59849a4259e7cef70fe5d6d53a4bd1c59a195b0577bd81cb76044beca022100a735b319fa66af7b178fc719b93f905961ef4d4446deca8757a90de2106dd98a014cc95241046c7d87fd72caeab48e937f2feca9e9a4bd77f0eff4ebb2dbbb9855c023e334e188d32aaec4632ea4cbc575c037d8101aec73d029236e7b1c2380f3e4ad7edced41046fd41cddf3bbda33a240b417a825cc46555949917c7ccf64c59f42fd8dfe95f34fae3b09ed279c8c5b3530510e8cca6230791102eef9961d895e8db54af0563c410488d618b988efd2511fc1f9c03f11c210808852b07fe46128c1a6b1155aa22cdf4b6802460ba593db2d11c7e6cbe19cedef76b7bcabd05d26fd97f4c5a59b225053ae'
        self.assertEqual(
            serialize_script(deserialize_script(script)),
            script,
            "Script serialize roundtrip failed"
        )


class TestTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Attempting transaction creation")

    # FIXME: I don't know how to write this as a unit test.
    # What should be asserted?
    def test_all(self):
        privs = [sha256(str(random.randrange(2 ** 256))) for x in range(4)]
        pubs = [privtopub(priv) for priv in privs]
        addresses = [pubtoaddr(pub) for pub in pubs]
        mscript = mk_multisig_script(pubs[1:], 2, 3)
        msigaddr = p2sh_scriptaddr(mscript)
        tx = mktx(['01' * 32 + ':1', '23' * 32 + ':2'], [msigaddr + ':20202', addresses[0] + ':40404'])
        tx1 = sign(tx, 1, privs[0])

        sig1 = multisign(tx, 0, mscript, privs[1])
        self.assertTrue(verify_tx_input(tx1, 0, mscript, sig1, pubs[1]), "Verification Error")

        sig3 = multisign(tx, 0, mscript, privs[3])
        self.assertTrue(verify_tx_input(tx1, 0, mscript, sig3, pubs[3]), "Verification Error")

        tx2 = apply_multisignatures(tx1, 0, mscript, [sig1, sig3])
        print("Outputting transaction: ", tx2)

    # https://github.com/vbuterin/pybitcointools/issues/71
    def test_multisig(self):
        script = mk_multisig_script(["0254236f7d1124fc07600ad3eec5ac47393bf963fbf0608bcce255e685580d16d9",
                                     "03560cad89031c412ad8619398bd43b3d673cb5bdcdac1afc46449382c6a8e0b2b"],
                                    2)

        self.assertEqual(p2sh_scriptaddr(script), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")

        self.assertEqual(p2sh_scriptaddr(script, 0x05), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")
        self.assertEqual(p2sh_scriptaddr(script, 5), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")

        self.assertEqual(p2sh_scriptaddr(script, 0xc4), "2MuABMvWTgpZRd4tAG25KW6YzvcoGVZDZYP")
        self.assertEqual(p2sh_scriptaddr(script, 196), "2MuABMvWTgpZRd4tAG25KW6YzvcoGVZDZYP")


class TestDeterministicGenerate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Beginning RFC6979 deterministic signing tests")

    def test_all(self):
        # Created with python-ecdsa 0.9
        # Code to make your own vectors:
        # class gen:
        #     def order(self): return 115792089237316195423570985008687907852837564279074904382605163141518161494337
        # dummy = gen()
        # for i in range(10): ecdsa.rfc6979.generate_k(dummy, i, hashlib.sha256, hashlib.sha256(str(i)).digest())
        test_vectors = [
            32783320859482229023646250050688645858316445811207841524283044428614360139869,
            109592113955144883013243055602231029997040992035200230706187150761552110229971,
            65765393578006003630736298397268097590176526363988568884298609868706232621488,
            85563144787585457107933685459469453513056530050186673491900346620874099325918,
            99829559501561741463404068005537785834525504175465914981205926165214632019533,
            7755945018790142325513649272940177083855222863968691658328003977498047013576,
            81516639518483202269820502976089105897400159721845694286620077204726637043798,
            52824159213002398817852821148973968315579759063230697131029801896913602807019,
            44033460667645047622273556650595158811264350043302911918907282441675680538675,
            32396602643737403620316035551493791485834117358805817054817536312402837398361
        ]

        for i, ti in enumerate(test_vectors):
            mine = deterministic_generate_k(bin_sha256(str(i)), encode(i, 256, 32))
            self.assertEqual(
                ti,
                mine,
                "Test vector does not match. Details:\n%s\n%s" % (
                    ti,
                    mine
                )
            )


class TestBIP0032(unittest.TestCase):
    """See: https://en.bitcoin.it/wiki/BIP_0032"""

    @classmethod
    def setUpClass(cls):
        print("Beginning BIP0032 tests")

    def _full_derive(self, key, chain):
        if len(chain) == 0:
            return key
        elif chain[0] == 'pub':
            return self._full_derive(bip32_privtopub(key), chain[1:])
        else:
            return self._full_derive(bip32_ckd(key, chain[0]), chain[1:])

    def test_all(self):
        test_vectors = [
            [[],
             'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'],
            [['pub'],
             'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'],
            [[2 ** 31],
             'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'],
            [[2 ** 31, 1],
             'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'],
            [[2 ** 31, 1, 2 ** 31 + 2],
             'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'],
            [[2 ** 31, 1, 2 ** 31 + 2, 'pub', 2, 1000000000],
             'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy']
        ]

        mk = bip32_master_key(safe_from_hex('000102030405060708090a0b0c0d0e0f'))

        for tv in test_vectors:
            left, right = self._full_derive(mk, tv[0]), tv[1]
            self.assertEqual(
                left,
                right,
                "Test vector does not match. Details: \n%s\n%s\n\%s" % (
                    tv[0],
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(left)],
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(right)],
                )
            )

    def test_all_testnet(self):
        test_vectors = [
            [[],
             'tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m'],
            [['pub'],
             'tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp'],
            [[2 ** 31],
             'tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9'],
            [[2 ** 31, 1],
             'tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q'],
            [[2 ** 31, 1, 2 ** 31 + 2],
             'tprv8gjmbDPpbAirVSezBEMuwSu1Ci9EpUJWKokZTYccSZSomNMLytWyLdtDNHRbucNaRJWWHANf9AzEdWVAqahfyRjVMKbNRhBmxAM8EJr7R15'],
            [[2 ** 31, 1, 2 ** 31 + 2, 'pub', 2, 1000000000],
             'tpubDHNy3kAG39ThyiwwsgoKY4iRenXDRtce8qdCFJZXPMCJg5dsCUHayp84raLTpvyiNA9sXPob5rgqkKvkN8S7MMyXbnEhGJMW64Cf4vFAoaF']
        ]

        mk = bip32_master_key(safe_from_hex('000102030405060708090a0b0c0d0e0f'), TESTNET_PRIVATE)

        for tv in test_vectors:
            left, right = self._full_derive(mk, tv[0]), tv[1]
            self.assertEqual(
                left,
                right,
                "Test vector does not match. Details:\n%s\n%s\n%s\n\%s" % (
                    left,
                    tv[0],
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(left)],
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(right)],
                )
            )

    def test_extra(self):
        master = bip32_master_key(safe_from_hex("000102030405060708090a0b0c0d0e0f"))

        # m/0
        assert bip32_ckd(master,
                         "0") == "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R"
        assert bip32_privtopub(bip32_ckd(master,
                                         "0")) == "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1"

        # m/1
        assert bip32_ckd(master,
                         "1") == "xprv9uHRZZhbkedL4yTpidDvuVfrdUkTbhDHviERRBkbzbNDZeMjWzqzKAdxWhzftGDSxDmBdakjqHiZJbkwiaTEXJdjZAaAjMZEE3PMbMrPJih"
        assert bip32_privtopub(bip32_ckd(master,
                                         "1")) == "xpub68Gmy5EVb2BdHTYHpekwGdcbBWax19w9HwA2DaADYvuCSSgt4YAErxxSN1KWSnmyqkwRNbnTj3XiUBKmHeC8rTjLRPjSULcDKQQgfgJDppq"

        # m/0/0
        assert bip32_ckd(bip32_ckd(master, "0"),
                         "0") == "xprv9ww7sMFLzJMzur2oEQDB642fbsMS4q6JRraMVTrM9bTWBq7NDS8ZpmsKVB4YF3mZecqax1fjnsPF19xnsJNfRp4RSyexacULXMKowSACTRc"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, "0"),
                                         "0")) == "xpub6AvUGrnEpfvJ8L7GLRkBTByQ9uBvUHp9o5VxHrFxhvzV4dSWkySpNaBoLR9FpbnwRmTa69yLHF3QfcaxbWT7gWdwws5k4dpmJvqpEuMWwnj"

        # m/0'
        assert bip32_ckd(master,
                         2 ** 31) == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        assert bip32_privtopub(bip32_ckd(master,
                                         2 ** 31)) == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

        # m/1'
        assert bip32_ckd(master,
                         2 ** 31 + 1) == "xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master,
                                         2 ** 31 + 1)) == "xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        # m/1'
        assert bip32_ckd(master,
                         1 + 2 ** 31) == "xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master,
                                         1 + 2 ** 31)) == "xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        # m/0'/0
        assert bip32_ckd(bip32_ckd(master, 2 ** 31),
                         "0") == "xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM1h3BoPuEJzsgeypdKj"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2 ** 31),
                                         "0")) == "xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG"

        # m/0'/0'
        assert bip32_ckd(bip32_ckd(master, 2 ** 31),
                         2 ** 31) == "xprv9wTYmMFmpgaLB5Hge4YtaGqCKpsYPTD9vXWSsmdZrNU3Y2i4WoBykm6ZteeCLCCZpGxdHQuqEhM6Gdo2X6CVrQiTw6AAneF9WSkA9ewaxtS"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2 ** 31),
                                         2 ** 31)) == "xpub6ASuArnff48dPZN9k65twQmvsri2nuw1HkS3gA3BQi12Qq3D4LWEJZR3jwCAr1NhsFMcQcBkmevmub6SLP37bNq91SEShXtEGUbX3GhNaGk"

        # m/44'/0'/0'/0/0
        assert bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2 ** 31), 2 ** 31), 2 ** 31), 0),
                         0) == "xprvA4A9CuBXhdBtCaLxwrw64Jaran4n1rgzeS5mjH47Ds8V67uZS8tTkG8jV3BZi83QqYXPcN4v8EjK2Aof4YcEeqLt688mV57gF4j6QZWdP9U"
        assert bip32_privtopub(
            bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2 ** 31), 2 ** 31), 2 ** 31), 0),
                      0)) == "xpub6H9VcQiRXzkBR4RS3tU6RSXb8ouGRKQr1f1NXfTinCfTxvEhygCiJ4TDLHz1dyQ6d2Vz8Ne7eezkrViwaPo2ZMsNjVtFwvzsQXCDV6HJ3cV"


class TestStartingAddressAndScriptGenerationConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Starting address and script generation consistency tests")

    def test_all(self):
        for i in range(5):
            a = privtoaddr(random_key())
            self.assertEqual(a, script_to_address(address_to_script(a)))
            self.assertEqual(a, script_to_address(address_to_script(a), 0))
            self.assertEqual(a, script_to_address(address_to_script(a), 0x00))

            b = privtoaddr(random_key(), 5)
            self.assertEqual(b, script_to_address(address_to_script(b)))
            self.assertEqual(b, script_to_address(address_to_script(b), 0))
            self.assertEqual(b, script_to_address(address_to_script(b), 0x00))
            self.assertEqual(b, script_to_address(address_to_script(b), 5))
            self.assertEqual(b, script_to_address(address_to_script(b), 0x05))

        for i in range(5):
            a = privtoaddr(random_key(), 0x6f)
            self.assertEqual(a, script_to_address(address_to_script(a), 111))
            self.assertEqual(a, script_to_address(address_to_script(a), 0x6f))

            b = privtoaddr(random_key(), 0xc4)
            self.assertEqual(b, script_to_address(address_to_script(b), 111))
            self.assertEqual(b, script_to_address(address_to_script(b), 0x6f))
            self.assertEqual(b, script_to_address(address_to_script(b), 196))
            self.assertEqual(b, script_to_address(address_to_script(b), 0xc4))


class TestRipeMD160PythonBackup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('Testing the pure python backup for ripemd160')

    def test_all(self):
        strvec = [
            '',
            'The quick brown fox jumps over the lazy dog',
            'The quick brown fox jumps over the lazy cog',
            'Nobody inspects the spammish repetition'
        ]

        target = [
            '9c1185a5c5e9fc54612808977ee8f548b2258d31',
            '37f332f68db77bd9d7edd4969571ad671cf9dd3b',
            '132072df690933835eb8b6ad0b77e7b6f14acad7',
            'cc4a5ce1b3df48aec5d22d1f16b894a0b894eccc'
        ]

        hash160target = [
            'b472a266d0bd89c13706a4132ccfb16f7c3b9fcb',
            '0e3397b4abc7a382b3ea2365883c3c7ca5f07600',
            '53e0dacac5249e46114f65cb1f30d156b14e0bdc',
            '1c9b7b48049a8f98699bca22a5856c5ef571cd68'
        ]

        for i, s in enumerate(strvec):
            digest = ripemd.RIPEMD160(s).digest()
            hash160digest = ripemd.RIPEMD160(bin_sha256(s)).digest()
            self.assertEqual(bytes_to_hex_string(digest), target[i])
            self.assertEqual(bytes_to_hex_string(hash160digest), hash160target[i])
            self.assertEqual(bytes_to_hex_string(bin_hash160(from_string_to_bytes(s))), hash160target[i])
            self.assertEqual(hash160(from_string_to_bytes(s)), hash160target[i])


class TestScriptVsAddressOutputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('Testing script vs address outputs')

    def test_all(self):
        addr0 = '1Lqgj1ThNfwLgHMp5qJUerYsuUEm8vHmVG'
        script0 = '76a914d99f84267d1f90f3e870a5e9d2399918140be61d88ac'
        addr1 = '31oSGBBNrpCiENH3XMZpiP6GTC4tad4bMy'
        script1 = 'a9140136d001619faba572df2ef3d193a57ad29122d987'

        inputs = [{
            'output': 'cd6219ea108119dc62fce09698b649efde56eca7ce223a3315e8b431f6280ce7:0',
            'value': 158000
        }]

        outputs = [
            [{'address': addr0, 'value': 1000}, {'address': addr1, 'value': 2000}],
            [{'script': script0, 'value': 1000}, {'address': addr1, 'value': 2000}],
            [{'address': addr0, 'value': 1000}, {'script': script1, 'value': 2000}],
            [{'script': script0, 'value': 1000}, {'script': script1, 'value': 2000}],
            [addr0 + ':1000', addr1 + ':2000'],
            [script0 + ':1000', addr1 + ':2000'],
            [addr0 + ':1000', script1 + ':2000'],
            [script0 + ':1000', script1 + ':2000']
        ]

        for outs in outputs:
            tx_struct = deserialize(mktx(inputs, outs))
            self.assertEqual(tx_struct['outs'], outputs[3])


class TestConversions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.privkey_hex = (
            "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262"
        )
        cls.privkey_bin = (
            b"\xe9\x87=y\xc6\xd8}\xc0\xfbjWxc3\x89\xf4E2\x130=\xa6\x1f \xbdg\xfc#:\xa32b"
        )

        cls.pubkey_hex = (
            "04588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9f88ff2a00d7e752d44cbe16e1ebcf0890b76ec7c78886109dee76ccfc8445424"
        )
        cls.pubkey_bin = (
            b"\x04X\x8d *\xfc\xc1\xeeJ\xb5%LxG\xec%\xb9\xa15\xbb\xda\x0f+\xc6\x9e\xe1\xa7\x14t\x9f\xd7}\xc9\xf8\x8f\xf2\xa0\r~u-D\xcb\xe1n\x1e\xbc\xf0\x89\x0bv\xec|x\x88a\t\xde\xe7l\xcf\xc8DT$"
        )

    def test_privkey_to_pubkey(self):
        pubkey_hex = privkey_to_pubkey(self.privkey_hex)
        self.assertEqual(pubkey_hex, self.pubkey_hex)

    def test_changebase(self):
        self.assertEqual(
            self.pubkey_bin,
            changebase(
                self.pubkey_hex, 16, 256, minlen=len(self.pubkey_bin)
            )
        )

        self.assertEqual(
            self.pubkey_hex,
            changebase(
                self.pubkey_bin, 256, 16, minlen=len(self.pubkey_hex)
            )
        )

        self.assertEqual(
            self.privkey_bin,
            changebase(
                self.privkey_hex, 16, 256, minlen=len(self.privkey_bin)
            )
        )

        self.assertEqual(
            self.privkey_hex,
            changebase(
                self.privkey_bin, 256, 16, minlen=len(self.privkey_hex)
            )
        )

class TestAddressUnspent(unittest.TestCase):
    satoshi_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    satoshi_unspent_len = 132
    mainnet_address = "1FdJkPdpXtK3t5utZHJAop3saLZWfPfgak"
    mainnet_unspent = [
        {'output': 'c5b78c0980b91d566e7818fc7a092083baf398202fa5d9801c727b1857f6f465:0', 'value': 1324731536},
        {'output': 'db966b76e8abed95070fefcf87de37d8923bdbc512b1f986e55e18d0bc5c7fc5:0', 'value': 1405023504},
    ]
    mainnet_address_multiple = ["1FdJkPdpXtK3t5utZHJAop3saLZWfPfgak", "1MQmZKGjRLUMUb8piNXzY1QzAN4syArses"]
    mainnet_unspent_multiple = [
        {'output': 'c5b78c0980b91d566e7818fc7a092083baf398202fa5d9801c727b1857f6f465:0', 'value': 1324731536},
        {'output': 'db966b76e8abed95070fefcf87de37d8923bdbc512b1f986e55e18d0bc5c7fc5:0', 'value': 1405023504},
        {'output': '9e141a9e89c93e75c83ac87bbac1932fe11907125c10db53eac4206dffb8b757:0', 'value': 488316}]
    testnet_address = "myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW"
    testnet_unspent = [
            {'output': '056b4f3201fff0a3fac2e93af0278a0fc8f9c602b3f4a955b051b7b46253be99:0', 'value': 110000000}]
    blockcypher_test_address = "CAuGy4TdxCDKeTkzsWm4AmCjpRY3WQgstV"
    blockcypher_test_unspent = []

    def setUp(self):
        import requests
        """response = requests.post("https://api.blockcypher.com/v1/bcy/test/addrs?token=573375de83e64bf6b1259420d198dbd5")
        result = response.json())"""
        requests.get("https://api.blockcypher.com/v1/bcy/test/faucet?token=573375de83e64bf6b1259420d198dbd5",
                     params={"address": self.blockcypher_test_address, "amount": 100000})


    def test_parse_addr_args(self):
        network, addr_args = parse_addr_args(self.mainnet_address)
        self.assertEqual(network, "btc")
        self.assertListEqual(addr_args, [self.mainnet_address])

        network, addr_args = parse_addr_args(self.mainnet_address, "btc")
        self.assertEqual(network, "btc")
        self.assertListEqual(addr_args, [self.mainnet_address])

        network, addr_args = parse_addr_args(*self.mainnet_address_multiple)
        self.assertEqual(network, "btc")
        self.assertListEqual(addr_args, self.mainnet_address_multiple)

        network, addr_args = parse_addr_args(*self.mainnet_address_multiple, "btc")
        self.assertEqual(network, "btc")
        self.assertListEqual(addr_args, self.mainnet_address_multiple)

        network, addr_args = parse_addr_args(self.testnet_address)
        self.assertEqual(network, "testnet")
        self.assertListEqual(addr_args, [self.testnet_address])

        network, addr_args = parse_addr_args([self.testnet_address], "testnet")
        self.assertEqual(network, "testnet")
        self.assertListEqual(addr_args, [self.testnet_address])

        network, addr_args = parse_addr_args(self.blockcypher_test_address, "bcy_test")
        self.assertEqual(network, "bcy_test")
        self.assertEqual(addr_args, [self.blockcypher_test_address])

    def assertUnorderedListEqual(self, list1, list2, key):
        list1 = sorted(list1, key=itemgetter(key))
        list2 = sorted(list2, key=itemgetter(key))
        self.assertEqual(list1, list2)

    def test_unspent_mainnet(self):
        unspent_outputs = bci_unspent(self.mainnet_address)
        self.assertUnorderedListEqual(unspent_outputs, self.mainnet_unspent, 'output')
        unspent_outputs = blockcypher_unspent(self.mainnet_address)
        self.assertUnorderedListEqual(unspent_outputs, self.mainnet_unspent, 'output')
        unspent_outputs_bci = bci_unspent(self.satoshi_address)
        self.assertGreaterEqual(len(unspent_outputs_bci), self.satoshi_unspent_len)
        unspent_outputs_bc = blockcypher_unspent(self.satoshi_address)
        self.assertGreaterEqual(len(unspent_outputs_bc), self.satoshi_unspent_len)
        self.assertEqual(len(unspent_outputs_bci), len(unspent_outputs_bc))
        unspent_outputs = unspent(self.mainnet_address)
        self.assertUnorderedListEqual(unspent_outputs, self.mainnet_unspent, 'output')
        unspent_outputs = unspent(self.mainnet_address, source="blockexplorer")
        self.assertUnorderedListEqual(unspent_outputs, self.mainnet_unspent, 'output')

    def test_unspent_mainnet_multiple_address(self):
        unspent_outputs = bci_unspent(self.mainnet_address_multiple)
        self.assertUnorderedListEqual(unspent_outputs, self.mainnet_unspent_multiple, 'output')
        unspent_outputs = blockcypher_unspent(self.mainnet_address_multiple)
        self.assertUnorderedListEqual(unspent_outputs, self.mainnet_unspent_multiple, 'output')

    def test_unspent_testnet(self):
        self.assertRaises(Exception, bci_unspent, self.testnet_address)
        unspent_outputs = blockcypher_unspent(self.testnet_address)
        self.assertUnorderedListEqual(unspent_outputs, self.testnet_unspent, 'output')

    def test_unspent_bcy_test(self):
        self.assertRaises(Exception, bci_unspent, self.blockcypher_test_address)
        unspent_outputs = blockcypher_unspent(self.blockcypher_test_address)
        print(unspent_outputs)
        self.assertUnorderedListEqual(unspent_outputs, self.blockcypher_test_unspent, 'output')

class TestBlockInfo(unittest.TestCase):
    minimum_last_block_height_main = 495929
    minimum_last_block_height_testnet = 1231684

    def test_last_block_height(self):
        height = last_block_height_bci()
        self.assertGreaterEqual(height, self.minimum_last_block_height_main)
        height = last_block_height()
        self.assertGreaterEqual(height, self.minimum_last_block_height_main)
        height = last_block_height("testnet")
        self.assertGreaterEqual(height, self.minimum_last_block_height_testnet)
        height = last_block_height_blockcypher()
        self.assertGreaterEqual(height, self.minimum_last_block_height_main)
        height = last_block_height_blockcypher("testnet")
        self.assertGreaterEqual(height, self.minimum_last_block_height_testnet)

class TestGetTransactions(unittest.TestCase):
    tx_hashes = ["7fe165ca88fb2439d6fd1002105a485bfccbb288f1f9c9fdcc33da8690d45981",
                 "7412e5e86e0f07d4dd818b0f6d4389c9f196c5715828c5092c0e5f5c67cc2687"]
    tx_hexes = [b'0100000001b082b343052ef7b5f71914a2a5d4063ee843e49db595919f1aeabcb4b006f76b010000006a473044022069daff9568e26cb85ef155eead74e1e1acf338a495a287c709e92ba75fe36ad102201fb9a8ea9a46fa7d0437b635bf7a25dd6c3aace214029e8fcbf48beaebb890cf012102187edfe5487df34118a8afb1b447e42cb75d9655d586a3578d5be89f5b2763dfffffffff0216d6d40a000000001976a9147d48ab93a39eeb9a5f3a5fe53a20efb533b6da6488ac6bf20000000000001976a9145f10a0434f1d4f5119a3d3f17ea44c35a947330f88ac00000000',
                b'0100000001d83ca497f91a9d6f75dd9c12ed2db1c54ae67f8113aea40536e055cbe722c846010000006a47304402206ab6fd2a107378f52437528a4802d5e40c1deb94b83f2ea07553eaf6f8339ccb02206b919b92b63721123e20c4e3c4cf9c37b041fae6ea2ef376b7c95a3c6537ba67012103542aa3891b2e2c3950ecbdbd10d1e8ce63a59682dcf6c5ff3a085649b9c3ef0affffffff01e00a0001000000001976a914d9c07c45043736caeed61bfaa9122301dfb248da88ac00000000']
    tx_jsons_bic = [{'ver': 1, 'inputs': [{'sequence': 4294967295, 'witness': '', 'prev_out': {'spent': True, 'tx_index': 304339214, 'type': 0, 'addr': '1L37ACyxXpT1qe25BVY6D3MUu6jcZN4a85', 'value': 182032657, 'n': 1, 'script': '76a914d0d05ce4e78d93ee95a7d79e82638dc84c7298bb88ac'}, 'script': '473044022069daff9568e26cb85ef155eead74e1e1acf338a495a287c709e92ba75fe36ad102201fb9a8ea9a46fa7d0437b635bf7a25dd6c3aace214029e8fcbf48beaebb890cf012102187edfe5487df34118a8afb1b447e42cb75d9655d586a3578d5be89f5b2763df'}], 'weight': 900, 'block_height': 495924, 'relayed_by': '0.0.0.0', 'out': [{'spent': True, 'tx_index': 304357770, 'type': 0, 'addr': '1CRSXCGg1Ky9Q5gTh6eXewHqN89TPtuFsJ', 'value': 181720598, 'n': 0, 'script': '76a9147d48ab93a39eeb9a5f3a5fe53a20efb533b6da6488ac'}, {'spent': False, 'tx_index': 304357770, 'type': 0, 'addr': '19ff7RPZuHubMSfUuYmeNAePy4gwE2oGJ6', 'value': 62059, 'n': 1, 'script': '76a9145f10a0434f1d4f5119a3d3f17ea44c35a947330f88ac'}], 'lock_time': 0, 'size': 225, 'double_spend': False, 'time': 1511544761, 'tx_index': 304357770, 'vin_sz': 1, 'hash': '7fe165ca88fb2439d6fd1002105a485bfccbb288f1f9c9fdcc33da8690d45981', 'vout_sz': 2},
                    {'ver': 1, 'inputs': [{'sequence': 4294967295, 'witness': '', 'prev_out': {'spent': True, 'tx_index': 298590677, 'type': 0, 'addr': '1MJxQ5aa4rEi4PTxmHMimZTC3TL58BSbZ2', 'value': 17080000, 'n': 1, 'script': '76a914dec7d4b435bd882db9e553a5a69665af0860d41788ac'}, 'script': '47304402206ab6fd2a107378f52437528a4802d5e40c1deb94b83f2ea07553eaf6f8339ccb02206b919b92b63721123e20c4e3c4cf9c37b041fae6ea2ef376b7c95a3c6537ba67012103542aa3891b2e2c3950ecbdbd10d1e8ce63a59682dcf6c5ff3a085649b9c3ef0a'}], 'weight': 764, 'block_height': 495924, 'relayed_by': '0.0.0.0', 'out': [{'spent': True, 'tx_index': 304357871, 'type': 0, 'addr': '1LrNDkTLt2qDCuTfG3kK9pbn9A43gR9Be3', 'value': 16780000, 'n': 0, 'script': '76a914d9c07c45043736caeed61bfaa9122301dfb248da88ac'}], 'lock_time': 0, 'size': 191, 'double_spend': False, 'time': 1511544779, 'tx_index': 304357871, 'vin_sz': 1, 'hash': '7412e5e86e0f07d4dd818b0f6d4389c9f196c5715828c5092c0e5f5c67cc2687', 'vout_sz': 1}]
    tx_jsons_bc = [{'block_hash': '0000000000000000007045f220469d8579364e8a3d92eaa3dc47642f65ceb101', 'block_height': 495924, 'block_index': 2, 'hash': '7fe165ca88fb2439d6fd1002105a485bfccbb288f1f9c9fdcc33da8690d45981', 'addresses': ['19ff7RPZuHubMSfUuYmeNAePy4gwE2oGJ6', '1CRSXCGg1Ky9Q5gTh6eXewHqN89TPtuFsJ', '1L37ACyxXpT1qe25BVY6D3MUu6jcZN4a85'], 'total': 181782657, 'fees': 250000, 'size': 225, 'preference': 'high', 'relayed_by': '85.6.243.56:8333', 'confirmed': '2017-11-24T17:35:44Z', 'received': '2017-11-24T17:32:41.065Z', 'ver': 1, 'double_spend': False, 'vin_sz': 1, 'vout_sz': 2, 'confirmations': 7, 'confidence': 1, 'inputs': [{'prev_hash': '6bf706b0b4bcea1a9f9195b59de443e83e06d4a5a21419f7b5f72e0543b382b0', 'output_index': 1, 'script': '473044022069daff9568e26cb85ef155eead74e1e1acf338a495a287c709e92ba75fe36ad102201fb9a8ea9a46fa7d0437b635bf7a25dd6c3aace214029e8fcbf48beaebb890cf012102187edfe5487df34118a8afb1b447e42cb75d9655d586a3578d5be89f5b2763df', 'output_value': 182032657, 'sequence': 4294967295, 'addresses': ['1L37ACyxXpT1qe25BVY6D3MUu6jcZN4a85'], 'script_type': 'pay-to-pubkey-hash', 'age': 495914}], 'outputs': [{'value': 181720598, 'script': '76a9147d48ab93a39eeb9a5f3a5fe53a20efb533b6da6488ac', 'spent_by': 'dc6d48bb503bb25174636a8b70029fbf25d757c671a3e0cfc8ab13941cbbeb41', 'addresses': ['1CRSXCGg1Ky9Q5gTh6eXewHqN89TPtuFsJ'], 'script_type': 'pay-to-pubkey-hash'}, {'value': 62059, 'script': '76a9145f10a0434f1d4f5119a3d3f17ea44c35a947330f88ac', 'addresses': ['19ff7RPZuHubMSfUuYmeNAePy4gwE2oGJ6'], 'script_type': 'pay-to-pubkey-hash'}]},
                   {'block_hash': '0000000000000000007045f220469d8579364e8a3d92eaa3dc47642f65ceb101', 'block_height': 495924, 'block_index': 1, 'hash': '7412e5e86e0f07d4dd818b0f6d4389c9f196c5715828c5092c0e5f5c67cc2687', 'addresses': ['1LrNDkTLt2qDCuTfG3kK9pbn9A43gR9Be3', '1MJxQ5aa4rEi4PTxmHMimZTC3TL58BSbZ2'], 'total': 16780000, 'fees': 300000, 'size': 191, 'preference': 'high', 'relayed_by': '137.117.193.113:8333', 'confirmed': '2017-11-24T17:35:44Z', 'received': '2017-11-24T17:32:59.921Z', 'ver': 1, 'double_spend': False, 'vin_sz': 1, 'vout_sz': 1, 'confirmations': 7, 'confidence': 1, 'inputs': [{'prev_hash': '46c822e7cb55e03605a4ae13817fe64ac5b12ded129cdd756f9d1af997a43cd8', 'output_index': 1, 'script': '47304402206ab6fd2a107378f52437528a4802d5e40c1deb94b83f2ea07553eaf6f8339ccb02206b919b92b63721123e20c4e3c4cf9c37b041fae6ea2ef376b7c95a3c6537ba67012103542aa3891b2e2c3950ecbdbd10d1e8ce63a59682dcf6c5ff3a085649b9c3ef0a', 'output_value': 17080000, 'sequence': 4294967295, 'addresses': ['1MJxQ5aa4rEi4PTxmHMimZTC3TL58BSbZ2'], 'script_type': 'pay-to-pubkey-hash', 'age': 493205}], 'outputs': [ {'value': 16780000, 'script': '76a914d9c07c45043736caeed61bfaa9122301dfb248da88ac', 'spent_by': 'e217dd7b48b8cd838d279d8bba4642ec33cb9bf1f6cb426b90c5de95e762ed60','addresses': ['1LrNDkTLt2qDCuTfG3kK9pbn9A43gR9Be3'], 'script_type': 'pay-to-pubkey-hash'}]}]
    testnet_hash = "9683898a35fdfe8033fd4f1ef6ddf0dc3f20bf5813b05495421797ba861711b5"
    testnet_hex = b"0100000001cd9ac8bd3d454d5869abba0b9fb820b05d16ce7645334de28c39ef21025c263d000000006a47304402200403e11c283e39a727e6c0dc9531a8052341b97575d50443e48268e1681c5df302200d89802f0c2cf11e86fbb06a3072e8a0d72371c336512d2ae3a2c3de6d6bafbc0121038aa15d2666158670e1a752f07194817e75146c31cddd2b029e3657502604e132feffffff0280f0fa02000000001976a914f23096605eb5a5767ed88d487d732ec37bc768e688acc887bf04000000001976a91468a45d67b9ce61fd1bb880aa2f9353a10df5c61a88ac46cb1200"
    testnet_json = {'block_hash': '000000005be78b33f514efbd7a8919928111659ba3265cf32fd75bd7dec638dc', 'block_height': 1231687, 'block_index': 1, 'hash': '9683898a35fdfe8033fd4f1ef6ddf0dc3f20bf5813b05495421797ba861711b5', 'addresses': ['mi4N8Vp7x4owuW7JcxFwEDbNJQWcgvFpen', 'mq4FUGvWjk8ded1PjcmWRiTDJF8NBhJYQh', 'n3bY2PXmZkyS2gJBSbZsc9L3TxwLvL2557'], 'total': 129661000, 'fees': 339000, 'size': 225, 'preference': 'high', 'relayed_by': '54.229.231.152:18333', 'confirmed': '2017-11-24T19:00:23Z', 'received': '2017-11-24T18:54:22.412Z', 'ver': 1, 'lock_time': 1231686, 'double_spend': False, 'vin_sz': 1, 'vout_sz': 2, 'confirmations': 1, 'confidence': 1, 'inputs': [{'prev_hash': '3d265c0221ef398ce24d334576ce165db020b89f0bbaab69584d453dbdc89acd', 'output_index': 0, 'script': '47304402200403e11c283e39a727e6c0dc9531a8052341b97575d50443e48268e1681c5df302200d89802f0c2cf11e86fbb06a3072e8a0d72371c336512d2ae3a2c3de6d6bafbc0121038aa15d2666158670e1a752f07194817e75146c31cddd2b029e3657502604e132', 'output_value': 130000000, 'sequence': 4294967294, 'addresses': ['mi4N8Vp7x4owuW7JcxFwEDbNJQWcgvFpen'], 'script_type': 'pay-to-pubkey-hash', 'age': 1231672}], 'outputs': [{'value': 50000000, 'script': '76a914f23096605eb5a5767ed88d487d732ec37bc768e688ac', 'addresses': ['n3bY2PXmZkyS2gJBSbZsc9L3TxwLvL2557'], 'script_type': 'pay-to-pubkey-hash'}, {'value': 79661000, 'script': '76a91468a45d67b9ce61fd1bb880aa2f9353a10df5c61a88ac', 'addresses': ['mq4FUGvWjk8ded1PjcmWRiTDJF8NBhJYQh'], 'script_type': 'pay-to-pubkey-hash'}]}

    def assertUnorderedListEqual(self, list1, list2, key):
        list1 = sorted(list1, key=itemgetter(key))
        list2 = sorted(list2, key=itemgetter(key))
        self.assertEqual(list1, list2)

    def test_get_transaction_hex(self):
        tx_hex = bci_fetchtx(self.tx_hashes[0])
        self.assertEqual(tx_hex, self.tx_hexes[0])
        tx_hex = blockcypher_fetchtx(self.tx_hashes[0])
        self.assertEqual(tx_hex, self.tx_hexes[0])

    def test_get_transaction_hex_testnet(self):
        tx_hex = blockcypher_fetchtx(self.testnet_hash, network="testnet")
        self.assertEqual(tx_hex, self.testnet_hex)

    def test_get_transaction_json_testnet(self):
        tx_hex = blockcypher_fetchtx(self.testnet_hash, hexonly=False, network="testnet")
        self.assertEqual(tx_hex, self.testnet_json)

    def test_get_multiple_transaction_hex(self):
        tx_hexes = bci_fetchtx(self.tx_hashes)
        self.assertUnorderedListEqual(tx_hexes, self.tx_hexes, "hash")
        tx_hex = blockcypher_fetchtx(self.tx_hashes)
        self.assertUnorderedListEqual(tx_hex, self.tx_hexes, "hash")

    def test_get_transaction_json(self):
        tx_json = bci_fetchtx(self.tx_hashes[0], hexonly=False)
        self.assertEqual(tx_json, self.tx_jsons_bic[0])
        tx_json = blockcypher_fetchtx(self.tx_hashes[0], hexonly=False)
        self.assertEqual(tx_json, self.tx_jsons_bc[0])

    def test_get_multiple_transaction_json(self):
        tx_json = bci_fetchtx(self.tx_hashes, hexonly=False)
        self.assertUnorderedListEqual(tx_json, self.tx_jsons_bic, "hash")
        tx_json = blockcypher_fetchtx(self.tx_hashes, hexonly=False)
        self.assertUnorderedListEqual(tx_json, self.tx_jsons_bc, "hash")

class TestAddressHistory(unittest.TestCase):
    mainnet_address2 = "1MQmZKGjRLUMUb8piNXzY1QzAN4syArses"
    mainnet_address = "15PCVmcqCmtXPhBiNTrXc3SXU4hZw7FTJW"
    mainnet_history = [{'address': '15PCVmcqCmtXPhBiNTrXc3SXU4hZw7FTJW', 'value': 14922000,
                        'output': 'a03a455bf6b1bb02b2d245e0443bc0a9763f5a4c1cc010a990e85d9c54fade12:20',
                        'block_height': 465523,
                        'spend': 'e94f2de0db1a2c4d936d3ef0ebe088f4ab1ad9d2fdf7020ba10c98a35e0a615a:3'},
                       {'address': '15PCVmcqCmtXPhBiNTrXc3SXU4hZw7FTJW', 'value': 32570319,
                        'output': '76a61b5a879d176d6227edd266396bc21b03bde6a81c02f896b6ffe5a74d5b51:52',
                        'block_height': 465454,
                        'spend': 'e94f2de0db1a2c4d936d3ef0ebe088f4ab1ad9d2fdf7020ba10c98a35e0a615a:0'}]
    testnet_address = "myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW"
    testnet_history = [
            {'output': '056b4f3201fff0a3fac2e93af0278a0fc8f9c602b3f4a955b051b7b46253be99:0', 'value': 110000000}]
    testnet_address_multiple = ["mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu", "myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW"]
    testnet_history_multiple = [
        {'output': '307f1073011c14fb1c2d687706c18301fdafc985fb7da8e256536a179b3f8e95:0', 'value': 110000000},
        {'output': '056b4f3201fff0a3fac2e93af0278a0fc8f9c602b3f4a955b051b7b46253be99:0', 'value': 110000000}]

    def test_history_mainnet(self):
        txs = bci_history(self.mainnet_address)
        print(txs)
        self.assertListEqual(txs, self.mainnet_history)
        txs = blockcypher_history(self.mainnet_address)
        self.assertListEqual(txs, self.mainnet_history)
        txs = history(self.mainnet_address)
        self.assertListEqual(txs, self.mainnet_history)


    def test_history_testnet(self):
        self.assertRaises(Exception, bci_history, self.testnet_address)
        txs = blockcypher_history(self.testnet_address)
        self.assertDictEqual(txs, self.testnet_history)

    def test_history_testnet_multiple(self):
        self.assertRaises(Exception, bci_unspent, self.testnet_address_multiple)
        history = blockcypher_unspent(self.testnet_address_multiple)
        self.assertListEqual(history, self.testnet_history_multiple)

class MakeTransactionTests(unittest.TestCase):
    testnet_magicbyte = 111
    bc_testchain_magicbyte = 26
    bc_testchain_private_key = "d31432f5bedc4305f516165058b47b4ee18df20fa5447aad0d5158970573852d"
    bc_testchain_private_key2 = "18320636eb362527c90c7d6baa54fb04bb5d537cd94c499134868f3f3abc909d"
    bc_testchain_address = "BxQzEE8oBaoADSRZQiV2DKThnh6M9e2dHC"
    bc_testchain_address2 = "BtGgQwWz5esqjT4JVQrBMw3cRdd4k8GwXy"
    testnet_private_key = "cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk"
    testnet_address = "myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW"
    testnet_private_key_2 = "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f"
    testnet_address_2 = "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu"

    def test_testnet_transaction(self):
        unspents = unspent(self.testnet_address_2)
        pub1 = privtopub(self.testnet_private_key)
        addr1 = pubtoaddr(pub1, magicbyte=self.testnet_magicbyte)
        self.assertEqual(addr1, self.testnet_address)
        pub2 = privtopub(self.testnet_private_key_2)
        addr2 = pubtoaddr(pub2, magicbyte=self.testnet_magicbyte)
        self.assertEqual(addr2, self.testnet_address_2)
        unspents = unspent(addr1)
        value = 1100000
        if unspents and sum(o['value'] for o in unspents) > value:
            details = {
                'addr': addr1,
                'private_key': self.testnet_private_key,
                'unspents': unspents,
                'receiver': addr2,
            }
        else:
            unspents = unspent(addr2)
            if not unspents:
                raise Exception("No unspents found for testnet addresses")
            details = {
                'addr': addr2,
                'private_key': self.testnet_private_key_2,
                'unspents': unspents,
                'receiver': addr1
            }
        outs = [{'value': value, 'address': details['receiver']}]
        tx = mktx(details['unspents'], outs)
        for i in range(0, len(unspents)):
            tx = sign(tx,i,details['private_key'])
        response = blockcypher_decodetx(tx, network="bcy_test")
        pass
        response = blockcypher_pushtx(tx, network="bcy_test")
        pass


    def test_blockcypher_test(self):
        addr = self.bc_testchain_address
        addr2 = self.bc_testchain_address2
        unspents = unspent(addr, addr2)
        print(unspents)


if __name__ == '__main__':
    unittest.main()
