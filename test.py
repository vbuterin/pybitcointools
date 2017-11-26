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
            x, y = random.randrange(2**256), random.randrange(2**256)
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
            seed = sha256(str(random.randrange(2**40)))[:32]
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
            priv = sha256(str(random.randrange(2**256)))
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
        privs = [sha256(str(random.randrange(2**256))) for x in range(4)]
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
            [[2**31],
             'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'],
            [[2**31, 1],
             'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'],
            [[2**31, 1, 2**31 + 2],
             'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'],
            [[2**31, 1, 2**31 + 2, 'pub', 2, 1000000000],
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
            [[2**31],
             'tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9'],
            [[2**31, 1],
             'tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q'],
            [[2**31, 1, 2**31 + 2],
             'tprv8gjmbDPpbAirVSezBEMuwSu1Ci9EpUJWKokZTYccSZSomNMLytWyLdtDNHRbucNaRJWWHANf9AzEdWVAqahfyRjVMKbNRhBmxAM8EJr7R15'],
            [[2**31, 1, 2**31 + 2, 'pub', 2, 1000000000],
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
                         2**31) == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        assert bip32_privtopub(bip32_ckd(master,
                                         2**31)) == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

        # m/1'
        assert bip32_ckd(master,
                         2**31 + 1) == "xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master,
                                         2**31 + 1)) == "xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        # m/1'
        assert bip32_ckd(master,
                         1 + 2**31) == "xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master,
                                         1 + 2**31)) == "xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        # m/0'/0
        assert bip32_ckd(bip32_ckd(master, 2**31),
                         "0") == "xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM1h3BoPuEJzsgeypdKj"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2**31),
                                         "0")) == "xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG"

        # m/0'/0'
        assert bip32_ckd(bip32_ckd(master, 2**31),
                         2**31) == "xprv9wTYmMFmpgaLB5Hge4YtaGqCKpsYPTD9vXWSsmdZrNU3Y2i4WoBykm6ZteeCLCCZpGxdHQuqEhM6Gdo2X6CVrQiTw6AAneF9WSkA9ewaxtS"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2**31),
                                         2**31)) == "xpub6ASuArnff48dPZN9k65twQmvsri2nuw1HkS3gA3BQi12Qq3D4LWEJZR3jwCAr1NhsFMcQcBkmevmub6SLP37bNq91SEShXtEGUbX3GhNaGk"

        # m/44'/0'/0'/0/0
        assert bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0),
                         0) == "xprvA4A9CuBXhdBtCaLxwrw64Jaran4n1rgzeS5mjH47Ds8V67uZS8tTkG8jV3BZi83QqYXPcN4v8EjK2Aof4YcEeqLt688mV57gF4j6QZWdP9U"
        assert bip32_privtopub(
            bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0),
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
    mainnet_address = "12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR"
    mainnet_unspent = [
        {'output': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f:1', 'value': 16336000000},
        {'output': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34:1', 'value': 5000000},
    ]
    mainnet_address_multiple = ["12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR", "1HuuxuHPxMvt9JfTc5LKDnbLYr5h9epfQS"]
    mainnet_unspent_multiple = [
        {'output': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f:1', 'value': 16336000000},
        {'output': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34:1', 'value': 5000000},
        {'output': '1bcb2f731b3a46898857b762b6a237e9221578cdc6d0144b1fd9ffe5ba5aa895:1', 'value': 18750000000}]
    testnet_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    testnet_unspent = [
            {'output': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c:0', 'value': 180000000}]

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

    def assertUnorderedListEqual(self, list1, list2, key):
        list1 = sorted(list1, key=itemgetter(key))
        list2 = sorted(list2, key=itemgetter(key))
        self.assertEqual(list1, list2)

    def test_unspent_mainnet(self):
        unspent_outputs = bci_unspent(self.mainnet_address)
        self.assertUnorderedListEqual(unspent_outputs, self.mainnet_unspent, 'output')
        unspent_outputs = blockcypher_unspent(self.mainnet_address)
        self.assertUnorderedListEqual(unspent_outputs, self.mainnet_unspent, 'output')
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

class TestBlockInfo(unittest.TestCase):
    minimum_last_block_height_main = 495929
    minimum_last_block_height_testnet = 1231684
    block_height = 294322
    mainnet_block_info = {
        'version': 2,
        'hash': "0000000000000000189bba3564a63772107b5673c940c16f12662b3e8546b412",
        'prevhash': "0000000000000000ced0958bd27720b71d32c5847e40660aaca39f33c298abb0",
        'timestamp': 1396684158,
        'merkle_root': "359d624d37aee1efa5662b7f5dbc390e996d561afc8148e8d716cf6ad765a952",
        'bits': 419486617,
        'nonce': 1225187768,
    }
    bc_mainnet_block_info = mainnet_block_info.copy()
    bc_mainnet_block_info['nonce'] = 0  #Blockcypher always returns a nonce of 0
    bc_mainnet_block_info['timestamp'] = '2014-04-05T07:49:18Z'
    testnet_block_info = {
        'version': 2,
        'hash': "00000000001be2d75acc520630a117874316c07fd7a724afae1a5d99038f4f4a",
        'prevhash': "000000000024f2b5690d852116dce43768c9c38922e94a5d7e848f7c2514e517",
        'timestamp': '2014-10-03T19:31:19Z',
        'merkle_root': "9c66b31403a26d737a7408d00d242fc99761d1c2cc9f2f3f205c79804f22848f",
        'bits': 457179072,
        'nonce': 0,
    }

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

    def test_block_header_data(self):
        block = bci_get_block_header_data(self.block_height)
        self.assertDictEqual(block, self.mainnet_block_info)
        block = blockcypher_get_block_header_data(self.block_height)
        self.assertDictEqual(block, self.bc_mainnet_block_info)
        block = blockcypher_get_block_header_data(self.block_height, network="testnet")
        self.assertDictEqual(block, self.testnet_block_info)


class TestFetchTransactions(unittest.TestCase):
    tx_hashes = ["7fe165ca88fb2439d6fd1002105a485bfccbb288f1f9c9fdcc33da8690d45981",
                 "7412e5e86e0f07d4dd818b0f6d4389c9f196c5715828c5092c0e5f5c67cc2687"]
    tx_hexes = [b'0100000001b082b343052ef7b5f71914a2a5d4063ee843e49db595919f1aeabcb4b006f76b010000006a473044022069daff9568e26cb85ef155eead74e1e1acf338a495a287c709e92ba75fe36ad102201fb9a8ea9a46fa7d0437b635bf7a25dd6c3aace214029e8fcbf48beaebb890cf012102187edfe5487df34118a8afb1b447e42cb75d9655d586a3578d5be89f5b2763dfffffffff0216d6d40a000000001976a9147d48ab93a39eeb9a5f3a5fe53a20efb533b6da6488ac6bf20000000000001976a9145f10a0434f1d4f5119a3d3f17ea44c35a947330f88ac00000000',
                b'0100000001d83ca497f91a9d6f75dd9c12ed2db1c54ae67f8113aea40536e055cbe722c846010000006a47304402206ab6fd2a107378f52437528a4802d5e40c1deb94b83f2ea07553eaf6f8339ccb02206b919b92b63721123e20c4e3c4cf9c37b041fae6ea2ef376b7c95a3c6537ba67012103542aa3891b2e2c3950ecbdbd10d1e8ce63a59682dcf6c5ff3a085649b9c3ef0affffffff01e00a0001000000001976a914d9c07c45043736caeed61bfaa9122301dfb248da88ac00000000']
    testnet_hash = "9683898a35fdfe8033fd4f1ef6ddf0dc3f20bf5813b05495421797ba861711b5"
    testnet_hex = b"0100000001cd9ac8bd3d454d5869abba0b9fb820b05d16ce7645334de28c39ef21025c263d000000006a47304402200403e11c283e39a727e6c0dc9531a8052341b97575d50443e48268e1681c5df302200d89802f0c2cf11e86fbb06a3072e8a0d72371c336512d2ae3a2c3de6d6bafbc0121038aa15d2666158670e1a752f07194817e75146c31cddd2b029e3657502604e132feffffff0280f0fa02000000001976a914f23096605eb5a5767ed88d487d732ec37bc768e688acc887bf04000000001976a91468a45d67b9ce61fd1bb880aa2f9353a10df5c61a88ac46cb1200"

    def assertUnorderedListEqual(self, list1, list2):
        list1 = sorted(list1)
        list2 = sorted(list2)
        self.assertEqual(list1, list2)

    def test_get_transaction_hex(self):
        tx_hex = bci_fetchtx(self.tx_hashes[0])
        self.assertEqual(tx_hex, self.tx_hexes[0])
        tx_hex = blockcypher_fetchtx(self.tx_hashes[0])
        self.assertEqual(tx_hex, self.tx_hexes[0])

    def test_get_transaction_hex_testnet(self):
        tx_hex = blockcypher_fetchtx(self.testnet_hash, network="testnet")
        self.assertEqual(tx_hex, self.testnet_hex)

    def test_get_multiple_transaction_hex(self):
        tx_hexes = bci_fetchtx(self.tx_hashes)
        self.assertUnorderedListEqual(tx_hexes, self.tx_hexes)
        tx_hex = blockcypher_fetchtx(self.tx_hashes)
        self.assertUnorderedListEqual(tx_hex, self.tx_hexes)

class MakeTransactionTests(unittest.TestCase):
    testnet_magicbyte = 111
    testnet_private_key = "cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk"
    testnet_address = "myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW"
    testnet_private_key_2 = "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f"
    testnet_address_2 = "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu"
    testnet_private_key_3 = "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"
    testnet_address_3 = "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"

    def test_testnet_transaction(self):
        pub1 = privtopub(self.testnet_private_key)
        addr1 = pubtoaddr(pub1, magicbyte=self.testnet_magicbyte)
        self.assertEqual(addr1, self.testnet_address)
        pub2 = privtopub(self.testnet_private_key_2)
        addr2 = pubtoaddr(pub2, magicbyte=self.testnet_magicbyte)
        self.assertEqual(addr2, self.testnet_address_2)
        pub3 = privtopub(self.testnet_private_key_3)
        addr3 = pubtoaddr(pub3, magicbyte=self.testnet_magicbyte)
        self.assertEqual(addr3, self.testnet_address_3)
        value = 1100000
        fee = 54400
        required_sats = value + fee

        #Find which of the 3 addresses currently has unspents with more than 1100000 value, and set transaction
        #paramaters accordingly

        unspents = unspent(addr1)
        unspent_value = sum(o['value'] for o in unspents)
        if unspents and unspent_value >= required_sats:
            details = {
                'sender': addr1,
                'private_key': self.testnet_private_key,
                'unspents': unspents,
                'receiver': addr2,
                'change_address': addr3
            }
        else:
            unspents = unspent(addr2)
            unspent_value = sum(o['value'] for o in unspents)
            if unspents and unspent_value >= required_sats:
                details = {
                    'sender': addr2,
                    'private_key': self.testnet_private_key_2,
                    'unspents': unspents,
                    'receiver': addr1,
                    'change_address': addr3
                }
            else:
                unspents = unspent(addr3)
                unspent_value = sum(o['value'] for o in unspents)
                if unspents and unspent_value >= required_sats:
                    details = {
                        'sender': addr3,
                        'private_key': self.testnet_private_key_3,
                        'unspents': unspents,
                        'receiver': addr2,
                        'change_address': addr1
                    }
                else:
                    raise Exception("Unspents with more than %s satoshis not found for any of of the 3 testnet addresses" % required_sats)

        change_value = unspent_value - required_sats
        outs = [{'value': value, 'address': details['receiver']}, {'value': change_value, 'address': details['change_address']}]

        tx = mktx(details['unspents'], outs)

        for i in range(0, len(unspents)):
            tx = sign(tx,i,details['private_key'])

        response = pushtx(tx, network="testnet")
        self.assertEqual(response.status_code, 201)

if __name__ == '__main__':
    unittest.main()
