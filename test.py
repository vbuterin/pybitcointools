from unittest import skip
import datetime
from dateutil.tz import tzutc
import unittest
from bitcoin import explorers
import blockcypher
from operator import itemgetter
import bitcoin.ripemd as ripemd
from bitcoin import *
from bitcoin import cryptos


class TestECCArithmetic(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Starting ECC arithmetic tests')

    def test_all(self):
        for i in range(8):
            print('### Round %d' % (i+1))
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
        tx = mktx(['01'*32+':1', '23'*32+':2'], [msigaddr+':20202', addresses[0]+':40404'])
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
            [[], 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'],
            [['pub'], 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'],
            [[2**31], 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'],
            [[2**31, 1], 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'],
            [[2**31, 1, 2**31 + 2], 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'],
            [[2**31, 1, 2**31 + 2, 'pub', 2, 1000000000], 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy']
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
            [[], 'tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m'],
            [['pub'], 'tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp'],
            [[2**31], 'tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9'],
            [[2**31, 1], 'tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q'],
            [[2**31, 1, 2**31 + 2], 'tprv8gjmbDPpbAirVSezBEMuwSu1Ci9EpUJWKokZTYccSZSomNMLytWyLdtDNHRbucNaRJWWHANf9AzEdWVAqahfyRjVMKbNRhBmxAM8EJr7R15'],
            [[2**31, 1, 2**31 + 2, 'pub', 2, 1000000000], 'tpubDHNy3kAG39ThyiwwsgoKY4iRenXDRtce8qdCFJZXPMCJg5dsCUHayp84raLTpvyiNA9sXPob5rgqkKvkN8S7MMyXbnEhGJMW64Cf4vFAoaF']
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
        assert bip32_ckd(master, "0") == "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R"
        assert bip32_privtopub(bip32_ckd(master, "0")) == "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1"

        # m/1
        assert bip32_ckd(master, "1") == "xprv9uHRZZhbkedL4yTpidDvuVfrdUkTbhDHviERRBkbzbNDZeMjWzqzKAdxWhzftGDSxDmBdakjqHiZJbkwiaTEXJdjZAaAjMZEE3PMbMrPJih"
        assert bip32_privtopub(bip32_ckd(master, "1")) == "xpub68Gmy5EVb2BdHTYHpekwGdcbBWax19w9HwA2DaADYvuCSSgt4YAErxxSN1KWSnmyqkwRNbnTj3XiUBKmHeC8rTjLRPjSULcDKQQgfgJDppq"

        # m/0/0
        assert bip32_ckd(bip32_ckd(master, "0"), "0") == "xprv9ww7sMFLzJMzur2oEQDB642fbsMS4q6JRraMVTrM9bTWBq7NDS8ZpmsKVB4YF3mZecqax1fjnsPF19xnsJNfRp4RSyexacULXMKowSACTRc"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, "0"), "0")) == "xpub6AvUGrnEpfvJ8L7GLRkBTByQ9uBvUHp9o5VxHrFxhvzV4dSWkySpNaBoLR9FpbnwRmTa69yLHF3QfcaxbWT7gWdwws5k4dpmJvqpEuMWwnj"

        # m/0'
        assert bip32_ckd(master, 2**31) == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        assert bip32_privtopub(bip32_ckd(master, 2**31)) == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

        # m/1'
        assert bip32_ckd(master, 2**31 + 1) == "xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master, 2**31 + 1)) == "xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        # m/1'
        assert bip32_ckd(master, 1 + 2**31) == "xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master, 1 + 2**31)) == "xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        # m/0'/0
        assert bip32_ckd(bip32_ckd(master, 2**31), "0") == "xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM1h3BoPuEJzsgeypdKj"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2**31), "0")) == "xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG"

        # m/0'/0'
        assert bip32_ckd(bip32_ckd(master, 2**31), 2**31) == "xprv9wTYmMFmpgaLB5Hge4YtaGqCKpsYPTD9vXWSsmdZrNU3Y2i4WoBykm6ZteeCLCCZpGxdHQuqEhM6Gdo2X6CVrQiTw6AAneF9WSkA9ewaxtS"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2**31), 2**31)) == "xpub6ASuArnff48dPZN9k65twQmvsri2nuw1HkS3gA3BQi12Qq3D4LWEJZR3jwCAr1NhsFMcQcBkmevmub6SLP37bNq91SEShXtEGUbX3GhNaGk"

        # m/44'/0'/0'/0/0
        assert bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0), 0) == "xprvA4A9CuBXhdBtCaLxwrw64Jaran4n1rgzeS5mjH47Ds8V67uZS8tTkG8jV3BZi83QqYXPcN4v8EjK2Aof4YcEeqLt688mV57gF4j6QZWdP9U"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0), 0)) == "xpub6H9VcQiRXzkBR4RS3tU6RSXb8ouGRKQr1f1NXfTinCfTxvEhygCiJ4TDLHz1dyQ6d2Vz8Ne7eezkrViwaPo2ZMsNjVtFwvzsQXCDV6HJ3cV"


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

class BaseCoinCase(unittest.TestCase):
    name = ""
    unspent_address = ""
    unspent_address_multiple = []
    unspent = []
    unspent_multiple = []
    addresses = []
    privkeys = []
    txid = None
    tx = None
    txinputs = None
    fee = 0
    coin = cryptos.Bitcoin
    blockcypher_api_key = None
    blockcypher_coin_symbol = None
    testnet = True

    @classmethod
    def setUpClass(cls):
        print('Starting %s tests' % cls.name)

    def assertUnorderedListEqual(self, list1, list2, key):
        list1 = sorted(list1, key=itemgetter(key))
        list2 = sorted(list2, key=itemgetter(key))
        self.assertEqual(list1, list2)

    def assertUnspentOK(self):
        c = self.coin(testnet=self.testnet)
        unspent_outputs = c.unspent(self.unspent_address)
        self.assertUnorderedListEqual(unspent_outputs, self.unspent, 'output')

    def assertParseArgsOK(self):
        addr_args = explorers.blockcypher.parse_addr_args(self.unspent_address)
        self.assertListEqual(addr_args, [self.unspent_address])

        addr_args = explorers.blockcypher.parse_addr_args(*self.unspent_address_multiple)
        self.assertListEqual(addr_args, self.unspent_address_multiple)

        addr_args = explorers.blockcypher.parse_addr_args(self.unspent_address_multiple)
        self.assertListEqual(addr_args, self.unspent_address_multiple)

    def assertTransactionOK(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0
        unspents = []

        for i, addr in enumerate(self.addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i
                unspents = addr_unspents

        #For dash and doge testnet, unspents are returned empty, need to add manually
        if max_value == 0:
            print(self.addresses)
            from_addr_i = int(input("Which address? " ))
            sender = self.addresses[from_addr_i]
            input_tx = input("Enter txid for input unspent: ").strip()
            input_n = input("Enter tx n for input unspent: ").strip()
            max_value = int(input("Enter input value: ").strip())
            unspents = [{'output': "%s:%s" % (input_tx, input_n), 'value': max_value}]

        #Arbitrarily set send value, change value, receiver and change address
        outputs_value = max_value - self.fee
        send_value = int(outputs_value * 0.1)
        change_value = int(outputs_value - send_value)

        if sender == self.addresses[0]:
            receiver = self.addresses[1]
            change_address = self.addresses[1]
        elif sender == self.addresses[1]:
            receiver = self.addresses[2]
            change_address = self.addresses[0]
        else:
            receiver = self.addresses[0]
            change_address = self.addresses[1]

        outs = [{'value': send_value, 'address': receiver},
                {'value': change_value, 'address': change_address}]

        #Create the transaction using all available unspents as inputs
        tx = mktx(unspents, outs)

        #3rd party check that transaction is ok, not really necessary. Blockcypher requires an API key for this request
        if self.blockcypher_api_key:
            tx_decoded = self.decodetx(tx)

        #For testnets, private keys are already available. For live networks, private keys need to be entered manually at this point
        try:
            privkey = self.privkeys[from_addr_i]
        except IndexError:
            privkey = input("Enter private key for address %s: %s" % (from_addr_i, sender))

        #Verify that the private key belongs to the sender address for this network
        self.assertEqual(sender, c.privtoaddr(privkey), msg="Private key does not belong to address %s on %s" % (sender, c.display_name))

        #Sign each input with the given private key
        for i in range(0, len(unspents)):
            tx = c.sign(tx, i, privkey)

        #Check transaction format is still ok
        if self.blockcypher_api_key:
            signed_tx_decoded = self.decodetx(tx)

        #Push the transaction to the network
        print(tx)
        result = c.pushtx(tx)
        self.assertPushTxOK(result)

    def assertPushTxOK(self, result):
        #For chain.so. Override for other explorers.
        if isinstance(result, dict):
            try:
                self.assertEqual(result['status'], "success")
                print("Txid %s successfully broadcast on %s network" % (result['data']['txid'], result['data']['network']))
            except AssertionError:
                raise AssertionError("Push tx failed. Result: %s" % result)
            except KeyError:
                raise AssertionError("Push tx failed. Response: %s" % result)
        else:
            if not result.status_code == 200:
                raise AssertionError(result.text)

    def decodetx(self, tx):
        return blockcypher.decodetx(tx, coin_symbol=self.blockcypher_coin_symbol, api_key=self.blockcypher_api_key)

    def delete_key_by_name(self, obj, key):
        if isinstance(obj, dict):
            for k, v  in obj.items():
                if k == key:
                    del obj[k]
                    self.delete_key_by_name(obj, key)
                    break
                elif isinstance(v, (dict, list)):
                    self.delete_key_by_name(v, key)
        elif isinstance(obj, list):
            for i in obj:
                self.delete_key_by_name(i, key)

    def assertFetchTXOK(self):
        coin = self.coin(testnet=self.testnet)
        tx = coin.fetchtx(self.txid)
        self.delete_key_by_name(tx, "confirmations")
        self.delete_key_by_name(self.tx, "confirmations")
        self.assertDictEqual(tx, self.tx)

    def assertTXInputsOK(self):
        coin = self.coin(testnet=self.testnet)
        inputs = coin.txinputs(self.txid)
        self.assertUnorderedListEqual(inputs, self.txinputs, key="output")


class TestBitcoin(BaseCoinCase):
    name = "Bitcoin"
    coin = cryptos.Bitcoin
    addresses = ["1Ba7UmguphMX1g8ibyWQL62qzNu7mrXLVz", "16mBWqf9zefiZcKrKSf6uo3He9ipzPyuTb", "15pXUHkdBXFeUUetZJnJqNoD7dyCzaJFUn"]
    fee = 54400
    blockcypher_coin_symbol = "btc"
    testnet = False

    unspent_address = "12gK1NsNhzrRxs2kGKSjXhA1bhd8vyyWMR"
    unspent = [
        {'output': 'b489a0e8a99daad4d1a85992d9e373a87463a95109a5c56f4e4827f4e5a1af34:1', 'value': 5000000,
         'time': 'Wed Mar 23 23:38:20 2011'},
        {'output': 'f5e0c14b7d1f95d245d990ac6bb9ccf28d7f80f721f8133cd6ed34f9c8d13f0f:1', 'value': 16336000000,
         'time': 'Tue Apr  5 03:45:36 2011'}]
    txid = "fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690"
    txinputs = [{"output": "7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583:1", 'value': 1000000},
                {"output": "da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf:1", 'value': 100000}]
    tx = {'network': 'BTC', 'txid': 'fd3c66b9c981a3ccc40ae0f631f45286e7b31cf6d9afa1acaf8be1261f133690',
          'blockhash': '00000000000006b15ad1bd27555f9813137625bd24a3e5692c5a25ca74ad450a', 'confirmations': 365270,
          'time': 1310086870, 'inputs': [
            {'input_no': 0, 'value': '0.01000000', 'address': '1B55WSKjheXigBKTCyL4aQjKFmfaT6Ppev',
             'type': 'pubkeyhash',
             'script': '3045022076bf3b0edd6c9cdd35fb30d77d780f1d752e959242b2bbd58123617b8db350a6022100a602b91002b9c6c078a7513f72e1d7ccbfa3aa6f1261706b3110db00b1205ae401 04fafb576fcaf43a773ee1e34c5a76ab1f4fe1a7dc23256dd7a4525092537fc11686227d495dff710a291e7e9a6bf474a968158c56882b153e4b2e17bc584ec3cc',
             'from_output': {'txid': '7a905da948f1e174c43c6f41b0a0ee338119191de7b92bd1ca3c79f899e5d583',
                             'output_no': 1}},
            {'input_no': 1, 'value': '0.00100000', 'address': '19aoyNZJpszbV9QYK8eW3SnvXK31uHA9gw',
             'type': 'pubkeyhash',
             'script': '3046022100aecef1b98cf1cead7daadfb538c4808e71c9ef0c1ecec04af64fb1fdcffa7afb022100ec1070f8dea90f9ef6d86ebf251a63a01eae48ff840e0aacce899775b2dd16c601 04d2eeecdff2d0fd3d19f07928689f2aed33f1298f7493f2ca77b3607b545a8b2a91af48c27bc949da72f6ef38412c95bdcf6618486207bb92cd9aa75cae2c116d',
             'from_output': {'txid': 'da1ad82b777c51105d3a24cef253e0301dd08153115013a49e0edf69fd7cdadf',
                             'output_no': 1}}], 'outputs': [
            {'output_no': 0, 'value': '0.00100000', 'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
             'type': 'pubkeyhash',
             'script': 'OP_DUP OP_HASH160 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 OP_EQUALVERIFY OP_CHECKSIG'}],
          'tx_hex': '010000000283d5e599f8793ccad12bb9e71d19198133eea0b0416f3cc474e1f148a95d907a010000008b483045022076bf3b0edd6c9cdd35fb30d77d780f1d752e959242b2bbd58123617b8db350a6022100a602b91002b9c6c078a7513f72e1d7ccbfa3aa6f1261706b3110db00b1205ae4014104fafb576fcaf43a773ee1e34c5a76ab1f4fe1a7dc23256dd7a4525092537fc11686227d495dff710a291e7e9a6bf474a968158c56882b153e4b2e17bc584ec3ccffffffffdfda7cfd69df0e9ea41350115381d01d30e053f2ce243a5d10517c772bd81ada010000008c493046022100aecef1b98cf1cead7daadfb538c4808e71c9ef0c1ecec04af64fb1fdcffa7afb022100ec1070f8dea90f9ef6d86ebf251a63a01eae48ff840e0aacce899775b2dd16c6014104d2eeecdff2d0fd3d19f07928689f2aed33f1298f7493f2ca77b3607b545a8b2a91af48c27bc949da72f6ef38412c95bdcf6618486207bb92cd9aa75cae2c116dffffffff01a0860100000000001976a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac00000000',
          'size': 405, 'version': 1, 'locktime': 0}

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    @skip("very high fees")
    def test_transaction(self):
        self.assertTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()


class TestBitcoinTestnet(BaseCoinCase):
    name = "Bitcoin Testnet"
    coin = cryptos.Bitcoin
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu","mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = "btc-testnet"
    testnet = True

    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c:0', 'value': 180000000,
               'time': 'Sat Nov 25 16:52:50 2017'}]         #For verifying unspent data is correct
    txid = "1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c"
    txinputs = [{'output': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33:1', 'value': 190453372316}]
    tx = {'network': 'BTCTEST', 'txid': '1d69dd7a23f18d86f514ff7d8ef85894ad00c61fb29f3f7597e9834ac2569c8c',
          'blockhash': '00000000000ac694c157a56de45e2f985adefda11d3e2d7375905a03950852df', 'confirmations': 17636,
          'time': 1511628770, 'inputs': [
            {'input_no': 0, 'value': '1904.53372316', 'address': '2N82RUEC3Vw7phe3aHdtbYYSdHq7xWDFqMh',
             'type': 'scripthash', 'script': '0014ffe21a1b058e7f8dedfcc3f1526f82303cff4fc7',
             'from_output': {'txid': '1b8ae7a7a9629bbcbc13339bc29b258122c8d8670c54e6883d35c6a699e23a33',
                             'output_no': 1}}], 'outputs': [
            {'output_no': 0, 'value': '1.80000000', 'address': 'ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA',
             'type': 'pubkeyhash',
             'script': 'OP_DUP OP_HASH160 7e585aa1913cf12e9948e90f67188ee9250d5556 OP_EQUALVERIFY OP_CHECKSIG'},
            {'output_no': 1, 'value': '1902.73272316', 'address': '2NDrw9uodKHBZx9wB6kzqUBY5sAC1QCAdzL',
             'type': 'scripthash', 'script': 'OP_HASH160 e223701f10c2a5e7782ef6e10a2560f4c6e968a2 OP_EQUAL'}],
          'tx_hex': '01000000000101333ae299a6c6353d88e6540c67d8c82281259bc29b3313bcbc9b62a9a7e78a1b0100000017160014ffe21a1b058e7f8dedfcc3f1526f82303cff4fc7ffffffff020095ba0a000000001976a9147e585aa1913cf12e9948e90f67188ee9250d555688acfcb92b4d2c00000017a914e223701f10c2a5e7782ef6e10a2560f4c6e968a2870247304402207f2aa4118eee2ef231eab3afcbf6b01b4c1ca3672bd87a3864cf405741bd2c1d02202ab7502cbc50126f68cb2b366e5b3799d3ec0a3359c6a895a730a6891c7bcae10121023c13734016f27089393f9fc79736e4dca1f27725c68e720e1855202f3fbf037e00000000',
          'size': 249, 'version': 1, 'locktime': 0}

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_transaction(self):
        self.assertTransactionOK()

    def test_sendmultitx(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0

        for i, addr in enumerate(self.addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i

        privkey = self.privkeys[from_addr_i]

        #Arbitrarily set send value, change value, receiver and change address
        fee = self.fee * 0.1
        outputs_value = max_value - fee
        send_value1 = int(outputs_value * 0.1)
        send_value2 = int(outputs_value * 0.5)

        if sender == self.addresses[0]:
            receiver1 = self.addresses[1]
            receiver2 = self.addresses[2]
        elif sender == self.addresses[1]:
            receiver1 = self.addresses[2]
            receiver2 = self.addresses[0]
        else:
            receiver1 = self.addresses[0]
            receiver2 = self.addresses[1]

        result = c.sendmultitx(privkey, "%s:%s" % (receiver1, send_value1), "%s:%s" % (receiver2, send_value2), self.fee)
        self.assertPushTxOK(result)

    def test_send(self):

        c = self.coin(testnet=self.testnet)

        #Find which of the three addresses currently has the most coins and choose that as the sender
        max_value = 0
        sender = self.addresses[0]
        from_addr_i = 0

        for i, addr in enumerate(self.addresses):
            addr_unspents = c.unspent(addr)
            value = sum(o['value'] for o in addr_unspents)
            if value > max_value:
                max_value = value
                sender = addr
                from_addr_i = i

        privkey = self.privkeys[from_addr_i]

        #Arbitrarily set send value, change value, receiver and change address
        outputs_value = max_value - self.fee
        send_value = int(outputs_value * 0.1)

        if sender == self.addresses[0]:
            receiver = self.addresses[1]
        elif sender == self.addresses[1]:
            receiver = self.addresses[2]
        else:
            receiver = self.addresses[0]

        result = c.send(privkey, receiver, send_value, fee=self.fee)
        self.assertPushTxOK(result)

    def test_unspent(self):
        self.assertUnspentOK()


class TestLitecoinTestnet(BaseCoinCase):
    name = "Litecoin Testnet"
    coin = cryptos.Litecoin
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu", "mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000,
               'time': 'Wed Dec 20 14:21:21 2017'}]         #For verifying unspent data is correct

    txid = "2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93"
    txinputs = [{'output': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984:0', 'value': 17984768},
                {'output': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984:1', 'value': 161862912},
                {'output': 'f27a53b9433eeb9d011a8c77439edb7a582a01166756e00ea1076699bfa58371:1', 'value': 17941248}]
    tx = {'network': 'LTCTEST', 'txid': '2a288547460ebe410e98fe63a1900b6452d95ec318efb0d58a5584ac67f27d93',
          'blockhash': '9c557ffb695078e9f79d92b449fc0e61d82c331692258eb38495013aaf636218', 'confirmations': 1956,
          'time': 1513789292, 'inputs': [
            {'input_no': 0, 'value': '0.17984768', 'address': 'mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu',
             'type': 'pubkeyhash',
             'script': '3045022100c7081d2329334a78cde23359da1d9684d60b7fdb3e396c9d2633c419f9ad30ff022058e7cd031df6b7c7208b3140887e9ba012c81e4f300fcf388256f2636b0682e401 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
             'from_output': {'txid': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984',
                             'output_no': 0}},
            {'input_no': 1, 'value': '1.61862912', 'address': 'mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu',
             'type': 'pubkeyhash',
             'script': '304402207ceb8ca2179fc4ff975ebc3a95b6b1ddc5ce0c280203576d8a1d53948c7138ac02201157f68003220b7f6c3abc7756e7838e062b81ed511f6caff66aa1a73525efa301 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
             'from_output': {'txid': '83a32eb466e6a4600011b18cb4d7679f05bae8df40572a37b7c08e8849a7c984',
                             'output_no': 1}},
            {'input_no': 2, 'value': '0.17941248', 'address': 'mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu',
             'type': 'pubkeyhash',
             'script': '3045022100a95b8b36d08f944949b7fa2dca32f5e44e568339dcde11a8713e4676ed3bc77202204d117c91053b667714b1496583583bf8633b7fb189a800d08fdaaefd3f1ef49301 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
             'from_output': {'txid': 'f27a53b9433eeb9d011a8c77439edb7a582a01166756e00ea1076699bfa58371',
                             'output_no': 1}}], 'outputs': [
            {'output_no': 0, 'value': '0.19773452', 'address': 'mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6',
             'type': 'pubkeyhash',
             'script': 'OP_DUP OP_HASH160 42a3e11a80b25ff63b2074c51d1745132bccbba1 OP_EQUALVERIFY OP_CHECKSIG'},
            {'output_no': 1, 'value': '1.77961076', 'address': 'myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW',
             'type': 'pubkeyhash',
             'script': 'OP_DUP OP_HASH160 c384950342cb6f8df55175b48586838b03130fad OP_EQUALVERIFY OP_CHECKSIG'}],
          'tx_hex': '010000000384c9a749888ec0b7372a5740dfe8ba059f67d7b48cb1110060a4e666b42ea383000000006b483045022100c7081d2329334a78cde23359da1d9684d60b7fdb3e396c9d2633c419f9ad30ff022058e7cd031df6b7c7208b3140887e9ba012c81e4f300fcf388256f2636b0682e401210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff84c9a749888ec0b7372a5740dfe8ba059f67d7b48cb1110060a4e666b42ea383010000006a47304402207ceb8ca2179fc4ff975ebc3a95b6b1ddc5ce0c280203576d8a1d53948c7138ac02201157f68003220b7f6c3abc7756e7838e062b81ed511f6caff66aa1a73525efa301210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff7183a5bf996607a10ee0566716012a587adb9e43778c1a019deb3e43b9537af2010000006b483045022100a95b8b36d08f944949b7fa2dca32f5e44e568339dcde11a8713e4676ed3bc77202204d117c91053b667714b1496583583bf8633b7fb189a800d08fdaaefd3f1ef49301210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0ffffffff020cb82d01000000001976a91442a3e11a80b25ff63b2074c51d1745132bccbba188ac74789b0a000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000',
          'size': 521, 'version': 1, 'locktime': 0}

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_transaction(self):
        self.assertTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()

class TestDashTestnet(BaseCoinCase):
    name = "Dash Testnet"
    coin = cryptos.Dash
    addresses = ["ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz", "yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ", "ySPomQ35mpKiV89LDdAM3URFSibNiXEC4J"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "yV1AhJ3N3Dh4LeiN1ECYpWuLEgmfcA1y5G"
    unspent = [{'output': '546842058817fc29f18de4ba1f0aa5d45fa429c8716ea59d005f878af463ee6c:0', 'value': 29228600000,
               'time': 'Wed Dec 20 14:49:25 2017'}]         #For verifying unspent data is correct
    txid = "725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0"
    txinputs = [{'output': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777:0', 'value': 44907516684},
                {'output': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777:1', 'value': 4989724076}]
    tx = {'txid': '725ff2599700462905aafe658a082c0545c2749f779a7c9114421b4ca65183d0', 'size': 374, 'version': 1,
          'locktime': 0, 'vin': [{'txid': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777', 'vout': 1,
                                  'scriptSig': {
                                      'asm': '3045022100db69455ce4b093372d64dd599d8c1debe05d3ea0e1118a7f96b26c149456937402201db29f3e0b70b8aeb1f3eb9854137f0d8c907336e67ec75aa572d6e97b744f77[ALL] 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
                                      'hex': '483045022100db69455ce4b093372d64dd599d8c1debe05d3ea0e1118a7f96b26c149456937402201db29f3e0b70b8aeb1f3eb9854137f0d8c907336e67ec75aa572d6e97b744f7701210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0'},
                                  'value': 449.07516684, 'valueSat': 44907516684,
                                  'address': 'yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ', 'sequence': 4294967295, 'n': 0,
                                  'addr': 'yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ', 'doubleSpentTxID': None,
                                  'isConfirmed': True, 'confirmations': 723, 'unconfirmedInput': False},
                                 {'txid': 'f0b59a7a00ab906653271760922592eaa8c733e24c60115cf4c1981276fc2777', 'vout': 0,
                                  'scriptSig': {
                                      'asm': '3045022100cf26f366cabd5a065cca183b1f67f7d00f3537791cd3f293c184790517a8221502203070dae8ffc0cb59354fc5add0d8a4cd7b56586038eb30fabe9832cf1e6a522d[ALL] 0391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0',
                                      'hex': '483045022100cf26f366cabd5a065cca183b1f67f7d00f3537791cd3f293c184790517a8221502203070dae8ffc0cb59354fc5add0d8a4cd7b56586038eb30fabe9832cf1e6a522d01210391ed6bf1e0842997938ea2706480a7085b8bb253268fd12ea83a68509602b6e0'},
                                  'value': 49.89724076, 'valueSat': 4989724076,
                                  'address': 'yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ', 'sequence': 4294967295, 'n': 1,
                                  'addr': 'yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ', 'doubleSpentTxID': None,
                                  'isConfirmed': True, 'confirmations': 723, 'unconfirmedInput': False}], 'vout': [
            {'value': '449.07516684', 'valueSat': 44907516684, 'n': 0, 'scriptPubKey': {
                'asm': 'OP_DUP OP_HASH160 c384950342cb6f8df55175b48586838b03130fad OP_EQUALVERIFY OP_CHECKSIG',
                'hex': '76a914c384950342cb6f8df55175b48586838b03130fad88ac', 'reqSigs': 1, 'type': 'pubkeyhash',
                'addresses': ['ye9FSaGnHH5A2cjJ9s2y9XTgyJZefB5huz']},
             'spentTxId': '90267c69d35999b21efadd99cbc68e8c7a18da525146254500fe8118d4176cf0', 'spentIndex': 0,
             'spentHeight': 45567,
             'multipleSpentAttempts': [{'txid': '90267c69d35999b21efadd99cbc68e8c7a18da525146254500fe8118d4176cf0'},
                                       {'txid': '90267c69d35999b21efadd99cbc68e8c7a18da525146254500fe8118d4176cf0',
                                        'index': 0}]}, {'value': '49.89704076', 'valueSat': 4989704076, 'n': 1,
                                                        'scriptPubKey': {
                                                            'asm': 'OP_DUP OP_HASH160 4f19399fc1f1fc2f4c0c2c33cae4e9067e7893b8 OP_EQUALVERIFY OP_CHECKSIG',
                                                            'hex': '76a9144f19399fc1f1fc2f4c0c2c33cae4e9067e7893b888ac',
                                                            'reqSigs': 1, 'type': 'pubkeyhash',
                                                            'addresses': ['yTXgT2aA32Y35VQ6N9KpFqKJKKdbidgKeZ']}}],
          'blockhash': '00000000042772fe75e56decf162e39f5016450040a2953737e0bc7bd0475637', 'height': 45550,
          'confirmations': 488, 'time': 1513853163, 'blocktime': 1513853163, 'valueOut': 498.9722076,
          'valueIn': 498.9724076, 'fees': 0.0002}

    def test_unspent(self):
        self.assertUnspentOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_transaction(self):
        self.assertTransactionOK()

@skip("Explorer not working")
class TestDogeTestnet(BaseCoinCase):
    name = "Doge Testnet"
    coin = cryptos.Doge
    addresses = ['nn1xreE17QZVwuxxVY3N497SygcBPsm15j', 'nbQPs6XNsA2NzndkhpLDASy4Khg8ZfhUfj', 'naGXBTzJbwp4QRNzZJAjx651T6duZy2kgV']
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "ncst7MzasMBQFwx2LuCwj8Z6F4pCRppzBP"
    unspent = [{'output': '3f7a5460983cdfdf8118a1ab6bc84c28e536e83971532d4910c26bd21153de19:1', 'value': 100000000,
               'time': 'Thu Sep 13 07:22:50 2012'}]         #For verifying unspent data is correct

    def test_transaction(self):
        self.assertTransactionOK()

class TestBitcoinCash(TestBitcoin):
    name = "Bitcoin Cash"
    coin = cryptos.BitcoinCash
    addresses = ["1Ba7UmguphMX1g8ibyWQL62qzNu7mrXLVz", "16mBWqf9zefiZcKrKSf6uo3He9ipzPyuTb", "15pXUHkdBXFeUUetZJnJqNoD7dyCzaJFUn"]
    blockcypher_coin_symbol = "btc"
    fee = 54400
    testnet = False

    unspent_address = "1KomPE4JdF7P4tBzb12cyqbBfrVp4WYxNS"
    unspent = [
            {'output': 'e3ead2c8e6ad22b38f49abd5ae7a29105f0f64d19865fd8ccb0f8d5b2665f476:1', 'value': 249077026}]

    def test_parse_args(self):
        self.assertParseArgsOK()

    @skip("Signing not yet working for Bitcoin Cash")
    def test_transaction(self):
        self.assertTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()

class TestBitcoinCashTestnet(BaseCoinCase):
    name = "Bitcoin Cash Testnet"
    coin = cryptos.BitcoinCash
    addresses = ["myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW", "mnjBtsvoSo6dMvMaeyfaCCRV4hAF8WA2cu","mmbKDFPjBatJmZ6pWTW6yqXSC6826YLBX6"]
    privkeys = ["cUdNKzomacP2631fa5Q4yHv2fADc8Ueymr5Z5NUSJjVM13igcVJk",
                   "cMrziExc6iMV8vvAML8QX9hGDP8zNhcsKbdS9BqrRa1b4mhKvK6f",
                   "c396c62dfdc529645b822dc4eaa7b9ddc97dd8424de09ca19decce61e6732f71"]  #Private keys for above addresses in same order
    fee = 54400
    blockcypher_coin_symbol = None
    testnet = True

    unspent_address = "ms31HApa3jvv3crqvZ3sJj7tC5TCs61GSA"
    unspent = [{'output': '80700e6d1125deafa22b307f6c7c99e75771f9fc05517fc795a1344eca7c8472:0', 'value': 550000000}]         #For verifying unspent data is correct
    txid = "b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a"
    txinputs = [{'output': "cbd43131ee11bc9e05f36f55088ede26ab5fb160cc3ff11785ce9cc653aa414b:0", 'value': 96190578808}]
    tx = {'txid': 'b4dd5908cca851d861b9d2ca267a901bb6f581f2bb096fbf42a28cc2d98e866a', 'version': 1, 'locktime': 0,
          'vin': [{'txid': 'cbd43131ee11bc9e05f36f55088ede26ab5fb160cc3ff11785ce9cc653aa414b', 'vout': 1,
                   'sequence': 4294967295, 'n': 0, 'scriptSig': {
                  'hex': '483045022100b9050a1d58f36a771c4e0869900fb0474b809b134fdad566742e5b3a0ed7580d022065b80e9cc2bc9b921a9b0aad12228d9967345959b021214dbe60b3ffa44dbf0e412102ae83c12f8e2a686fb6ebb25a9ebe39fcd71d981cc6c172fedcdd042536a328f2',
                  'asm': '3045022100b9050a1d58f36a771c4e0869900fb0474b809b134fdad566742e5b3a0ed7580d022065b80e9cc2bc9b921a9b0aad12228d9967345959b021214dbe60b3ffa44dbf0e[ALL|FORKID] 02ae83c12f8e2a686fb6ebb25a9ebe39fcd71d981cc6c172fedcdd042536a328f2'},
                   'addr': 'mpEjdy5ZbKtU9ziXaK7LR75HirUsou5E1c', 'valueSat': 96190578808, 'value': 961.90578808,
                   'doubleSpentTxID': None}], 'vout': [{'value': '11.00000000', 'n': 0, 'scriptPubKey': {
            'hex': '76a914c384950342cb6f8df55175b48586838b03130fad88ac',
            'asm': 'OP_DUP OP_HASH160 c384950342cb6f8df55175b48586838b03130fad OP_EQUALVERIFY OP_CHECKSIG',
            'addresses': ['myLktRdRh3dkK3gnShNj5tZsig6J1oaaJW'], 'type': 'pubkeyhash'}, 'spentTxId': None,
                                                        'spentIndex': None, 'spentHeight': None},
                                                       {'value': '950.90478808', 'n': 1, 'scriptPubKey': {
                                                           'hex': '76a9143479daa7de5c6d8dad24535e648861d4e7e3f7e688ac',
                                                           'asm': 'OP_DUP OP_HASH160 3479daa7de5c6d8dad24535e648861d4e7e3f7e6 OP_EQUALVERIFY OP_CHECKSIG',
                                                           'addresses': ['mkJRQbswMT73HpbgqMLVRFRx4pp8iZpxbi'],
                                                           'type': 'pubkeyhash'}, 'spentTxId': None, 'spentIndex': None,
                                                        'spentHeight': None}],
          'blockhash': '000000002bab447cbd0c60829a80051e320aa6308d578db3369eb85b2ebb9f46', 'blockheight': 1196454,
          'time': 1513786390, 'blocktime': 1513786390, 'valueOut': 961.90478808, 'size': 226, 'valueIn': 961.90578808,
          'fees': 0.001}

    def test_fetchtx(self):
        self.assertFetchTXOK()

    def test_txinputs(self):
        self.assertTXInputsOK()

    def test_parse_args(self):
        self.assertParseArgsOK()

    def test_transaction(self):
        self.assertTransactionOK()

    def test_unspent(self):
        self.assertUnspentOK()

if __name__ == '__main__':
    unittest.main()
