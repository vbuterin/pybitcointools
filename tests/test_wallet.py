import unittest
from unittest import mock

from cryptos import *


# TODO passphrase/seed_extension
class TestWalletKeystoreAddressIntegrity(unittest.TestCase):

    gap_limit = 1  # make tests run faster

    def _check_seeded_keystore_sanity(self, ks):
        self.assertTrue (ks.is_deterministic())
        self.assertFalse(ks.is_watching_only())
        self.assertFalse(ks.can_import())
        self.assertTrue (ks.has_seed())

    def _check_xpub_keystore_sanity(self, ks):
        self.assertTrue (ks.is_deterministic())
        self.assertTrue (ks.is_watching_only())
        self.assertFalse(ks.can_import())
        self.assertFalse(ks.has_seed())

    def _create_standard_wallet(self, seed, coin):
        w = coin.wallet(seed)
        return w

    def _create_multisig_wallet(self, ks1, ks2, ks3=None):
        """Creates a 2-of-2 or 2-of-3 multisig wallet."""
        store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
        store.put('x%d/' % 1, ks1.dump())
        store.put('x%d/' % 2, ks2.dump())
        if ks3 is None:
            multisig_type = "%dof%d" % (2, 2)
        else:
            multisig_type = "%dof%d" % (2, 3)
            store.put('x%d/' % 3, ks3.dump())
        store.put('wallet_type', multisig_type)
        store.put('gap_limit', self.gap_limit)
        w = wallet.Multisig_Wallet(store)
        w.synchronize()
        return w

    def test_electrum_seed_standard(self):
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        self.assertEqual(seed_type(seed_words), 'standard')

        w = Bitcoin().electrum_wallet(seed_words)

        self._check_seeded_keystore_sanity(w.keystore)
        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xtype, 'p2pkh')

        self.assertEqual(w.keystore.xprv, 'xprv9s21ZrQH143K32jECVM729vWgGq4mUDJCk1ozqAStTphzQtCTuoFmFafNoG1g55iCnBTXUzz3zWnDb5CVLGiFvmaZjuazHDL8a81cPQ8KL6')
        self.assertEqual(w.keystore.xpub, 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U')

        self.assertEqual(w.new_receiving_address(), '1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf')
        self.assertEqual(w.new_change_address(), '1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D')

        self.assertEqual(w.receiving_addresses, ['1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf'])
        self.assertEqual(w.change_addresses, ['1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D'])

        self.assertEqual(w.new_receiving_addresses(2), ['18KCZB4y7SKPmTGN2rDQuUsNxyVBX7CAbG', '15NuNdCwazxBd3y2MZin9qevuviA3pJe65'])
        self.assertEqual(w.new_change_addresses(2), ['1GSmpT2UWuELEMEv6GmoAYZwmUY1oFsypn', '1B6yGxiPdW8y8Zp8TLVSFV2jdKDiy3fDWv'])

        self.assertEqual(w.privkey('1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf', formt="wif_compressed"), "L4xstkeBfS6RbE6FezmKsHheFqktMMHQMsK7D1Hr5dvFbNhnekHM")
        self.assertEqual(w.privkey('1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D', formt="wif_compressed"), "L3eak2Wbw2MVgJBTcjZwNz7Ty6nw9YbDEbzAXpPxfUEfpLfXbVkA")
        self.assertEqual(w.privkey('18KCZB4y7SKPmTGN2rDQuUsNxyVBX7CAbG', formt="wif_compressed"), "KxERQEvau1865MuqPa1HdhKGMHAgsQJUq5XczC4rijEp7xj56hui")
        self.assertEqual(w.privkey('1GSmpT2UWuELEMEv6GmoAYZwmUY1oFsypn', formt="wif_compressed"), "L35MWQyAYLjURUPcSYvFnVj4KwxXXL1PKkqdnPwrfT95a5QtFMhv")
        self.assertEqual(w.privkey('15NuNdCwazxBd3y2MZin9qevuviA3pJe65', formt="wif_compressed"), "L46AzQn5yezvjNzgsNAPxZHCxm2rFXxDjrMzcnmBm1RJs4Gfp52P")
        self.assertEqual(w.privkey('1B6yGxiPdW8y8Zp8TLVSFV2jdKDiy3fDWv', formt="wif_compressed"), "L4miHgBAdGnpTdXi2psXN1TUoXNASfzrF7RGQqVfzbUgzV5vmfzJ")

    def test_electrum_seed_standard_watch(self):
        xpub = 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U'

        w = Bitcoin().watch_electrum_wallet(xpub)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))
        self.assertEqual(w.keystore.xtype, 'p2pkh')
        self.assertTrue(w.is_watching_only)

        self.assertEqual(w.new_receiving_address(), '1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf')
        self.assertEqual(w.new_change_address(), '1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D')

        self.assertEqual(w.receiving_addresses, ['1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf'])
        self.assertEqual(w.change_addresses, ['1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D'])

        self.assertEqual(w.new_receiving_addresses(2), ['18KCZB4y7SKPmTGN2rDQuUsNxyVBX7CAbG', '15NuNdCwazxBd3y2MZin9qevuviA3pJe65'])
        self.assertEqual(w.new_change_addresses(2), ['1GSmpT2UWuELEMEv6GmoAYZwmUY1oFsypn', '1B6yGxiPdW8y8Zp8TLVSFV2jdKDiy3fDWv'])

    def test_electrum_seed_standard_testnet(self):
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        self.assertEqual(seed_type(seed_words), 'standard')

        w = Bitcoin(testnet=True).electrum_wallet(seed_words)

        self._check_seeded_keystore_sanity(w.keystore)
        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xtype, 'p2pkh')

        self.assertEqual(w.keystore.xprv, 'xprv9s21ZrQH143K32jECVM729vWgGq4mUDJCk1ozqAStTphzQtCTuoFmFafNoG1g55iCnBTXUzz3zWnDb5CVLGiFvmaZjuazHDL8a81cPQ8KL6')
        self.assertEqual(w.keystore.xpub, 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U')

        self.assertEqual(w.new_receiving_address(), 'n2tiBwrzMwvXQwf7mxPUpqpNRwdyxwbNqT')
        self.assertEqual(w.new_change_address(), 'myxcHbSfyKnmcN56xjzghckzx95XfYa75v')

        self.assertEqual(w.receiving_addresses, ['n2tiBwrzMwvXQwf7mxPUpqpNRwdyxwbNqT'])
        self.assertEqual(w.change_addresses, ['myxcHbSfyKnmcN56xjzghckzx95XfYa75v'])

        self.assertEqual(w.new_receiving_addresses(2), ['mnq9rE9wvTkeYZjykRBnjQ5hpy5tQFS2VC', 'mjtrfgHvQ2PSQASe58h9yksFmvJrsmx3i7'])
        self.assertEqual(w.new_change_addresses(2), ['mvxj7W7TKvfb1TiXoqkAzTnGdU8ie5Rmrv', 'mqcva1oNSXaDugHkAuTp5QF4VJpRroBguF'])

        self.assertEqual(w.receiving_address(100), "moopS26mFMQdeyu8ycPQFXZS5mSYAbBT6r")

        self.assertEqual(w.privkey('n2tiBwrzMwvXQwf7mxPUpqpNRwdyxwbNqT', formt="wif_compressed"), "cVKsMfe36VngkfZX3QaTEcCht54J1oP6RuTaKRkMakaFr7hRcH9c")
        self.assertEqual(w.privkey('myxcHbSfyKnmcN56xjzghckzx95XfYa75v', formt="wif_compressed"), "cU1aCwWTN63kqjej19P4kJcXbL6LozguJe8deErUAatg55jcrjW4")
        self.assertEqual(w.privkey('mnq9rE9wvTkeYZjykRBnjQ5hpy5tQFS2VC', formt="wif_compressed"), "cNbQs9vSL4pMEoP6mypR11pKyWU6XrQAu7g66cXNDqtpNhqNqKzr")
        self.assertEqual(w.privkey('mjtrfgHvQ2PSQASe58h9yksFmvJrsmx3i7', formt="wif_compressed"), "cUTATKmwQihBtpTxFmyXKsnGazLFuz3uotWTjDDhG85K7oR9mKQs")
        self.assertEqual(w.privkey('mvxj7W7TKvfb1TiXoqkAzTnGdU8ie5Rmrv', formt="wif_compressed"), "cTSLyKy1yQRjaurspxjP9pE7xBFwBn75Pnz6tpQNAZo5ppZ2qPvs")
        self.assertEqual(w.privkey('mqcva1oNSXaDugHkAuTp5QF4VJpRroBguF', formt="wif_compressed"), "cV8hkbB24LV5d4zyREgejKxYRkfa786YK9ZjXFxBVi8hFE88Uqts")
        self.assertEqual(w.privkey('moopS26mFMQdeyu8ycPQFXZS5mSYAbBT6r', formt="wif_compressed"), "cRCMQHdaJeA15bvRuHkPqzk46uikwpuzPUtLkMcraUHnx98BVnFH")

    def test_electrum_seed_segwit(self):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(seed_type(seed_words), 'segwit')

        w = Bitcoin().electrum_wallet(seed_words)

        self._check_seeded_keystore_sanity(w.keystore)
        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xtype, 'p2wpkh')

        self.assertEqual(w.keystore.xprv, 'zprvAZswDvNeJeha8qZ8g7efN3FXYVJLaEUsE9TW6qXDEbVe74AZ75c2sZFZXPNFzxnhChDQ89oC8C5AjWwHmH1HeRKE1c4kKBQAmjUDdKDUZw2')
        self.assertEqual(w.keystore.xpub, 'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ')

        self.assertEqual(w.new_receiving_address(), 'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af')
        self.assertEqual(w.new_change_address(), 'bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p')

        self.assertEqual(w.receiving_addresses, ['bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af'])
        self.assertEqual(w.change_addresses, ['bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p'])

        self.assertEqual(w.new_receiving_addresses(2), ['bc1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nq604y2n', 'bc1qk8pyjanxrtv9039mz3muzjalfuk9r5xugm3803'])
        self.assertEqual(w.new_change_addresses(2), ['bc1q6xwxcw6m9ga35687tnu5tstmsvmzjwdnzktemv', 'bc1qgl92qp6haea2ktxe93umzsyhv9z8u32xtvk3qk'])

        self.assertEqual(w.receiving_address(100), "bc1ql6m8hpkst40p5g3fp6vkc69fysn8w9cpanuh09")

        self.assertEqual(w.privkey('bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af', formt="wif_compressed"), "L9fSXYNxYWHJWUqrQ6yhZCAJXq6XsfvcJ1Y2EnMAZfLLRNVQswQj")
        self.assertEqual(w.privkey('bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p', formt="wif_compressed"), "L8rPGyfyzdLLEzxuBeC87Jvpp8FKxwrRtmkZ2PkRmRjqxNF8TVwG")
        self.assertEqual(w.privkey('bc1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nq604y2n', formt="wif_compressed"), "LDSB7EmiqX25GkFpzJi7cnNBhpyrUaGLSJiqGu8oKJcH7q91dwaL")
        self.assertEqual(w.privkey('bc1qk8pyjanxrtv9039mz3muzjalfuk9r5xugm3803', formt="wif_compressed"), "LD8dYgymFBKz2mju2KsaKHe2AuisXCTSgaiRkHaVbrzuUsNkA24U")
        self.assertEqual(w.privkey('bc1q6xwxcw6m9ga35687tnu5tstmsvmzjwdnzktemv', formt="wif_compressed"), "L7NeR6r9yU2n4zddxTCUpKYmzugYuouyLsCZR9naTqkBW6sjpxDM")
        self.assertEqual(w.privkey('bc1qgl92qp6haea2ktxe93umzsyhv9z8u32xtvk3qk', formt="wif_compressed"), "L6mxN5yrGMdbVFM7ihxFMUi7fsj9gmC3GFqsCa2an25SKdyqpUyR")
        self.assertEqual(w.privkey('bc1ql6m8hpkst40p5g3fp6vkc69fysn8w9cpanuh09', formt="wif_compressed"), "LAc21LGaLeN8bfAFwGHUFqPbu1cazb53ycaHWRBykrpwoVf5ZC3N")

    def test_electrum_seed_segwit_watch(self):
        xpub = 'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ'

        w = Bitcoin().watch_electrum_p2wpkh_wallet(xpub)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))
        self.assertEqual(w.keystore.xtype, 'p2wpkh')
        self.assertTrue(w.is_watching_only)

        self.assertEqual(w.new_receiving_address(), 'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af')
        self.assertEqual(w.new_change_address(), 'bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p')

        self.assertEqual(w.receiving_addresses, ['bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af'])
        self.assertEqual(w.change_addresses, ['bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p'])

        self.assertEqual(w.new_receiving_addresses(2), ['bc1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nq604y2n', 'bc1qk8pyjanxrtv9039mz3muzjalfuk9r5xugm3803'])
        self.assertEqual(w.new_change_addresses(2), ['bc1q6xwxcw6m9ga35687tnu5tstmsvmzjwdnzktemv', 'bc1qgl92qp6haea2ktxe93umzsyhv9z8u32xtvk3qk'])

        self.assertEqual(w.receiving_address(100), "bc1ql6m8hpkst40p5g3fp6vkc69fysn8w9cpanuh09")

    def test_electrum_seed_segwit_testnet(self):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(seed_type(seed_words), 'segwit')

        w = Bitcoin(testnet=True).electrum_wallet(seed_words)

        self._check_seeded_keystore_sanity(w.keystore)
        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xtype, 'p2wpkh')

        self.assertEqual(w.keystore.xprv, 'zprvAZswDvNeJeha8qZ8g7efN3FXYVJLaEUsE9TW6qXDEbVe74AZ75c2sZFZXPNFzxnhChDQ89oC8C5AjWwHmH1HeRKE1c4kKBQAmjUDdKDUZw2')
        self.assertEqual(w.keystore.xpub, 'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ')

        self.assertEqual(w.new_receiving_address(), 'tb1q3g5tmkmlvxryhh843v4dz026avatc0zzfuvzx6')
        self.assertEqual(w.new_change_address(), 'tb1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzjncg43j')

        self.assertEqual(w.receiving_addresses, ['tb1q3g5tmkmlvxryhh843v4dz026avatc0zzfuvzx6'])
        self.assertEqual(w.change_addresses, ['tb1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzjncg43j'])

        self.assertEqual(w.new_receiving_addresses(2), ['tb1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nqsfwh3q', 'tb1qk8pyjanxrtv9039mz3muzjalfuk9r5xuza255z'])
        self.assertEqual(w.new_change_addresses(2), ['tb1q6xwxcw6m9ga35687tnu5tstmsvmzjwdngss2ql', 'tb1qgl92qp6haea2ktxe93umzsyhv9z8u32xp2dzm9'])

        self.assertEqual(w.receiving_address(100), "tb1ql6m8hpkst40p5g3fp6vkc69fysn8w9cph48y5k")

        self.assertEqual(w.privkey('tb1q3g5tmkmlvxryhh843v4dz026avatc0zzfuvzx6', formt="wif_compressed"), "ca2RzTNoyZyZfvK7nWnpvWfNA4PwY82JN3gVMCog4mzLg7ZXqxBk")
        self.assertEqual(w.privkey('tb1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nqsfwh3q', formt="wif_compressed"), "cdoAa9maGaiLSBj6NiXEz6sFL4HG92N2WLsJPKbJpRGHNaGEA4UC")
        self.assertEqual(w.privkey('tb1qk8pyjanxrtv9039mz3muzjalfuk9r5xuza255z', formt="wif_compressed"), "cdVd1bycgF2FCDDAQjghgc95o92HBeZ8kcrtri316yeujcQTpjK1")
        self.assertEqual(w.privkey('tb1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzjncg43j', formt="wif_compressed"), "cZDNjtfqRh2bQSSAa41FUdRtSMYjdPx7xou28pCwGYPrD7NVebpU")
        self.assertEqual(w.privkey('tb1q6xwxcw6m9ga35687tnu5tstmsvmzjwdngss2ql', formt="wif_compressed"), "cXjdt1r1QXj3ES6uLs1cBe3qd8yxaG1fQuM2XaF5xxQBkr1FMkLc")
        self.assertEqual(w.privkey('tb1qgl92qp6haea2ktxe93umzsyhv9z8u32xp2dzm9', formt="wif_compressed"), "cX8wpzyhhRKregpP77mNioDBJ72ZMDHjLHzLJzV6H8jSaP5JETEF")
        self.assertEqual(w.privkey('tb1ql6m8hpkst40p5g3fp6vkc69fysn8w9cph48y5k', formt="wif_compressed"), "cay1UFGRmi4Pm6dXKg6bd9tfXEuzf3Ak3eikcqeVFyUx4EpkNrzL")


    def test_bip39_seed_bip44_standard(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        w = Bitcoin().wallet(seed_words)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xprv, 'xprv9zGLcNEb3cHUKizLVBz6RYeE9bEZAVPjH2pD1DEzCnPcsemWc3d3xTao8sfhfUmDLMq6e3RcEMEvJG1Et8dvfL8DV4h7mwm9J6AJsW9WXQD')
        self.assertEqual(w.keystore.xpub, 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJWFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLdvdbjv')

        self.assertEqual(w.keystore.xtype, 'p2pkh')

        self.assertEqual(w.new_receiving_address(), '16j7Dqk3Z9DdTdBtHcCVLaNQy9MTgywUUo')
        self.assertEqual(w.new_change_address(), '1GG5bVeWgAp5XW7JLCphse14QaC4qiHyWn')

        self.assertEqual(w.receiving_addresses, ['16j7Dqk3Z9DdTdBtHcCVLaNQy9MTgywUUo'])
        self.assertEqual(w.change_addresses, ['1GG5bVeWgAp5XW7JLCphse14QaC4qiHyWn'])

        self.assertEqual(w.new_receiving_addresses(2), ['1K9UsDbEEe2SfKUMTh8B7ZPyYLHeB3f2j7', '1DpbsAw25KyyKwG6oGPCZBPJK7WnL2bKZ9'])
        self.assertEqual(w.new_change_addresses(2), ['15D5w9aZQpcmGfKoQrrVMHRYGdDzyFDkre', '17ABdZyMVWfU2tZEZWUAXPMsD8wTgcbmum'])

        self.assertEqual(w.receiving_address(100), "14TUbjfoT4EKjdyjjUpP3LSBjXMGf87K2Q")

        self.assertEqual(w.privkey('16j7Dqk3Z9DdTdBtHcCVLaNQy9MTgywUUo', formt="wif_compressed"), "L422visYK6FZnmxowLYEof4ty8FvqEUS7YJuNi6Y2hWUqRuDt3qK")
        self.assertEqual(w.privkey('1K9UsDbEEe2SfKUMTh8B7ZPyYLHeB3f2j7', formt="wif_compressed"), "L1HdAazBSe52DxsHv8tXwS1gPAMEXmCXPrUQRTCqd34naS6d28Mk")
        self.assertEqual(w.privkey('1DpbsAw25KyyKwG6oGPCZBPJK7WnL2bKZ9', formt="wif_compressed"), "Kz9fHKgCQdYBgmHSFBMZmgAWUV7zkx6VvUUhS7LuxHaAZXkiG59v")
        self.assertEqual(w.privkey('1GG5bVeWgAp5XW7JLCphse14QaC4qiHyWn', formt="wif_compressed"), "KxzBNXidRYKuwyeZmHPikUsN4eVXP4agnqbcXToQkMb5sBSahsL3")
        self.assertEqual(w.privkey('15D5w9aZQpcmGfKoQrrVMHRYGdDzyFDkre', formt="wif_compressed"), "L59fod5uqjBgouaUMyTdq5Nt8Dho5xeZvxCuZLF8V77zXb7pLSMC")
        self.assertEqual(w.privkey('17ABdZyMVWfU2tZEZWUAXPMsD8wTgcbmum', formt="wif_compressed"), "L4EyTu44oxXpVynitaUQ9Uf7Sw3EoYEGs1GFXaxb6KQATViskWZP")
        self.assertEqual(w.privkey('14TUbjfoT4EKjdyjjUpP3LSBjXMGf87K2Q', formt="wif_compressed"), "L3n4ZyY1YWV8Kyyn8HbRZNgRoyucUJKyFsbdvjNX7vWr5iRfsyoY")

    def test_bip39_seed_bip44_standard_watch(self):
        xpub = 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJWFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLdvdbjv'

        w = Bitcoin().watch_wallet(xpub)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xtype, 'p2pkh')
        self.assertTrue(w.is_watching_only)

        self.assertEqual(w.new_receiving_address(), '16j7Dqk3Z9DdTdBtHcCVLaNQy9MTgywUUo')
        self.assertEqual(w.new_change_address(), '1GG5bVeWgAp5XW7JLCphse14QaC4qiHyWn')

        self.assertEqual(w.receiving_addresses, ['16j7Dqk3Z9DdTdBtHcCVLaNQy9MTgywUUo'])
        self.assertEqual(w.change_addresses, ['1GG5bVeWgAp5XW7JLCphse14QaC4qiHyWn'])

        self.assertEqual(w.new_receiving_addresses(2), ['1K9UsDbEEe2SfKUMTh8B7ZPyYLHeB3f2j7', '1DpbsAw25KyyKwG6oGPCZBPJK7WnL2bKZ9'])
        self.assertEqual(w.new_change_addresses(2), ['15D5w9aZQpcmGfKoQrrVMHRYGdDzyFDkre', '17ABdZyMVWfU2tZEZWUAXPMsD8wTgcbmum'])

        self.assertEqual(w.receiving_address(100), "14TUbjfoT4EKjdyjjUpP3LSBjXMGf87K2Q")


    def test_bip39_seed_bip49_p2sh_segwit(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        w = Bitcoin().p2wpkh_p2sh_wallet(seed_words)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xprv, 'yprvAJEYHeNEPcyBoQYM7sGCxDiNCTX65u4ANgZuSGTrKN5YCC9MP84SBayrgaMyZV7zvkHrr3HVPTK853s2SPk4EttPazBZBmz6QfDkXeE8Zr7')
        self.assertEqual(w.keystore.xpub, 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbLz9niQ4')

        self.assertEqual(w.keystore.xtype, 'p2wpkh-p2sh')

        self.assertEqual(w.new_receiving_address(), '35ohQTdNykjkF1Mn9nAVEFjupyAtsPAK1W')
        self.assertEqual(w.new_change_address(), '3KaBTcviBLEJajTEMstsA2GWjYoPzPK7Y7')

        self.assertEqual(w.receiving_addresses, ['35ohQTdNykjkF1Mn9nAVEFjupyAtsPAK1W'])
        self.assertEqual(w.change_addresses, ['3KaBTcviBLEJajTEMstsA2GWjYoPzPK7Y7'])

        self.assertEqual(w.new_receiving_addresses(2),
                         ['3DitVjWr2LKgPwadXuEd3QXX76BNJXstzj', '3GMNcTdXjJEzkUrv3QaPn7iBCmVoLH3tV8'])
        self.assertEqual(w.new_change_addresses(2),
                         ['3KaBA2yTSn8e1F9LTT731Jr4cZXfVVGD37', '32s2nRytkeABETk2wGs7rez68LjPrNo8u5'])

        self.assertEqual(w.receiving_address(100), "3CSGipmQKSevBFjfQmbqS2n1kedD1FfoXo")
        self.assertEqual(len(w.receiving_addresses), 4)
        self.assertEqual(len(w.change_addresses), 3)

        self.assertEqual(w.privkey('35ohQTdNykjkF1Mn9nAVEFjupyAtsPAK1W', formt="wif_compressed"),
                         "KyUdS5eoaKr7hhXgUnyTk6nyYZGArzSFy49xc32TsuYLAiAtDTzB")
        self.assertEqual(w.privkey('3DitVjWr2LKgPwadXuEd3QXX76BNJXstzj', formt="wif_compressed"),
                         "L5VccEBER99XTkEg1xtpCHaigfjjiH6DzGsJccnyY7eSaSJd85Yv")
        self.assertEqual(w.privkey('3GMNcTdXjJEzkUrv3QaPn7iBCmVoLH3tV8', formt="wif_compressed"),
                         "KwnEbt7APPfwnm378RDX99wTfxqbSY1SYYK6hiAZd1emuA5Q9Tna")
        self.assertEqual(w.privkey('3CSGipmQKSevBFjfQmbqS2n1kedD1FfoXo', formt="wif_compressed"),
                         "KxFZTZwLxiqkBkBqyxZ8CLz2ZEwVawX6jzAtnh5zvVW2YNTuKZnu")
        self.assertEqual(w.privkey('3KaBTcviBLEJajTEMstsA2GWjYoPzPK7Y7', formt="wif_compressed"),
                         "L4N6uquY9mPxc3HxwPVSFYekFpbmqMXwAdbYQNi9awJrJQ4cms8g")
        self.assertEqual(w.privkey('3KaBA2yTSn8e1F9LTT731Jr4cZXfVVGD37', formt="wif_compressed"),
                         "Kzb58wjceypSETV4CHqJr5a1fiWKZ4xhvAAQr4ZGmHwgZdHFuqW3")
        self.assertEqual(w.privkey('32s2nRytkeABETk2wGs7rez68LjPrNo8u5', formt="wif_compressed"),
                         "L5E56T1ZH1gZGVxqJZ5QexhM5KD55TRK5kaTmA9XhigKxwrSJvwD")

    def test_bip39_seed_bip49_p2sh_segwit_watch(self):
        xpub = 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbLz9niQ4'

        w = Bitcoin().watch_p2wpkh_p2sh_wallet(xpub)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xtype, 'p2wpkh-p2sh')
        self.assertTrue(w.is_watching_only)


        self.assertEqual(w.new_receiving_address(), '35ohQTdNykjkF1Mn9nAVEFjupyAtsPAK1W')
        self.assertEqual(w.new_change_address(), '3KaBTcviBLEJajTEMstsA2GWjYoPzPK7Y7')

        self.assertEqual(w.receiving_addresses, ['35ohQTdNykjkF1Mn9nAVEFjupyAtsPAK1W'])
        self.assertEqual(w.change_addresses, ['3KaBTcviBLEJajTEMstsA2GWjYoPzPK7Y7'])

        self.assertEqual(w.new_receiving_addresses(2),
                         ['3DitVjWr2LKgPwadXuEd3QXX76BNJXstzj', '3GMNcTdXjJEzkUrv3QaPn7iBCmVoLH3tV8'])
        self.assertEqual(w.new_change_addresses(2),
                         ['3KaBA2yTSn8e1F9LTT731Jr4cZXfVVGD37', '32s2nRytkeABETk2wGs7rez68LjPrNo8u5'])

        self.assertEqual(w.receiving_address(100), "3CSGipmQKSevBFjfQmbqS2n1kedD1FfoXo")
        self.assertEqual(len(w.receiving_addresses), 4)
        self.assertEqual(len(w.change_addresses), 3)

    def test_bip39_seed_bip49_p2sh_segwit_testnet(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        w = Bitcoin(testnet=True).p2wpkh_p2sh_wallet(seed_words)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xprv, 'uprv91cL9abSyRBCUSy1raBjwuWYcpB9f21B3KgCtbvhjYpRMv6d1zMmRSTChtv76Kx84tzktSwpfKXGtxDM9rSEVq1m2g1dz2PJHeiiukzTVzB')
        self.assertEqual(w.keystore.xpub, 'upub5EbgZ68LonjVgw3UxbikK3THAr1e4Uj2QYbogzLKHtMQEiRmZXg1yEmgZALF6dFJKtf7t35eE1vcwiUPeujmhSG7pGz5fYAjgD5nTELevk8')

        self.assertEqual(w.keystore.xtype, 'p2wpkh-p2sh')

        self.assertEqual(w.new_receiving_address(), '2NCUmWfaix7dgepJzpHBa3NqHLVTrZbYn5A')
        self.assertEqual(w.new_change_address(), '2NFbJUWbARWN83L18U6JG5HAjp2Lp4A738w')

        self.assertEqual(w.receiving_addresses, ['2NCUmWfaix7dgepJzpHBa3NqHLVTrZbYn5A'])
        self.assertEqual(w.change_addresses, ['2NFbJUWbARWN83L18U6JG5HAjp2Lp4A738w'])

        self.assertEqual(w.new_receiving_addresses(2),
                         ['2N8P2d23LRUrUGhjmFDHJkELchowAWx8oCP', '2Mt48CJ669Mge4n1nDQbhypoSeKAfhMcMME'])
        self.assertEqual(w.new_change_addresses(2),
                         ['2N52CRv9DQN9jP6mqrEJYh2aHSpzdqCDkT2', '2N8AnS2Z83hMarLbkxfxNqgcFyqb8d93jXz'])

        self.assertEqual(w.receiving_address(100), "2NBZCTLMuxJzTT8KYusrAJuKX7uX7Rrn3yb")
        self.assertEqual(len(w.receiving_addresses), 4)
        self.assertEqual(len(w.change_addresses), 3)

        self.assertEqual(w.privkey('2NCUmWfaix7dgepJzpHBa3NqHLVTrZbYn5A', formt="wif_compressed"),
                         "cPtnJoaMd9i9Bu8n25CvzjzjarCcQovkBfY6MpNmP4pAbjzqXVd5")
        self.assertEqual(w.privkey('2N8P2d23LRUrUGhjmFDHJkELchowAWx8oCP', formt="wif_compressed"),
                         "cUZjQvXZ4ytNVtdnVmVHum4afTGP9Z13XaN4TtFeXVrWEyQMskTg")
        self.assertEqual(w.privkey('2Mt48CJ669Mge4n1nDQbhypoSeKAfhMcMME', formt="wif_compressed"),
                         "cVpKjSsujCYy599X9PEsa1t6gzKDM5KSJ1jq5jSPNKff4yaxjAAm")
        self.assertEqual(w.privkey('2NFbJUWbARWN83L18U6JG5HAjp2Lp4A738w', formt="wif_compressed"),
                         "cQzyrNGXvTkbkwKzMoAxUbcHozZtQXfNspMwbQoP9M3cs5S5YCFd")
        self.assertEqual(w.privkey('2NFbJUWbARWN83L18U6JG5HAjp2Lp4A738w', formt="wif_compressed"),
                         "cQzyrNGXvTkbkwKzMoAxUbcHozZtQXfNspMwbQoP9M3cs5S5YCFd")
        self.assertEqual(w.privkey('2N52CRv9DQN9jP6mqrEJYh2aHSpzdqCDkT2', formt="wif_compressed"),
                         "cQkmYkrwMpWo1koPykJ6LbLFtLmGN7P4SJkoFPdGvto3VzMmb7ZK")
        self.assertEqual(w.privkey('2N8AnS2Z83hMarLbkxfxNqgcFyqb8d93jXz', formt="wif_compressed"),
                         "cUyRoiviymD8b4MFkW9NB7tJ8o5FmVtrDGRo7syPT4FKSBDH3ME5")

    def test_bip39_seed_bip84_native_segwit(self):
        seed_words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        w = Bitcoin().p2wpkh_wallet(seed_words)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xprv, 'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE')
        self.assertEqual(w.keystore.xpub, 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs')

        self.assertEqual(w.keystore.xtype, 'p2wpkh')

        self.assertEqual(w.new_receiving_address(), 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')
        self.assertEqual(w.new_change_address(), 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el')

        self.assertEqual(w.receiving_addresses, ['bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'])
        self.assertEqual(w.change_addresses, ['bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el'])

        self.assertEqual(w.new_receiving_addresses(2),
                         ['bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g', 'bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z'])
        self.assertEqual(w.new_change_addresses(2),
                         ['bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf', 'bc1qn8alfh45rlsj44pcdt0f2cadtztgnz4gq3h3uf'])

        self.assertEqual(w.receiving_address(100), "bc1q2m7xsl8hf256as3s6e0pvcgz5n5a0de4ey30rl")
        self.assertEqual(len(w.receiving_addresses), 4)
        self.assertEqual(len(w.change_addresses), 3)

        self.assertEqual(w.privkey('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', formt="wif_compressed"),
                         "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d")
        self.assertEqual(w.privkey('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g', formt="wif_compressed"),
                         "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy")
        self.assertEqual(w.privkey('bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z', formt="wif_compressed"),
                         "L1WWMekCNikUJwrkmxqXWafFu3gmzJ777WpPGgz5Y1o7U11hrDDs")
        self.assertEqual(w.privkey('bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el', formt="wif_compressed"),
                         "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF")
        self.assertEqual(w.privkey('bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf', formt="wif_compressed"),
                         "KyDKM6os4SNpyCN79CGaZF91vVtzmnragXN7A3qAxVvFDws9jBqh")
        self.assertEqual(w.privkey('bc1qn8alfh45rlsj44pcdt0f2cadtztgnz4gq3h3uf', formt="wif_compressed"),
                         "KwQ1irwXPWRmfEH7CtyiFSA2dZ8TCrczAa7onpr3yNEEPrxGmnfS")
        self.assertEqual(w.privkey('bc1q2m7xsl8hf256as3s6e0pvcgz5n5a0de4ey30rl', formt="wif_compressed"),
                         "L2MQjNV27qN6eZy3msVu6KQw8iHzSGMwoNZV7SH9uL5mCnpLcxxw")

    def test_bip39_seed_bip84_native_segwit_watch(self):
        xpub = 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs'

        w = Bitcoin().watch_p2wpkh_wallet(xpub)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xtype, 'p2wpkh')
        self.assertTrue(w.is_watching_only)

        self.assertEqual(w.new_receiving_address(), 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')
        self.assertEqual(w.new_change_address(), 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el')

        self.assertEqual(w.receiving_addresses, ['bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'])
        self.assertEqual(w.change_addresses, ['bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el'])

        self.assertEqual(w.new_receiving_addresses(2),
                         ['bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g', 'bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z'])
        self.assertEqual(w.new_change_addresses(2),
                         ['bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf', 'bc1qn8alfh45rlsj44pcdt0f2cadtztgnz4gq3h3uf'])

        self.assertEqual(w.receiving_address(100), "bc1q2m7xsl8hf256as3s6e0pvcgz5n5a0de4ey30rl")
        self.assertEqual(len(w.receiving_addresses), 4)
        self.assertEqual(len(w.change_addresses), 3)

    def test_bip39_seed_bip84_native_segwit_testnet(self):
        seed_words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        w = Bitcoin(testnet=True).p2wpkh_wallet(seed_words)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xprv,
                         'tprv8fSjiqEQ8YG7Ro7gw2ScwcvweYuuWi1ZzGUtrPz918HvDtBzL5s2voFTrN4y3yUwj5cYD54pLhxk6NKCzHUjcka3zbKjbTEcsuAnkzbjhkL')
        self.assertEqual(w.keystore.xpub,
                         'tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M')

        self.assertEqual(w.keystore.xtype, 'p2wpkh')

        self.assertEqual(w.new_receiving_address(), 'tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl')
        self.assertEqual(w.new_change_address(), 'tb1q9u62588spffmq4dzjxsr5l297znf3z6j5p2688')

        self.assertEqual(w.receiving_addresses, ['tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl'])
        self.assertEqual(w.change_addresses, ['tb1q9u62588spffmq4dzjxsr5l297znf3z6j5p2688'])

        self.assertEqual(w.new_receiving_addresses(2),
                         ['tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97', 'tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct'])
        self.assertEqual(w.new_change_addresses(2),
                         ['tb1qkwgskuzmmwwvqajnyr7yp9hgvh5y45kg8wvdmd', 'tb1q2vma00td2g9llw8hwa8ny3r774rtt7aenfn5zu'])

        self.assertEqual(w.receiving_address(100), "tb1q0gzpnp4yhr20p7tqdrqmm7872w0unmawzka9zu")
        self.assertEqual(len(w.receiving_addresses), 4)
        self.assertEqual(len(w.change_addresses), 3)

        self.assertEqual(w.privkey('tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl', formt="wif_compressed"),
                         "cTGhosGriPpuGA586jemcuH9pE9spwUmneMBmYYzrQEbY92DJrbo")
        self.assertEqual(w.privkey('tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97', formt="wif_compressed"),
                         "cQFUndrpAyMaE3HAsjMCXiT94MzfsABCREat1x7Qe3Mtq9KihD4V")
        self.assertEqual(w.privkey('tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct', formt="wif_compressed"),
                         "cRe5KDj3rcZJAtZVmWe3G2rdGdXyKCjVbWBVDXqSg2WHq1qq6MNe")
        self.assertEqual(w.privkey('tb1q9u62588spffmq4dzjxsr5l297znf3z6j5p2688', formt="wif_compressed"),
                         "cQ5TcujvBuw5bZfEVJmXZw5Ac1mQ6ryAjHeDrJcmn6oDyhfva5by")
        self.assertEqual(w.privkey('tb1qkwgskuzmmwwvqajnyr7yp9hgvh5y45kg8wvdmd', formt="wif_compressed"),
                         "cVg4cGUL42Kf2XVPC5Uqa7ggsqqWHsKjnZgU6f7nARFoYCVxzh2Y")
        self.assertEqual(w.privkey('tb1q2vma00td2g9llw8hwa8ny3r774rtt7aenfn5zu', formt="wif_compressed"),
                         "cMqRXWvu4JoYcPHMEEJAA48XfmNaf77DH4Tyc9UdbGgKLLEiEqW9")
        self.assertEqual(w.privkey('tb1q0gzpnp4yhr20p7tqdrqmm7872w0unmawzka9zu', formt="wif_compressed"),
                         "cRkgP842XmEK8yr8uDA8QD5kXfBtoTyhjtvGkQTLeXPyZdFWUr2v")


if __name__ == '__main__':
    unittest.main()