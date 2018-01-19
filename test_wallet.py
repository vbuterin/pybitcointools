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


    def test_bip39_seed_bip44_standard_testnet(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        w = Bitcoin(testnet=True).wallet(seed_words)

        self.assertTrue(isinstance(w.keystore, keystore.BIP32_KeyStore))

        self.assertEqual(w.keystore.xprv, 'tprv8ge9CLX5ncJTveX12FSB4BFuuybSL5czL7csLyhEiWTAfqSuSHcdm9DkZTeHjmnRg5YA4tkMpGLqS5irHFUj8hG3USykMt99CjtK8dPKKXW')
        self.assertEqual(w.keystore.xpub, 'tpubDDLBLkZKvyz8p7Ynuu6mTav2V17NVQotuRDedVjY8nFZWKhg4gSDwdqcjbkwqyiMUrxXn4qcpkK2zrmS3nAViMN3iWkyai4VXz5vUJN7Qw8')

        self.assertEqual(w.keystore.xtype, 'p2pkh')

        self.assertEqual(w.new_receiving_address(), 'mxXZeGVPna3BhMKzFjee8ykZK5yN4F24ao')
        self.assertEqual(w.new_change_address(), 'mrzKXhWb8RcmpPAn5Rx4bFHsVShdaeaLm2')

        self.assertEqual(w.receiving_addresses, ['mxXZeGVPna3BhMKzFjee8ykZK5yN4F24ao'])
        self.assertEqual(w.change_addresses, ['mrzKXhWb8RcmpPAn5Rx4bFHsVShdaeaLm2'])

        self.assertEqual(w.new_receiving_addresses(2), ['mzmqnjPcfektxejUxSjiTAj5GW7Vt2QYtQ', 'mxrgiks6xVKRRiWpBqrQGoFiFY9y3QcFvq'])
        self.assertEqual(w.new_change_addresses(2), ['n2M9d3U6bfLvGxZr5MDs3MLN9fHxn4bgLB', 'mp7Seq8Gm1QAQnHdib1NS6pxU5AbNLfzk5'])

        self.assertEqual(w.receiving_address(100), "mgTxZQbaGif6Hsdj88D3vF7SqXP34mW7Y6")
        self.assertEqual(len(w.receiving_addresses), 4)
        self.assertEqual(len(w.change_addresses), 3)

        self.assertEqual(w.privkey('mxXZeGVPna3BhMKzFjee8ykZK5yN4F24ao', formt="wif_compressed"), "cQrA8q59oRha45Epvd5JeUPcVByCU1rqtK7pUeJZpecnJ97c7qQ9")
        self.assertEqual(w.privkey('mzmqnjPcfektxejUxSjiTAj5GW7Vt2QYtQ', formt="wif_compressed"), "cMx52abNoK83sjzNSFjiRRyiN2dhqE3eGXYUR61qjQBaguASWN8m")
        self.assertEqual(w.privkey('mxrgiks6xVKRRiWpBqrQGoFiFY9y3QcFvq', formt="wif_compressed"), "cRj3R3KMc4CQc2JzRgpNXz3a7wMrY7nb3a4awqvWfdHesKzQbgFT")
        self.assertEqual(w.privkey('mrzKXhWb8RcmpPAn5Rx4bFHsVShdaeaLm2', formt="wif_compressed"), "cNsv9jpFsW22rkUoL9XFqTMMeEf4rzGu9Xm3LptGXoyWcDkZnbuE")
        self.assertEqual(w.privkey('n2M9d3U6bfLvGxZr5MDs3MLN9fHxn4bgLB', formt="wif_compressed"), "cQJH9Q1ZCL3tEUWaQqtA9sgpUm2SJtUpQAxVatBSRTQ3GzXsUqJZ")
        self.assertEqual(w.privkey('mp7Seq8Gm1QAQnHdib1NS6pxU5AbNLfzk5', formt="wif_compressed"), "cU6PiMbhUzScnGpVW4WBTbXV4oqbUzmaTtP8QWwPunWKWaYSSg9E")
        self.assertEqual(w.privkey('mgTxZQbaGif6Hsdj88D3vF7SqXP34mW7Y6', formt="wif_compressed"), "cSup4gPigcwuDziBrAEhv6TxFFXg3kjXj8QVdLx34zX5v8ZcyZnK")


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

        self.assertEqual(w.new_receiving_addresses()[0], 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')
        self.assertEqual(w.new_change_addresses()[0], 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el')

    def test_electrum_multisig_seed_standard(self):
        seed_words = 'blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure'
        self.assertEqual(bitcoin.seed_type(seed_words), 'standard')

        ks1 = keystore.from_seed(seed_words, '', True)
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9s21ZrQH143K3t9vo23J3hajRbzvkRLJ6Y1zFrUFAfU3t8oooMPfb7f87cn5KntgqZs5nipZkCiBFo5ZtaSD2eDo7j7CMuFV8Zu6GYLTpY6')
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcGNEPu3aJQqXTydqR9t49Tkwb4Esrj112kw8xLthv8uybxvaki4Ygt9xiwZUQGeFTG7T2TUzR3eA4Zp3aq5RXsABHFBUrq4c')

        # electrum seed: ghost into match ivory badge robot record tackle radar elbow traffic loud
        ks2 = keystore.from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDbenT33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '32ji3QkAgXNz6oFoRfakyD3ys1XXiERQYN')
        self.assertEqual(w.get_change_addresses()[0], '36XWwEHrrVCLnhjK5MrVVGmUHghr9oWTN1')

    def test_electrum_multisig_seed_segwit(self):
        seed_words = 'snow nest raise royal more walk demise rotate smooth spirit canyon gun'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks1 = keystore.from_seed(seed_words, '', True)
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'ZprvAjxLRqPiDfPDxXrm8JvcoCGRAW6xUtktucG6AMtdzaEbTEJN8qcECvujfhtDU3jLJ9g3Dr3Gz5m1ypfMs8iSUh62gWyHZ73bYLRWyeHf6y4')
        self.assertEqual(ks1.xpub, 'Zpub6xwgqLvc42wXB1wEELTdALD9iXwStMUkGqBgxkJFYumaL2dWgNvUkjEDWyDFZD3fZuDWDzd1KQJ4NwVHS7hs6H6QkpNYSShfNiUZsgMdtNg')

        # electrum seed: hedgehog sunset update estate number jungle amount piano friend donate upper wool
        ks2 = keystore.from_xpub('Zpub6y4oYeETXAbzLNg45wcFDGwEG3vpgsyMJybiAfi2pJtNF3i3fJVxK2BeZJaw7VeKZm192QHvXP3uHDNpNmNDbQft9FiMzkKUhNXQafUMYUY')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)
        self.assertEqual(w.txin_type, 'p2wsh')

        self.assertEqual(w.get_receiving_addresses()[0], 'bc1qvzezdcv6vs5h45ugkavp896e0nde5c5lg5h0fwe2xyfhnpkxq6gq7pnwlc')
        self.assertEqual(w.get_change_addresses()[0], 'bc1qxqf840dqswcmu7a8v82fj6ej0msx08flvuy6kngr7axstjcaq6us9hrehd')

    def test_bip39_multisig_seed_bip45_standard(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks1 = keystore.from_bip39_seed(seed_words, '', "m/45'/0")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9vyEFyXf7pYVv4eDU3hhuCEAHPHNGuxX73nwtYdpbLcqwJCPwFKknAK8pHWuHHBirCzAPDZ7UJHrYdhLfn1NkGp9rk3rVz2aEqrT93qKRD9')
        self.assertEqual(ks1.xpub, 'xpub69xafV4YxC6o8Yiga5EiGLAtqR7rgNgNUGiYgw3S9g9pp6XYUne1KxdcfYtxwmA3eBrzMFuYcNQKfqsXCygCo4GxQFHfywxpUbKNfYvGJka')

        # bip39 seed: tray machine cook badge night page project uncover ritual toward person enact
        # der: m/45'/0
        ks2 = keystore.from_xpub('xpub6B26nSWddbWv7J3qQn9FbwPPQktSBdPQfLfHhRK4375QoZq8fvM8rQey1koGSTxC5xVoMzNMaBETMUmCqmXzjc8HyAbN7LqrvE4ovGRwNGg')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '3JPTQ2nitVxXBJ1yhMeDwH6q417UifE3bN')
        self.assertEqual(w.get_change_addresses()[0], '3FGyDuxgUDn2pSZe5xAJH1yUwSdhzDMyEE')

    def test_bip39_multisig_seed_p2sh_segwit(self):
        # bip39 seed: pulse mixture jazz invite dune enrich minor weapon mosquito flight fly vapor
        # der: m/49'/0'/0'
        # NOTE: there is currently no bip43 standard derivation path for p2wsh-p2sh
        ks1 = keystore.from_xprv('YprvAUXFReVvDjrPerocC3FxVH748sJUTvYjkAhtKop5VnnzVzMEHr1CHrYQKZwfJn1As3X4LYMav6upxd5nDiLb6SCjRZrBH76EFvyQAG4cn79')
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'Ypub6hWbqA2p47QgsLt5J4nxrR3ngu8xsPGb7PdV8CDh48KyNngNqPKSqertAqYhQ4umELu1UsZUCYfj9XPA6AdSMZWDZQobwF7EJ8uNrECaZg1')

        # bip39 seed: slab mixture skin evoke harsh tattoo rare crew sphere extend balcony frost
        # der: m/49'/0'/0'
        ks2 = keystore.from_xpub('Ypub6iNDhL4WWq5kFZcdFqHHwX4YTH4rYGp8xbndpRrY7WNZFFRfogSrL7wRTajmVHgR46AT1cqUG1mrcRd7h1WXwBsgX2QvT3zFbBCDiSDLkau')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)
        self.assertEqual(w.txin_type, 'p2wsh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '35LeC45QgCVeRor1tJD6LiDgPbybBXisns')
        self.assertEqual(w.get_change_addresses()[0], '39RhtDchc6igmx5tyoimhojFL1ZbQBrXa6')

if __name__ == '__main__':
    unittest.main()