#Taken from Electrum source to ensure compatibility


import unittest
from cryptos import *
"""from lib import keystore
from lib import mnemonic
from lib import old_mnemonic
from lib.util import bh2u"""


class Test_NewMnemonic(unittest.TestCase):

    def test_to_seed(self):
        seed = mnemonic_to_seed("foobar", passphrase='none')
        self.assertEqual(safe_hexlify(seed),
                          '741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5b'
                          'b22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce')

    def test_random_seeds(self):
        iters = 10
        for _ in range(iters):
            seed = entropy_to_words(os.urandom(16))
            i = words_to_mnemonic_int(seed)
            self.assertEqual(mnemonic_int_to_words(i, 12), seed)

class Test_BIP39Checksum(unittest.TestCase):

    def test(self):
        mnemonic = u'gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog'
        is_wordlist_valid = words_verify(mnemonic)
        is_checksum_valid = wo
        self.assertTrue(is_wordlist_valid)
        self.assertTrue(is_checksum_valid)


if __name__ == '__main__':
    unittest.main()
