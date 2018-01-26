from .base import BaseCoin
from ..transaction import SIGHASH_ALL, SIGHASH_FORKID
from ..explorers import blockdozer
from ..main import b58check_to_bin
from ..py3specials import bin_to_b58check

FORKID_BTG = 79

class BitcoinGold(BaseCoin):
    coin_symbol = "bcc"
    display_name = "Bitcoin Gold"
    segwit_supported = True
    magicbyte = 38
    script_magicbyte = 23
    wif_prefix = 0x80
    hd_path = 0
    explorer = None
    hashcode = SIGHASH_ALL | SIGHASH_FORKID | FORKID_BTG << 8
    secondary_hashcode = SIGHASH_ALL | SIGHASH_FORKID
    segwit_hrp = "bc"
    testnet_overrides = {
        'display_name': "Bitcoin Gold Testnet",
        'coin_symbol': "tbcc",
        'magicbyte': 111,
        'script_magicbyte': 196,
        'wif_prefix': 0xef,
        'xprv_headers': {
            'p2pkh': 0x04358394,
            'p2wpkh-p2sh': 0x044a4e28,
            'p2wsh-p2sh': 0x295b005,
            'p2wpkh': 0x04358394,
            'p2wsh': 0x2aa7a99
        },
        'xpub_headers': {
            'p2pkh': 0x043587cf,
            'p2wpkh-p2sh': 0x044a5262,
            'p2wsh-p2sh': 0x295b43f,
            'p2wpkh': 0x043587cf,
            'p2wsh': 0x2aa7ed3
        },
        'hd_path': 1,
    }

    def __init__(self, testnet=False, legacy=False, **kwargs):
        super(BitcoinGold, self).__init__(testnet=testnet, **kwargs)
        if legacy and not testnet:
            self.magicbyte = 0
            self.script_magicbyte = 5

    def address_from_btc(self, addr):
        pubkey_hash = b58check_to_bin(addr)
        return bin_to_b58check(pubkey_hash, self.magicbyte)

    def sh_address_from_btc(self, addr):
        pubkey_hash = b58check_to_bin(addr)
        return bin_to_b58check(pubkey_hash, self.script_magicbyte)

    def unspent(self, *addrs):
        """
        Get unspent transactions for addresses
        """
        raise NotImplementedError("Explorer operations not supported for %s" % self.display_name)

    def history(self, *addrs, **kwargs):
        """
        Get transaction history for addresses
        """
        raise NotImplementedError("Explorer operations not supported for %s" % self.display_name)

    def fetchtx(self, tx):
        """
        Fetch a tx from the blockchain
        """
        raise NotImplementedError("Explorer operations not supported for %s" % self.display_name)

    def txinputs(self, tx):
        """
        Fetch inputs of a transaction on the blockchain
        """
        raise NotImplementedError("Explorer operations not supported for %s" % self.display_name)

    def pushtx(self, tx):
        """
        Push/ Broadcast a transaction to the blockchain
        """
        raise NotImplementedError("Explorer operations not supported for %s" % self.display_name)