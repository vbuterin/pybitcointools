from .main import *
from .keystore import xpubkey_to_address

class HDWallet(object):
    def __init__(self, keystore, num_addresses=0):
        self.coin = keystore.coin
        self.keystore = keystore
        self.addresses = {}
        self.last_receiving_index = 0
        self.last_change_index = 0
        self.new_receiving_addresses(num=num_addresses)
        self.new_change_addresses(num=num_addresses)
        self.is_watching_only = self.keystore.is_watching_only()
        self.txin_type = 'p2pkh'

    def privkey(self, address, formt="wif", password=None):
        if self.is_watching_only:
            return
        try:
            addr_derivation = self.addresses[address]
        except KeyError:
            raise Exception("Address %s has not been generated yet. Generate new addresses with \
                            new_receiving_addresses or new_change_addresses methods" % address)
        pk, compressed = self.keystore.get_private_key(addr_derivation, password)
        return decode_privkey(pk, formt)

    def export_privkeys(self, password=None):
        if self.is_watching_only:
            return
        return {
            'receiving': {addr: self.privkey(addr, password=password) for addr in self.receiving_addresses},
            'change': {addr: self.privkey(addr, password=password) for addr in self.change_addresses}
        }

    def pubkey_receiving(self, index):
        return self.keystore.derive_pubkey(False, index)

    def pubkey_change(self, index):
        return self.keystore.derive_pubkey(True, index)

    def pubtoaddr(self, pubkey):
        return xpubkey_to_address(pubkey, coin=self.coin)[1]

    def receiving_address(self, index):
        pubkey = self.pubkey_receiving(index)
        address = self.pubtoaddr(pubkey)
        self.addresses[address] = (False, index)
        return address

    def change_address(self, index):
        pubkey = self.pubkey_change(index)
        address = self.pubtoaddr(pubkey)
        self.addresses[address] = (True, index)
        return address

    @property
    def receiving_addresses(self):
        return [addr for addr in self.addresses.keys() if not self.addresses[addr]['change']]

    @property
    def change_addresses(self):
        return [addr for addr in self.addresses.keys() if self.addresses[addr]['change']]

    def new_address_range(self, num):
        return range(self.last_receiving_index, self.last_receiving_index+num)

    def new_receiving_addresses(self, num=10):
        return list(map(self.receiving_address, self.new_address_range(num)))

    def new_change_addresses(self, num=10):
        return list(map(self.change_address, self.new_address_range(num)))

    def new_receiving_address(self):
        return self.new_receiving_addresses(num=1)[0]

    def new_change_address(self):
        return self.new_change_addresses(num=1)[0]

    def balance(self):
        raise NotImplementedError

    def unspent(self):
        raise NotImplementedError

    def select(self):
        raise NotImplementedError

    def history(self):
        raise NotImplementedError

    def sign(self, tx, password=None):
        if self.is_watching_only:
            return
        raise NotImplementedError

    def mksend(self, outs):
        raise NotImplementedError

    def sign_message(self, message, address, password=None):
        if self.is_watching_only:
            return
        raise NotImplementedError

    def is_mine(self, address):
        return address in self.addresses.keys()

    def is_change(self, address):
        return address in self.change_addresses