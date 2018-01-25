from .main import *
from .keystore import xpubkey_to_address

class HDWallet(object):

    def __init__(self, keystore, num_addresses=0, last_receiving_index=0, last_change_index=0):
        self.coin = keystore.coin
        self.keystore = keystore
        self.addresses = {}
        self.last_receiving_index = last_receiving_index
        self.last_change_index = last_change_index
        self.new_receiving_addresses(num=num_addresses)
        self.new_change_addresses(num=num_addresses)
        self.is_watching_only = self.keystore.is_watching_only()
        if self.keystore.electrum:
            self.script_type = self.keystore.xtype
        else:
            self.script_type = "p2pkh"

    def privkey(self, address, formt="wif_compressed", password=None):
        if self.is_watching_only:
            return
        try:
            addr_derivation = self.addresses[address]
        except KeyError:
            raise Exception(
                "Address %s has not been generated yet. Generate new addresses with new_receiving_addresses or new_change_addresses methods" % address)
        pk, compressed = self.keystore.get_private_key(addr_derivation, password)
        return self.coin.encode_privkey(pk, formt, script_type=self.script_type)

    def export_privkeys(self, password=None):
        if self.is_watching_only:
            return
        return {
            'receiving': {addr: self.privkey(addr, password=password) for addr in self.receiving_addresses},
            'change': {addr: self.privkey(addr, password=password) for addr in self.change_addresses}
        }

    def pubkey_receiving(self, index):
        return self.keystore.derive_pubkey(0, index)

    def pubkey_change(self, index):
        return self.keystore.derive_pubkey(1, index)

    def pubtoaddr(self, pubkey):
        if self.keystore.xtype == "p2pkh":
            return self.coin.pubtoaddr(pubkey)
        elif self.keystore.xtype == "p2wpkh":
            return self.coin.pubtosegwit(pubkey)
        elif self.keystore.xtype == "p2wpkh-p2sh":
            return self.coin.pubtop2w(pubkey)

    def receiving_address(self, index):
        pubkey = self.pubkey_receiving(index)
        address = self.pubtoaddr(pubkey)
        self.addresses[address] = (0, index)
        return address

    def change_address(self, index):
        pubkey = self.pubkey_change(index)
        address = self.pubtoaddr(pubkey)
        self.addresses[address] = (1, index)
        return address

    @property
    def receiving_addresses(self):
        return [addr for addr in self.addresses.keys() if not self.addresses[addr][0]]

    @property
    def change_addresses(self):
        return [addr for addr in self.addresses.keys() if self.addresses[addr][0]]

    def new_receiving_address_range(self, num):
        index = self.last_receiving_index
        return range(index, index+num)

    def new_change_address_range(self, num):
        index = self.last_change_index
        return range(index, index+num)

    def new_receiving_addresses(self, num=10):
        addresses = list(map(self.receiving_address, self.new_receiving_address_range(num)))
        self.last_receiving_index += num
        return addresses

    def new_change_addresses(self, num=10):
        addresses = list(map(self.change_address, self.new_change_address_range(num)))
        self.last_change_index += num
        return addresses

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

    def account(self, address, password=None):
        derivation = self.addresses[address][0]
        privkey = self.privkey(address, formt="wif_compressed", password=password)
        pub = self.coin.privtopub(privkey)
        derivation = "%s/%s'/%s" % (self.keystore.root_derivation, derivation[0], derivation[1])
        return (derivation, privkey, pub, address)

    def details(self, password=None):
        return {
            'type': "%s %s" % ("Electrum" if self.keystore.electrum else "BIP39", self.keystore.xtype),
            'xkeys': (self.keystore.root_derivation, self.keystore.xpriv, self.keystore.xpub),
            'xreceiving': (),
            'xchange': (),
            'receiving': [self.account(a, password=password) for a in self.receiving_addresses],
            'change': [self.account(a, password=password) for a in self.change_addresses]
        }