from .main import *
from .transaction import select

class HDWallet(object):

    def __init__(self, keystore, transaction_history=None, num_addresses=0, last_receiving_index=0, last_change_index=0):
        self.coin = keystore.coin
        self.keystore = keystore
        self.address_derivations = {}
        self.last_receiving_index = last_receiving_index
        self.last_change_index = last_change_index
        self.new_receiving_addresses(num=num_addresses)
        self.new_change_addresses(num=num_addresses)
        self.is_watching_only = self.keystore.is_watching_only()
        self.transaction_history = transaction_history or []
        self.used_addresses = self.get_used_addresses()
        if self.keystore.electrum:
            self.script_type = self.keystore.xtype
        else:
            self.script_type = "p2pkh"

    def privkey(self, address, formt="wif_compressed", password=None):
        if self.is_watching_only:
            return
        try:
            addr_derivation = self.address_derivations[address]
        except KeyError:
            raise Exception(
                "Address %s has not been generated yet. Generate new address_derivations with new_receiving_addresses or new_change_addresses methods" % address)
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
        self.address_derivations[address] = (0, index)
        return address

    def change_address(self, index):
        pubkey = self.pubkey_change(index)
        address = self.pubtoaddr(pubkey)
        self.address_derivations[address] = (1, index)
        return address

    @property
    def addresses(self):
        return self.address_derivations.keys()

    @property
    def receiving_addresses(self):
        return [addr for addr in self.address_derivations.keys() if not self.address_derivations[addr][0]]

    @property
    def change_addresses(self):
        return [addr for addr in self.address_derivations.keys() if self.address_derivations[addr][0]]

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

    def get_balances(self):
        return self.coin.get_balance(*self.addresses)

    def balance(self):
        balances = self.get_balances()
        confirmed_balance = sum(b['confirmed'] for b in balances)
        unconfirmed_balance = sum(b['unconfirmed'] for b in balances)
        return {
            'total': confirmed_balance + unconfirmed_balance,
            'unconfirmed': unconfirmed_balance,
            'confirmed': confirmed_balance
        }

    def unspent(self, addresses=None, merkle_proof=False):
        addresses = addresses or self.addresses
        return self.coin.unspent(*addresses, merkle_proof=merkle_proof)

    def select_unspents(self, value, addresses=None, merkle_proof=False):
        unspents = self.unspent(addresses=addresses, merkle_proof=merkle_proof)
        return select(unspents, value)

    def history(self, addresses=None, merkle_proof=False):
        addresses = addresses or self.addresses
        return self.coin.history(*addresses, merkle_proof=merkle_proof)

    def get_used_addresses(self):
        return list(set([tx['addr'] for tx in self.transaction_history]))

    def synchronise(self):
        tx_hashes = [tx['tx_hash'] for tx in self.transaction_history]
        txs = self.history()
        new_txs = [tx for tx in txs if tx['tx_hash'] not in tx_hashes]
        self.transaction_history += self.coin.filter_by_proof(*new_txs)
        self.used_addresses = self.get_used_addresses()

    def sign(self, txobj, password=None):
        if self.is_watching_only:
            return
        pkeys_for = [inp['address'] for inp in txobj['ins']]
        privkeys = {address: self.privkey('address', password) for address in pkeys_for}
        return self.coin.signall(txobj, privkeys)

    def select_receive_address(self):
        try:
            return next(addr for addr in self.receiving_addresses if addr not in self.used_addresses)
        except StopIteration:
            return self.new_receiving_address()

    def select_change_address(self):
        try:
            return next(addr for addr in self.receiving_addresses if addr not in self.used_addresses)
        except StopIteration:
            return self.new_change_address()

    def pushtx(self, tx_hex):
        return self.coin.pushtx(tx_hex)

    def preparemultitx(self, outs, fee=50000, change_addr=None, addresses=None):
        change = change_addr or self.select_change_address()
        value = sum(out['value'] for out in outs) + fee
        ins = self.select_unspents(value, addresses=addresses)
        if self.coin.segwit_supported:
            if self.keystore.xtype == 'p2pkh':
                for i in ins:
                    i['segwit'] = False
                    i['new_segwit'] = False
            elif self.keystore.xtype == "p2wpkh-p2sh":
                for i in ins:
                    i['segwit'] = True
                    i['new_segwit'] = False
            elif self.keystore.xtype == 'p2wpkh':
                for i in ins:
                    i['segwit'] = True
                    i['new_segwit'] = True
        return self.coin.mksend(ins, outs, fee=fee, change=change)

    def preparetx(self, to, value, fee=50000, change_addr=None, addresses=None):
        outs = [{'address': to, 'value': value}]
        return self.preparemultitx(outs, fee=fee, change_addr=change_addr, addresses=addresses)

    def preparesignedtx(self, to, value, fee=50000, change_addr=None, addresses=addresses, password=None):
        txobj = self.preparetx(to, value, fee=fee, change_addr=change_addr, addresses=addresses)
        return self.sign(txobj, password=password)

    def preparesignedmultitx(self, outs, fee=50000, change_addr=None, addresses=None, password=None):
        txobj = self.preparemultitx(outs, fee=fee, change_addr=change_addr, addresses=addresses)
        return self.sign(txobj, password=password)

    def send(self, to, value, fee=50000, change_addr=None, addresses=None, password=None):
        tx = self.preparesignedtx(to, value, fee=fee, change_addr=change_addr, addresses=addresses, password=password)
        return self.pushtx(tx)

    def sendmultitx(self, outs, fee=50000, change_addr=None, addresses=None, password=None):
        tx = self.preparesignedmultitx(outs, fee=fee, change_addr=change_addr, addresses=addresses, password=password)
        return self.pushtx(tx)

    def is_mine(self, address):
        return address in self.address_derivations.keys()

    def is_change(self, address):
        return address in self.change_addresses

    def account(self, address, password=None):
        derivation = self.address_derivations[address][0]
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