from .main import *
from .transaction import select

class Wallet:
    def __init__(self, keystore, transaction_history=None):
        self.coin = keystore.coin
        self.keystore = keystore
        self.address_derivations = {}
        self.is_watching_only = self.keystore.is_watching_only()
        self.transaction_history = transaction_history or []
        self.xtype = self.keystore.xtype
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

    def receiving_address(self, index):
        pubkey = self.keystore.keypairs.keys()(index)
        address = self.pubtoaddr(pubkey)
        self.address_derivations[address] = pubkey
        return address

    def change_address(self, index):
        pubkey =  self.keystore.keypairs.keys()(index)
        address = self.pubtoaddr(pubkey)
        self.address_derivations[address] = pubkey
        return address

    def pubtoaddr(self, pubkey):
        if self.xtype == "p2pkh":
            return self.coin.pubtoaddr(pubkey)
        elif self.xtype == "p2wpkh":
            return self.coin.pubtosegwit(pubkey)
        elif self.xtype == "p2wpkh-p2sh":
            return self.coin.pubtop2w(pubkey)

    @property
    def addresses(self):
        return [self.pubtoaddr(pub) for pub in self.keystore.keypairs.keys()]

    @property
    def receiving_addresses(self):
        return self.addresses

    @property
    def change_addresses(self):
        return self.addresses

    def select_receive_address(self):
        return self.addresses[0]

    def select_change_address(self):
        return self.addresses[0]

    def new_receiving_address_range(self, num):
        return self.receiving_addresses[0]

    def new_change_address_range(self, num):
        return self.receiving_addresses[0]

    def new_receiving_addresses(self, num=10):
        return self.addresses

    def new_change_addresses(self, num=10):
        return self.addresses

    def new_receiving_address(self):
        return self.new_receiving_addresses(num=1)[0]

    def new_change_address(self):
        return self.new_change_addresses(num=1)[0]

    def is_mine(self, address):
        return address in self.addresses

    def is_change(self, address):
        return True

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

    def synchronise(self):
        tx_hashes = [tx['tx_hash'] for tx in self.transaction_history]
        txs = self.history()
        new_txs = [tx for tx in txs if tx['tx_hash'] not in tx_hashes]
        self.transaction_history += self.coin.filter_by_proof(*new_txs)

    def sign(self, txobj, password=None):
        if self.is_watching_only:
            return
        pkeys_for = [inp['address'] for inp in txobj['ins']]
        privkeys = {address: self.privkey('address', password) for address in pkeys_for}
        return self.coin.signall(txobj, privkeys)

    def pushtx(self, tx_hex):
        return self.coin.pushtx(tx_hex)

    def preparemultitx(self, outs, fee=50000, change_addr=None, fee_for_blocks=0, addresses=None):
        change = change_addr or self.select_change_address()
        value = sum(out['value'] for out in outs) + fee
        ins = self.select_unspents(value, addresses=addresses)
        if self.coin.segwit_supported:
            if self.xtype == 'p2pkh':
                for i in ins:
                    i['segwit'] = False
                    i['new_segwit'] = False
            elif self.xtype == "p2wpkh-p2sh":
                for i in ins:
                    i['segwit'] = True
                    i['new_segwit'] = False
            elif self.xtype == 'p2wpkh':
                for i in ins:
                    i['segwit'] = True
                    i['new_segwit'] = True
        return self.coin.mktx_with_change(ins, outs, fee=fee, fee_for_blocks=fee_for_blocks, change=change)

    def preparetx(self, to, value, fee=50000,  fee_for_blocks=0, change_addr=None, addresses=None):
        outs = [{'address': to, 'value': value}]
        return self.preparemultitx(outs, fee=fee, fee_for_blocks=fee_for_blocks, change_addr=change_addr,
                                   addresses=addresses)

    def preparesignedtx(self, to, value, fee=50000, fee_for_blocks=0, change_addr=None, addresses=addresses,
                        password=None):
        txobj = self.preparetx(to, value, fee=fee, fee_for_blocks=fee_for_blocks, change_addr=change_addr,
                               addresses=addresses)
        return self.sign(txobj, password=password)

    def preparesignedmultitx(self, outs, fee=50000, fee_for_blocks=0, change_addr=None, addresses=None, password=None):
        txobj = self.preparemultitx(outs, fee=fee, change_addr=change_addr, addresses=addresses,
                                    fee_for_blocks=fee_for_blocks)
        return self.sign(txobj, password=password)

    def send(self, to, value, fee=50000, fee_for_blocks=0, change_addr=None, addresses=None, password=None):
        tx = self.preparesignedtx(to, value, fee=fee, fee_for_blocks=fee_for_blocks, change_addr=change_addr,
                                  addresses=addresses, password=password)
        return self.pushtx(tx)

    def sendmultitx(self, outs, fee=50000, fee_for_blocks=0, change_addr=None, addresses=None, password=None):
        tx = self.preparesignedmultitx(outs, fee=fee, fee_for_blocks=fee_for_blocks, change_addr=change_addr,
                                       addresses=addresses, password=password)
        return self.pushtx(tx)

class HDWallet(Wallet):
    def __init__(self, keystore, transaction_history=None, num_addresses=0, last_receiving_index=0, last_change_index=0):
        super(HDWallet, self).__init__(keystore, transaction_history=transaction_history)
        self.last_receiving_index = last_receiving_index
        self.last_change_index = last_change_index
        self.new_receiving_addresses(num=num_addresses)
        self.new_change_addresses(num=num_addresses)
        self.used_addresses = self.get_used_addresses()
        self.xtype = self.keystore.xtype
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
        if self.xtype == "p2pkh":
            return self.coin.pubtoaddr(pubkey)
        elif self.xtype == "p2wpkh":
            return self.coin.pubtosegwit(pubkey)
        elif self.xtype == "p2wpkh-p2sh":
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

    def is_change(self, address):
        return address in self.change_addresses

    def get_used_addresses(self):
        return list(set([tx['addr'] for tx in self.transaction_history]))

    def synchronise(self):
        super(HDWallet, self).synchronise()
        self.used_addresses = self.get_used_addresses()

    def shift_frm_amount(self, coin, withdrawal_address, frm_amount, fee=50000, fee_for_blocks=1, password=None):
        """
        Shapeshift to another coin, setting the amount according to the amount to send with this coin
        coin is the symbol of the coin to receive
        withdrawal address is the address of the other coin to receive
        frm_amount is the amount to send from this wallet
        fee, fee_for_blocks: set an exact fee or estimate the fee based on how quickly to confirm the transaction
        """
        return_address = self.select_receive_address()
        data = self.coin.create_shift(coin, withdrawal_address, return_address)
        deposit_address = data['deposit']
        self.send(deposit_address, frm_amount, fee=fee, fee_for_blocks=fee_for_blocks, password=password)
        return self.coin.shapeshift.tx_status(deposit_address)

    def shift_to_amount(self, coin, withdrawal_address, receive_amount, fee=50000, fee_for_blocks=1):
        """
        Shapeshift to another coin, setting the amount to the amount of the other coin to receive
        withdrawal address is the address of the other coin to receive
        coin is the symbol of the coin to receive
        withdrawal address is the address of the other coin to receive
        receive_amount is the amount of the other coin to receive
        fee, fee_for_blocks: set an exact fee or estimate the fee based on how quickly to confirm the transaction
        """
        return_address = self.select_receive_address()
        data = self.coin.create_shift(coin, withdrawal_address, return_address, amount_to_receive=receive_amount)
        deposit_address = data['deposit']
        deposit_amount = data['depositAmount']
        self.send(deposit_address, deposit_amount, fee=fee, fee_for_blocks=fee_for_blocks)
        return self.coin.shapeshift.tx_status(deposit_address)