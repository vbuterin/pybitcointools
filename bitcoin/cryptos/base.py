from ..transaction import SIGHASH_ALL


class BaseCoin(object):
    """
    Base implementation of crypto coin class
    All child coins must follow same pattern.
    """

    coin_symbol = None
    display_name = None
    magicbyte = None
    is_testnet = None
    hashcode = SIGHASH_ALL

    def __init__(self, testnet=False, **kwargs):
        self.is_testnet = testnet

        # override default attributes from kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)

    def privtopub(self, privkey):
        """
        Get public key from private key
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def pubtoaddr(self, pubkey):
        """
        Get address from a pubic key
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def privtoaddr(self, privkey):
        """
        Get address from a private key
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def sign(self, tx, i, privkey):
        """
        Sign a transaction with index using a private key
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def signall(self, tx, privkey):
        """
        Sign all transactions with index using a private key
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def unspent(self, *addrs, **kwargs):
        """
        Get unspent transactions for addresses
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def history(self, *addrs, **kwargs):
        """
        Get transaction history for addresses
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def pushtx(self, tx):
        """
        Push/ Broadcast a transaction to the blockchain
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def mktx(self, *args):
        """
        Make a transaction to the blockchain
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def send(self, privkey, to, value, fee=10000, **kwargs):
        """
        Send an amount from wallet.
        Requires private key, target address, value and fee
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def sendmultitx(self, privkey, *args, **kwargs):
        """
        Send multiple transactions/amounts at once
        Requires private key, address:value pairs and fee
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def preparetx(self, frm, to, value, fee=10000, **kwargs):
        """
        Prepare a transaction using from and to address, value and a fee
        """
        raise NotImplementedError("This method is not implemeted for this coin")

    def preparemultitx(self, frm, *args, **kwargs):
        """
        Prepare multiple transactions at once.
        Requires from address, to_address:value pairs and fees
        """
        raise NotImplementedError("This method is not implemeted for this coin")
