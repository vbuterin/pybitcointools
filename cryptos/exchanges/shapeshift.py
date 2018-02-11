#!/usr/bin/python
#Modified version of https://github.com/abitfan/shapeshiftio

import requests


class ShapeShiftIO:
    def __init__(self, api_key=None):
        """
        https://shapeshift.io/api
        """
        self.baseurl = "https://shapeshift.io"
        self.api_key = api_key

    def get_request(self, url):
        response = requests.get(url)
        return response.json()

    def post_request(self, url, postdata):
        response = requests.post(postdata)
        return response.json()

    def rate(self, frm, to):
        """
        Gets the current rate offered by Shapeshift. This is an estimate because the rate can occasionally change
        rapidly depending on the markets. The rate is also a 'use-able' rate not a direct market rate.
        Meaning multiplying your input coin amount times the rate should give you a close approximation of what will
        be sent out. This rate does not include the transaction (miner) fee taken off every transaction.
        [pair] is any valid coin pair such as btc_ltc or ltc_btc
        Success Output:
            {
                "pair" : "btc_ltc",
                "rate" : "70.1234"
            }
        """
        pair = "%s_%s" % (frm, to)
        self.url = self.baseurl + "/rate/" + pair
        return self.get_request(self.url)

    def limit(self, frm, to):
        """
        Gets the current deposit limit set by Shapeshift. Amounts deposited over this limit will be sent to the return address if one was entered, otherwise the user will need to contact ShapeShift support to retrieve their coins. This is an estimate because a sudden market swing could move the limit.
        [pair] is any valid coin pair such as btc_ltc or ltc_btc
        Success Output:
            {
                "pair" : "btc_ltc",
                "limit" : "1.2345"
            }
        """
        pair = "%s_%s" % (frm, to)
        self.url = self.baseurl + "/limit/" + pair
        return self.get_request(self.url)

    def market_info(self, frm, to):
        """
        This gets the market info (pair, rate, limit, minimum limit, miner fee)
        [pair] (OPTIONAL) is any valid coin pair such as btc_ltc or ltc_btc.
        The pair is not required and if not specified will return an array of all market infos.
        Success Output:
        {
            "pair"     : "btc_ltc",
            "rate"     : 130.12345678,
            "limit"    : 1.2345,
            "min"      : 0.02621232,
            "minerFee" : 0.0001
            }
        """
        pair = "%s_%s" % (frm, to)
        self.url = self.baseurl + "/marketinfo/" + pair
        return self.get_request(self.url)

    def recent_tx(self, max_results=5):
        """
        Get a list of the most recent transactions.
        [max] is an optional maximum number of transactions to return.
        If [max] is not specified this will return 5 transactions.
        Also, [max] must be a number between 1 and 50 (inclusive).
        Success Output:
            [
                {
                     curIn : [currency input],
                     curOut: [currency output],
                     amount: [amount],
                     timestamp: [time stamp]     //in seconds
                },
                ...
             ]
        """
        self.url = self.baseurl + "/recenttx/" + str(max_results)
        return self.get_request(self.url)

    def tx_status(self, address):
        """
        This returns the status of the most recent deposit transaction to the address.
        [address] is the deposit address to look up.

        Success Output:  (various depending on status)

        Status: No Deposits Received
            {
                status:"no_deposits",
                address:[address]           //matches address submitted
            }

        Status: Received (we see a new deposit but have not finished processing it)
            {
                status:"received",
                address:[address]           //matches address submitted
            }

        Status: Complete
            {
                status : "complete",
                address: [address],
                withdraw: [withdrawal address],
                incomingCoin: [amount deposited],
                incomingType: [coin type of deposit],
                outgoingCoin: [amount sent to withdrawal address],
                outgoingType: [coin type of withdrawal],
                transaction: [transaction id of coin sent to withdrawal address]
            }

        Status: Failed
            {
                status : "failed",
                error: [Text describing failure]
            }
        """
        self.url = self.baseurl + "/txStat/" + address
        return self.get_request(self.url)

    def time_remaining(self, address):
        """
        When a transaction is created with a fixed amount requested there is a 10 minute window for the deposit.
        After the 10 minute window if the deposit has not been received the transaction expires and a new one must be
        created. This api call returns how many seconds are left before the transaction expires.
        Please note that if the address is a ripple address, it will include the "?dt=destTagNUM" appended on the end,
        and you will need to use the URIEncodeComponent() function on the address before sending it in as a param,
        to get a successful response.
        [address] is the deposit address to look up.
        Success Output:
            {
                status:"pending",
                seconds_remaining: 600
            }
        The status can be either "pending" or "expired".
        If the status is expired then seconds_remaining will show 0.
        """
        self.url = self.baseurl + "/timeremaining/" + address
        return self.get_request(self.url)

    def coin_list(self):
        """
        Allows anyone to get a list of all the currencies that Shapeshift currently supports at any given time.
        The list will include the name, symbol, availability status, and an icon link for each.
        Success Output:
            {
                "SYMBOL1" :
                    {
                        name: ["Currency Formal Name"],
                        symbol: <"SYMBOL1">,
                        image: ["https://shapeshift.io/images/coins/coinName.png"],
                         status: [available / unavailable]
                    }
                (one listing per supported currency)
            }
        The status can be either "available" or "unavailable". Sometimes coins become temporarily unavailable during updates or
        unexpected service issues.
        """
        self.url = self.baseurl + "/getcoins"
        return self.get_request(self.url)

    def tx_by_apikey(self):
        """
        Allows vendors to get a list of all transactions that have ever been done using a specific API key.
        Transactions are created with an affilliate PUBLIC KEY, but they are looked up using the linked PRIVATE KEY,
        to protect the privacy of our affiliates' account details.
            [apiKey] is the affiliate's PRIVATE api key.

                [
                    {
                        inputTXID: [Transaction ID of the input coin going into shapeshift],
                        inputAddress: [Address that the input coin was paid to for this shift],
                        inputCurrency: [Currency type of the input coin],
                        inputAmount: [Amount of input coin that was paid in on this shift],
                        outputTXID: [Transaction ID of the output coin going out to user],
                        outputAddress: [Address that the output coin was sent to for this shift],
                        outputCurrency: [Currency type of the output coin],
                        outputAmount: [Amount of output coin that was paid out on this shift],
                        shiftRate: [The effective rate the user got on this shift.],
                        status: [status of the shift]
                     }
                    (one listing per transaction returned)
                ]

            The status can be "received", "pending", "verifying_send", "sent_exact", "exchanged". "sent_exact" is the same as
            "exchanged", for all intensive purposes, meaning the shift completed, funds were sent in and out and there was no error.
        """
        self.url = self.baseurl + "/txbyapikey/" + self.api_key
        return self.get_request(self.url)

    def tx_by_address(self, address):
        """
        Allows vendors to get a list of all transactions that have ever been sent to one of their addresses.
        The affilliate's PRIVATE KEY must be provided, and will only return transactions that were sent to output
        address AND were created using / linked to the affiliate's PUBLIC KEY. Please note that if the address is a
        ripple address and it includes the "?dt=destTagNUM" appended on the end, you will need to use the
        URIEncodeComponent() function on the address before sending it in as a param, to get a successful response.
        [address] the address that output coin was sent to for the shift
        [apiKey] is the affiliate's PRIVATE api key.
        Success Output:
        [
                {
                    inputTXID: [Transaction ID of the input coin going into shapeshift],
                    inputAddress: [Address that the input coin was paid to for this shift],
                    inputCurrency: [Currency type of the input coin],
                    inputAmount: [Amount of input coin that was paid in on this shift],
                    outputTXID: [Transaction ID of the output coin going out to user],
                    outputAddress: [Address that the output coin was sent to for this shift],
                    outputCurrency: [Currency type of the output coin],
                    outputAmount: [Amount of output coin that was paid out on this shift],
                    shiftRate: [The effective rate the user got on this shift.],
                    status: [status of the shift]
                }
                (one listing per transaction returned)
            ]
        The status can be "received", "pending", "verifying_send", "sent_exact", "exchanged". "sent_exact" is the same as
        "exchanged", for all intensive purposes, meaning the shift completed, funds were sent in and out and there was no error.
        """
        self.url = self.baseurl + "/txbyaddress/" + address + "/" + self.api_key
        return self.get_request(self.url)

    def validate_address(self, address, coin):
        """
        Allows user to verify that their receiving address is a valid address according to a given wallet daemon.
        If isvalid returns true, this address is valid according to the coin daemon indicated by the currency symbol.
        [address] the address that the user wishes to validate
        [coinSymbol] the currency symbol of the coin
        Success Output:
                {
                     isValid: [true / false],
                     error: [(if isvalid is false, there will be an error message)]
                }
        isValid will either be true or false. If isvalid returns false, an error parameter will be present and will contain a descriptive error message.
        """
        self.url = self.baseurl + "/validateAddress/" + address + "/" + coin
        return self.get_request(self.url)

    def shift(self, frm, to, withdrawal, returnAddress, destTag=None, rsAddress=None):
        """
        This is the primary data input into ShapeShift.
            data required:
            withdrawal     = the address for resulting coin to be sent to
            pair       = what coins are being exchanged in the form [input coin]_[output coin]  ie btc_ltc
            returnAddress  = (Optional) address to return deposit to if anything goes wrong with exchange
            destTag    = (Optional) Destination tag that you want appended to a Ripple payment to you
            rsAddress  = (Optional) For new NXT accounts to be funded, you supply this on NXT payment to you

            example data: {"withdrawal":"AAAAAAAAAAAAA", "pair":"btc_ltc", returnAddress:"BBBBBBBBBBB"}

            Success Output:
                {
                    deposit: [Deposit Address (or memo field if input coin is BTS / BITUSD)],
                    depositType: [Deposit Type (input coin symbol)],
                    withdrawal: [Withdrawal Address], //-- will match address submitted in post
                    withdrawalType: [Withdrawal Type (output coin symbol)],
                    public: [NXT RS-Address pubkey (if input coin is NXT)],
                    xrpDestTag : [xrpDestTag (if input coin is XRP)],
                    apiPubKey: [public API attached to this shift, if one was given]
                }
            """
        postdata = {
            'withdrawal': withdrawal,
            'pair': "%s_%s" % (frm, to),
            'returnAddress': returnAddress
        }
        if destTag:
            postdata['destTag'] = destTag
        if rsAddress:
            postdata['rsAddress'] = rsAddress
        if self.api_key:
            postdata['apiKey'] = self.api_key
        self.url = self.baseurl + "/shift"
        return self.post_request(self.url, postdata)

    def set_mail(self, email, txid):
        """
        This call requests a receipt for a transaction.
        The email address will be added to the conduit associated with that transaction as well.
        (Soon it will also send receipts to subsequent transactions on that conduit)
            data required:
            email    = the address for receipt email to be sent to
            txid       = the transaction id of the transaction TO the user (ie the txid for the withdrawal NOT the deposit)
            example data {"email":"mail@example.com", "txid":"123ABC"}

            Success Output:
                {"email":
                    {
                    "status":"success",
                    "message":"Email receipt sent"
                    }
                }
        """
        postdata = {'email': email, 'txid': txid}
        self.url = self.baseurl + "/mail"
        return self.post_request(self.url, postdata)

    def send_amount_quote_only(self, frm, to, amount):
        """
        This call allows you to request a quoted price on the amount of a transaction without a
        withdrawal address.

            //1. Quoted Price request


            //Note :  This request will only return information about a quoted rate
            //         This request will NOT generate the deposit address.



              Data required:

                amount  = the amount to be sent to the withdrawal address
                pair    = what coins are being exchanged in the form [input coin]_[output coin]  ie ltc_btc

                example data {"amount":123, "pair":"ltc_btc"}


              Success Output:
                {
                     success:
                      {
                        pair: [pair],
                        withdrawalAmount: [Withdrawal Amount], // Amount of the output coin you will receive
                        depositAmount: [Deposit Amount], // Exact amount of input coin to send in
                        expiration: [timestamp when this will expire],
                        quotedRate: [the exchange rate to be honored]
                        minerFee: [miner fee for this transaction]
                      }
                }
        """
        postdata = {'amount': amount, 'pair': "%s_%s" % (frm, to)}
        self.url = self.baseurl + "/sendamount"
        return self.post_request(self.url, postdata)

    def send_amount(self, frm, to, amount, withdrawal, returnAddress, destTag=None, rsAddress=None):
        """
        This call allows you to request a fixed amount to be sent to the withdrawal address.
        You provide a withdrawal address and the amount you want sent to it.
        We return the amount to deposit and the address to deposit to. This allows you to use shapeshift as a payment
        mechanism.
        //1. Send amount request


            Data required:

                amount          = the amount to be sent to the withdrawal address
                withdrawal      = the address for coin to be sent to
                pair            = what coins are being exchanged in the form [input coin]_[output coin]  ie ltc_btc
                returnAddress   = (Optional) address to return deposit to if anything goes wrong with exchange
                destTag         = (Optional) Destination tag that you want appended to a Ripple payment to you
                rsAddress       = (Optional) For new NXT accounts to be funded, supply this on NXT payment to you
                apiKey          = (Optional) Your affiliate PUBLIC KEY, for volume tracking, affiliate payments, split-shifts, etc...

            example data {"amount":123, "withdrawal":"123ABC", "pair":"ltc_btc", returnAddress:"BBBBBBB"}  Success Output:


            {
                 success:
                  {
                    pair: [pair],
                    withdrawal: [Withdrawal Address], //-- will match address submitted in post
                    withdrawalAmount: [Withdrawal Amount], // Amount of the output coin you will receive
                    deposit: [Deposit Address (or memo field if input coin is BTS / BITUSD)],
                    depositAmount: [Deposit Amount], // Exact amount of input coin to send in
                    expiration: [timestamp when this will expire],
                    quotedRate: [the exchange rate to be honored]
                    apiPubKey: [public API attached to this shift, if one was given]
                  }
            }
        """
        postdata = {'amount': amount,
                    'pair': "%s_%s" % (frm, to),
                    'withdrawal': withdrawal,
                    'returnAddress': returnAddress}
        if destTag:
            postdata['destTag'] = destTag
        if rsAddress:
            postdata['rsAddress'] = rsAddress
        if self.api_key:
            postdata['apiKey'] = self.api_key
        self.url = self.baseurl + "/sendamount"
        return self.post_request(self.url, postdata)

    def cancel_pending(self, address):
        """
        This call allows you to request for canceling a pending transaction by the deposit address. If there is fund sent to the deposit address, this pending transaction cannot be canceled.
            data required: address  = The deposit address associated with the pending transaction
            Example data : {address : "1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v"}
            Success Output:
             {  success  : " Pending Transaction cancelled "  }
            Error Output:
             {  error  : {errorMessage}  }
        """
        postdata = {'address': address}
        self.url = self.baseurl + "/cancelpending"
        return self.post_request(self.url, postdata)