hd_coldwallet.py is a tool for cold storage with a standard bip39/bip44 addres scheme (commonly called an 'HD' wallet). 

Download it to a raspberry pi or a fresh offline PC

	steven@steven $ python hd_coldwallet.py generate > mywords
	Make sure you are offline, alone, and your screen is not visible. [OK]

	steven@steven $ cat mywords 
	tide there thought shine vault blind behave balcony tree pull beach clutch

	steven@steven $ python hd_coldwallet.py pubkey --account 0 < mywords > myxpub
	Make sure you are offline, alone, and your screen is not visible. [OK]

	steven@steven $ cat myxpub
	xpub6Bor33aJFTbn9RTUfhVxLsJbjtgAZJFa2sT3owAoEbVS1t6QaeACeuJoYbQnHtZwHn3XzLWLgDFFhkdYSJDVwLEDFd4Nq8iyxtq3bQLYd81

	steven@steven $ python hd_coldwallet.py address --xpub `cat myxpub` --index 0
	1Lc3ojcBDmhRujpwsPViVmpr1aYR5obbuf

It has a lot of options too, like you can use your own entropy (e.g, from dice) or generate longer mnemonics.  Here's an example using user entropy and a 18 word mnemonic:

    	python hd_coldwallet.py generate --entropy_bits 256 --entropy_source user

You can also use it to make transactions (online) from the xpub, and sign the transactions (offline).

you can even generate a transaction from the xpub online, (it handles change for you in the transaction too)

	python hd_coldwallet.py send --xpub `cat myxpub` --fee 0.0009 1LuckyG4tMMZf64j6ea7JhCz7sDpk6vdcS 0.5 1dice7fUkz5h4z2wPc1wLMPWgB5mDwK 0.5 > transaction.unsigned
	
then, offline,

	python hd_coldwallet.py sign --input_file transaction.unsigned < mywords > transaction.signed


