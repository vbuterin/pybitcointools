import bitcoin
import sys
import argparse
import urllib2
import json

require_offline=False
running_offline=None

def user_input(s,expectednotchar=None):
	sys.stderr.write(s)
	q=raw_input()
	if(expectednotchar and (q[0].lower() not in expectednotchar)):
		quit()
	return q

def test_offline():
	global running_offline
	if(running_offline is None):
		user_input("Make sure you are offline, alone, and your screen is not visible. [OK]")
		print("Testing if you are online...")
		try:
			result=urllib2.urlopen("https://google.com",timeout=3.0).read()
			user_input("You lied about being offline! [OK]")
			running_offline=False
			return False
		except Exception as e:
			print(e)
			running_offline=True
			return True
	else:
		return running_offline
		
		
def offlineonly(f):	
	def wrapper(): 
		global require_offline
		if(require_offline):
			if(not test_offline()):
				user_input('Warning!  You are not in offline mode! You should immediately quit before executing this function! Do you want to do so now? [Y/n]','n')
		return f()
	return wrapper
	
@offlineonly
def get_password():
	mnemonic=user_input('Type your password mnemonic, one word at a time:\n')
	return mnemonic

@offlineonly
def get_entropy():
	choice=user_input('Do you want to use\n\t(1) System Entropy\n\t(2) User Entropy\n')
	

def get_master_key():
	words=' '.join(get_password().split())
	try:
		a=bitcoin.words_verify(words)
	except Exception as e:
		print(e)
		a=False
	
	if(not a):
		q=user_input("Warning! Mnemonic does not verify as a string of bip39 english space-seperated words! continue? [y/N]",'y')

	seed=bitcoin.mnemonic_to_seed(words)
	master_key=bitcoin.bip32_master_key(seed)
	return master_key

def sign(args):
	master_key=get_master_key()
	account_privkey=bitcoin.hd_lookup(master_key,account=args.account)
	input_transaction=json.load(args.input_transaction)
	#compute the largest change address and largest address in the account (use xpub and bitcoin.bip32_string_to_path)
	#compute all the underlying addresses and pkeys into a string hash
	#decide on the change address
	#build the transaction
	#sign the transaction
	#print the hex
	
def pubkey(args):
	master_key=get_master_key()
	
	if(args.root or (args.account and args.account < 0)):
		#print("The following is your master root extended public key:")
		print(bitcoin.bip32_privtopub(master_key))
	else:
		account_privkey=bitcoin.hd_lookup(master_key,account=args.account)
		#print("The following is the extended public key for account #%d:" % (args.account))
		print(bitcoin.bip32_privtopub(account_privkey))

def send(args):
	if(len(args.outputs) % 2 != 0):
		raise Exception("When sending, there must be an even number of arguments for the outputs (address,price)")
	unspents=bitcoin.BlockchainInfo.unspent_xpub(args.xpub)
	def btctosatoshi(vs):
		return int(float(vs)*100000000.0)
	fee=btctosatoshi(args.fee)
	if(fee < 0):
		fee=int(-0.0001*100000000) #todo do something to estimated fee...make it negative or something though
	outaddrval=[(args.outputs[2*i],btctosatoshi(args.outputs[2*i+1])) for i in range(len(args.outputs)//2)]
	outtotalval=sum([o[1] for o in outaddrval])
	unspenttotalval=sum([u['value'] for u in unspents])
	if(outtotalval+abs(fee) >= unspenttotalval):
		raise Exception("There is unlikely to be enough unspent outputs to cover the transaction and fees")
	out={}
	out['unspents']=unspents
	out['fee']=fee #negative if estimated
	out['outputs']=outaddrval

	json.dump(out,sys.stdout)

def address(args):
	if(not args.index):
		unspents=bitcoin.BlockchainInfo.unspent_xpub(args.xpub)
		index=0
		for u in unspents:
			upath=u['xpub']['path']
			cdex=bitcoin.bip32_path_from_string(upath)[-1]
			index=max(cdex,index)
		index+=1
	else:
		index=args.index
	address=bitcoin.pubtoaddr(bitcoin.bip32_descend(args.xpub,0,index))
	print(address)

def generate(args):
	
	
if __name__=="__main__":
	aparser=argparse.ArgumentParser()
	subaparsers=aparser.add_subparsers()
	aparse_send=subaparsers.add_parser('send',help="[online] Get the unspents and generate an unsigned transaction to some outputs")
	aparse_send.add_argument('--xpub','-p',required=True,help="The xpubkey for the hdwallet account")
	aparse_send.add_argument('--fee','-f',default=-1,type=float,help="The fee to use")
	aparse_send.add_argument('outputs',help="The outputs, two at a time in <addr> <amount> format...e.g. 1L3qUmg3GeuGrGvi1JxT2jMhAdV76qVj7V 1.032",nargs='+')
	aparse_send.set_defaults(func=send)
	
	aparse_pubkey=subaparsers.add_parser('pubkey',help='[offline] Get the extended HD pubkey for a particular account')
	aparse_pubkey_accountgroup=aparse_pubkey.add_mutually_exclusive_group(required=True)
	aparse_pubkey_accountgroup.add_argument('--account','-a',type=int,help="The number of the hd wallet account to export the pubkey for.")
	aparse_pubkey_accountgroup.add_argument('--root','-r',action='store_true',help="The exported wallet account pubkey is the master extended pubkey.")
	aparse_pubkey.set_defaults(func=pubkey)

	aparse_address=subaparsers.add_parser('address',help='[online or offline] Get an address for an account')
	aparse_address.add_argument('--xpub','-p',required=True,help="The xpubkey for the hdwallet account")
	aparse_address.add_argument('--index','-i','--address',type=int,help='The index of the address to get from the account')
	aparse_address.set_defaults(func=address)

	args=aparser.parse_args()
	args.func(args)
	
	

	
