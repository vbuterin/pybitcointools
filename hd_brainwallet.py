import bitcoin
import sys
import argparse


is_offline = False
def test_offline():
	raw_input("Make sure you are offline, alone, and your screen is not visible. [OK]")
	print("Testing if you are online...")
	try:
		urllib2.urlopen("https://google.com",timeout=2.0)
		raw_input("You lied about being offline!")
		return False
	except:
		return True
		
		
def offlineonly(f):	
	def wrapper():
		if(not is_offline):
			q=raw_input('Warning!  You are not in offline mode! You should immediately quit before executing this function! [Y/n]')
			if(q.lower()!='n'):
				quit()
		return f()
	return wrapper
	
@offlineonly
def get_password():
	mnemonic=raw_input('Type your password mnemonic, one word at a time:\n')
	return mnemonic


if __name__=="__main__":

	

	if(args.is_offline):
		is_offline=test_offline()
	
	