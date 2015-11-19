import hashlib
import os.path
from bisect import bisect_right,bisect_left

wordlist_english=list(open(os.path.join(os.path.dirpath(__file__),'english.txt'),'r'))

def entropy_cs(entbytes):
	entropy_size=8*len(entbytes)
	checksum_size=entropy_size//32
	hd=hashlib.sha256(entbytes).hexdigest()
	csint=int(hd,16) >> (256-checksum_size)
	return csint,checksum_size

def entropy_to_words(entbytes,wordlist=wordlist_english):
	entropy_size=8*len(entbytes)
	csint,checksum_size = entropy_cs(entbytes)

	mint=(entint << checksum_size) | csint
	mnemonic_size=(entropy_size+checksum_size)/11
	
	backwords=[wordlist[(seedint >> (11*x)) & 0x7FF].strip() for x in range(seedsize)]
	return reversed(backwords)

	
#def words_to_seed(words,wordlist=wordlist_english):
	

def words_bisect(word,wordlist=wordlist_english):
	lo=bisect_left(wordlist,word)
	hi=lo
	lw=len(word)
	while(wordlist[hi][:lw]==word):
		hi+=1
	
	return lo,hi

def words_split(wordstr,wordlist=wordlist_english):
	def popword(wordstr,wordlist):
		for fwl in range(1,9):
			w=wordstr[:fwl]
			lo,hi=words_bisect(w,wordlist)
			if(hi-lo == 1):
				return w,wordstr[fwl:]
			wordlist=wordlist[lo:hi]
		raise Exception("Wordstr %s not found in list" %(w))

	words=[]
	tail=wordstr
	while(len(tail)):
		head,tail=popword(tail,wordlist)
		words.append(head)
	return words

def words_verify(words):
	pass
	#if words in string, split them first.
	
