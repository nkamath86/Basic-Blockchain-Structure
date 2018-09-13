#!/usr/bin/env  python2
#Author: nkamath

#Building the basic architecture of a blockchain 
#Current immplementation only supports two users

from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import sha3, json, sys, socket

users = {} #dont think we need this; only have two users now.

def hashMe(msg=""):
    # this is a helper function that wraps our hashing algorithm
    if type(msg)!=str:
        msg = json.dumps(msg,sort_keys=True)  # If we don't sort keys, we can't guarantee repeatability
        
    return sha3.sha3_256(str(msg).encode('utf-8')).hexdigest()


def addUser():
	#function to help add new users to the blockchain
	print 'We will now be adding you as a new user... '
	username, initialBalance = raw_input('Enter Username and Initial Balance seperated by space').strip().split()
	if username in users:
		print 'Username already exists! Try something else.'
		return False
	else:
		if initialBalance > 0:
			users[username] = {}
			users[username]['initialBalance'] = initialBalance
			new_key = RSA.generate(2048)
			public_key = new_key.publickey().exportKey("PEM")
			private_key = new_key.exportKey("PEM") 
			users[username]['public_key'] = public_key
			users[username]['private_key'] = private_key
		return True

def makeConnection(sign):
	#function to handle creation of socket connection 
	if sign == -1:
		#client side
		HOST = ''    #localhost
		PORT = 50007 #port
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((HOST, PORT))
	else:
		#receiver side
		HOST = ''    #localhost
		PORT = 50007 #The same port
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((HOST, PORT))
		s.listen(1)
		conn, addr = s.accept()
		print 'Connection established... ' 

def makeTransaction():
	list_of_users = users.keys()
	sign = -1
	if int(raw_input('Are you the sender (1) or receiver (2) ?').strip()) == 2:
		sign = 1 	#receiver, so increase in amount (+ve)

	makeConnection(sign)

	if sign == -1:	#sender
		amount = int(raw_input('Enter amount to be sent: ').strip())

		transaction = {}


