from ntru import Ntru
import base64
import binascii
import numpy as np
from itertools import chain
import math, random
import time

import pandas as pd
import csv


# process for converting string message into vector base

def trans(msg):
    encoded = []
    encoded.append(base64.b64encode(bytes(msg,"utf-8") ) )
    #print("\n--------ENCODED TEXT--------\n",encoded)
    binaryMessage=[]
    for i in range(len(encoded)):
    	binaryMessage.append(binascii.a2b_base64(encoded[i]) )
    encrypted_ints = []
    for i in range(len(encoded)):
    	encrypted_ints.append(int.from_bytes(binaryMessage[i],byteorder='little') )
    return encrypted_ints

# two functions use for format string and binary
def strToBin(m):
	return "".join(format(ord(c), 'b').zfill(8) for c in m)

def binToStr(b):
	bs = []
	for i in range(len(b)//8):
		bs.append(chr(int("".join([ str(x) for x in b[i*8:(i+1)*8] ]),2)))
	return "".join(bs)

    



# process
# paremeter can change to be 
# N    P    Q
#  107  3    64
#  167  3    128
#  263  3    128
#  503  3    256 

# initialize
f = [1, 1, -1, 0, -1, 1]
g = [-1, 0, 1, 1, 0, 0, -1]
d = 2    
N = 503
p = 3
q = 256

def NTRU_encrypt(msg):
    Bob = Ntru(N, p, q)
   
    Bob.genPublicKey(f, g, 2)
    # set public key
    public_key = Bob.getPublicKey()
    msg_1 = strToBin(msg)
    msg_1_new = []
    for i in msg_1:
        msg_1_new.append(int(i))
    #print(msg_1_new)
    
    # random poly
    ranPol = [-1, -1, 1, 1]
    Alice = Bob
    encrypt_msg = Alice.encrypt(msg_1_new,ranPol)
    #dec = Bob.decrypt(encrypt_msg)
    return encrypt_msg

def NTRU_decrypt(encrypt_msg):
    Bob = Ntru(N, p, q)
    Bob.genPublicKey(f, g, 2)
    dec = Bob.decrypt(encrypt_msg)

    # cause the last several 0 will be losed, so adding zeros at the end
    if len(dec)%8 != 0:
        rest = 8 * (len(dec)//8 + 1)  - 8 * (len(dec)//8) 
        print(rest)
        for i in range(int(rest)):
            dec.append(0)
        # convert back to string base
    dec_new = binToStr(dec)
    return dec_new






print(NTRU_encrypt("hello world"))
encrypt_msg = NTRU_encrypt("hello world")
#test case
print(NTRU_decrypt(encrypt_msg))

