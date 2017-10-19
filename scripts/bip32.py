# -*- coding: utf-8 -*-
"""
Created on Mon Oct 16 11:16:55 2017

@author: dfornaro
"""
from secp256k1 import order, G, pointMultiply
import hmac
import hashlib
import base58



###############################################################################
###############################################################################

def from_hex_to_bytes(value):
    if len(value) % 2 ==1:
        raise TypeError("hex must be composed by a odd number of value")
    value_base10 = [0]*int(len(value)/2)
    for i in range(0,int(len(value)/2)):
        value_base10[i] = int(value[i*2:(i+1)*2],16)
    value_bytes = bytes(value_base10)
    return value_bytes

###############################################################################
###############################################################################

seed = '000102030405060708090a0b0c0d0e0f'
seed_bytes = from_hex_to_bytes(seed)
hashValue = hmac.HMAC(key=b"Bitcoin seed", msg=seed_bytes, digestmod=hashlib.sha512).hexdigest()
# master private Key:
mp = hashValue[:64]
# master chain code
chain_code = hashValue [64:]

# version is needed to obtain xprv when encoded in base 58
version = '0488ade4'
# depth is the level of the tree, for the master key is set to 0
depth = '00'
# fingerprint is set to 0 for the master key
fingerprint  = '00000000'
# child_number is the index of the child, for the master key is set to 0
child_number = '00000000'

extended_pr_key = version + depth + fingerprint + child_number + chain_code + '00' + mp
extended_pr_key_bytes = from_hex_to_bytes(extended_pr_key)
# We need to add a checksum at the end of the extended private key (double sha256)
checksum = hashlib.sha256(hashlib.sha256(extended_pr_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pr_key_checked = extended_pr_key + checksum[:8]
extended_pr_key_checked_bytes = from_hex_to_bytes(extended_pr_key_checked)
# We will rapresent the extended private key in base 58
extended_pr_key_58 = base58.b58encode(extended_pr_key_checked_bytes)
print('Master extended private Key:',extended_pr_key_58)
expected = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
print('Expected extended private Key:',expected)
print('Are the two string equal?',expected == extended_pr_key_58,'\n')


###############################################################################
###############################################################################
###############################################################################

# Obtain a master public Key from a master private key
mp_int = int(mp,16)
MP_int = pointMultiply(mp_int , G)
prefix = b'\x03' if (MP_int[0] % 2 == 0) else b'\x02'
# Master Public Key:
MP = prefix + MP_int[0].to_bytes(32, byteorder='big')
MP_hex = MP.hex()

# in order to obtain the master public key, we will compute the same procedure

# version is needed to obtain xpub when encoded in base 58
version='0488b21e'
# depth is the level of the tree, for the master key is set to 0
depth = '00'
# fingerprint is set to 0 for the master key
fingerprint  = '00000000'
# child_number is the index of the child, for the master key is set to 0
child_number = '00000000'

extended_pub_key = version + depth + fingerprint + child_number + chain_code + MP_hex
extended_pub_key_bytes = from_hex_to_bytes(extended_pub_key)
# We need to add a checksum at the end of the extended public key (double sha256)
checksum = hashlib.sha256(hashlib.sha256(extended_pub_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pub_key_checked = extended_pub_key + checksum[0:8]
extended_pub_key_checked_bytes = from_hex_to_bytes(extended_pub_key_checked)
# We will rapresent the extended public key in base 58
extended_pub_key_58=base58.b58encode(extended_pub_key_checked_bytes)

print('Master extended public Key:',extended_pub_key_58)
expected = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
print('Expected extended public Key:',expected)
print('Are the two string equal?',expected == extended_pub_key_58,'\n')



###############################################################################
###############################################################################
###############################################################################
################### Derivation of the first child  ############################
###############################################################################
###############################################################################
###############################################################################

print ('     (m/0\')\n')

#computation of the child keys and chain-code

"""
HMAC-SHA512(Key = chain_code, Data = 0x00 || ser256(prKey) || ser32(i))
"""
index = '80000000'
data = '00' + mp + index

chain_code_bytes = from_hex_to_bytes(chain_code)
data_bytes = from_hex_to_bytes(data)

hashValue=hmac.HMAC(key=chain_code_bytes, msg=data_bytes, digestmod=hashlib.sha512).hexdigest()

p_int = (int(mp,16) + int(hashValue[0:64] ,16) ) % order
p = hex(p_int)[2:]
chain_code = hashValue [64:128]




# computation of the fingerprint
"""
Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256) of the
serialized ECDSA public key K, ignoring the chain code.
The first 32 bits of the identifier are called the key fingerprint.
"""

h1 = hashlib.sha256(MP).digest()
h2 = hashlib.new('ripemd160', h1).digest()

fingerprint_byte = h2[:4]

version='0488ade4'
depth = '01'
fingerprint = fingerprint_byte.hex()
# The index of the first child is 0, but from the moment that we want to be hardened, the index will start from 80000000
child_number = index


extended_pr_key = version + depth + fingerprint + child_number + chain_code + '00' + p
extended_pr_key_bytes = from_hex_to_bytes(extended_pr_key)
# We need to add a checksum at the end of the extended private key (double sha256)
checksum = hashlib.sha256(hashlib.sha256(extended_pr_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pr_key_checked = extended_pr_key + checksum[0:8]
extended_pr_key_checked_bytes = from_hex_to_bytes(extended_pr_key_checked)
# We will rapresent the extended private key in base 58
extended_pr_key_58=base58.b58encode(extended_pr_key_checked_bytes)

print('Child extended private Key:',extended_pr_key_58)
expected = 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
print('Expected extended private Key:',expected)
print('Are the two string equal?',expected == extended_pr_key_58,'\n')


###############################################################################
###############################################################################

p_int = int(p,16)
P_int = pointMultiply(p_int , G)
prefix = b'\x03' if (P_int[0] % 2 == 0) else b'\x02'
# Master Public Key:
P = prefix + P_int[0].to_bytes(32, byteorder='big')
P_hex = P.hex()

###############################################################################
###############################################################################
###############################################################################
################## Derivation of the child of the child  ######################
###############################################################################
###############################################################################
###############################################################################



print ('     (m/0\'/1)\n')

index = '00000001'
data = P_hex + index

chain_code_bytes = from_hex_to_bytes(chain_code)
data_bytes = from_hex_to_bytes(data)

hashValue=hmac.HMAC(key=chain_code_bytes, msg=data_bytes, digestmod=hashlib.sha512).hexdigest()

p_int = (int(p,16) + int(hashValue[0:64] ,16) ) % order
p = hex(p_int)[2:]
while len(p)<64:
    p='0'+p
chain_code = hashValue [64:128]




# computation of the fingerprint
"""
Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256) of the
serialized ECDSA public key K, ignoring the chain code.
The first 32 bits of the identifier are called the key fingerprint.
"""

h1 = hashlib.sha256(P).digest()
h2 = hashlib.new('ripemd160', h1).digest()

fingerprint_byte = h2[:4]

version='0488ade4'
depth = '02'
fingerprint = fingerprint_byte.hex()
# The index of this child is 1
child_number = index


extended_pr_key = version + depth + fingerprint + child_number + chain_code + '00' + p
extended_pr_key_bytes = from_hex_to_bytes(extended_pr_key)
# We need to add a checksum at the end of the extended private key (double sha256)
checksum = hashlib.sha256(hashlib.sha256(extended_pr_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pr_key_checked = extended_pr_key + checksum[0:8]
extended_pr_key_checked_bytes = from_hex_to_bytes(extended_pr_key_checked)
# We will rapresent the extended private key in base 58
extended_pr_key_58=base58.b58encode(extended_pr_key_checked_bytes)

print('Child extended private Key:',extended_pr_key_58)
expected = 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'
print('Expected extended private Key:',expected)
print('Are the two string equal?',expected == extended_pr_key_58,'\n')

###############################################################################
###############################################################################

p_int = int(p,16)
P_int = pointMultiply(p_int , G)
prefix = b'\x03' if (P_int[0] % 2 == 0) else b'\x02'
# Master Public Key:
P = prefix + P_int[0].to_bytes(32, byteorder='big')
P_hex = P.hex()

###############################################################################
###############################################################################
###############################################################################
########### Derivation of the child of the child of the child #################
###############################################################################
###############################################################################
###############################################################################



print ('     (m/0\'/1/2\')\n')

index = '80000002'
data = '00' + p + index

chain_code_bytes = from_hex_to_bytes(chain_code)
data_bytes = from_hex_to_bytes(data)

hashValue=hmac.HMAC(key=chain_code_bytes, msg=data_bytes, digestmod=hashlib.sha512).hexdigest()

p_int = (int(p,16) + int(hashValue[:64] ,16) ) % order
p = hex(p_int)[2:]
while len(p)<64:
    p='0'+p
chain_code = hashValue [64:]




# computation of the fingerprint
"""
Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256) of the
serialized ECDSA public key K, ignoring the chain code.
The first 32 bits of the identifier are called the key fingerprint.
"""

h1 = hashlib.sha256(P).digest()
h2 = hashlib.new('ripemd160', h1).digest()

fingerprint_byte = h2[:4]

version='0488ade4'
depth = '03'
fingerprint = fingerprint_byte.hex()
# The index of this child is 1
child_number = index


extended_pr_key = version + depth + fingerprint + child_number + chain_code + '00' + p
extended_pr_key_bytes = from_hex_to_bytes(extended_pr_key)
# We need to add a checksum at the end of the extended private key (double sha256)
checksum = hashlib.sha256(hashlib.sha256(extended_pr_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pr_key_checked = extended_pr_key + checksum[0:8]
extended_pr_key_checked_bytes = from_hex_to_bytes(extended_pr_key_checked)
# We will rapresent the extended private key in base 58
extended_pr_key_58=base58.b58encode(extended_pr_key_checked_bytes)

print('Child extended private Key:',extended_pr_key_58)
expected = 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'
print('Expected extended private Key:',expected)
print('Are the two string equal?',expected == extended_pr_key_58,'\n')

###############################################################################
###############################################################################

p_int = int(p,16)
P_int = pointMultiply(p_int , G)
prefix = b'\x03' if (P_int[0] % 2 == 0) else b'\x02'
# Master Public Key:
P = prefix + P_int[0].to_bytes(32, byteorder='big')
P_hex = P.hex()

###############################################################################
###############################################################################
###############################################################################
################## Derivation of the child of the child ...####################
###############################################################################
###############################################################################
###############################################################################



print ('     (m/0\'/1/2\/2\')\n')

index = '00000002'
data = P_hex + index

chain_code_bytes = from_hex_to_bytes(chain_code)
data_bytes = from_hex_to_bytes(data)

hashValue=hmac.HMAC(key=chain_code_bytes, msg=data_bytes, digestmod=hashlib.sha512).hexdigest()

p_int = (int(p,16) + int(hashValue[0:64] ,16) ) % order
p = hex(p_int)[2:]
while len(p)<64:
    p='0'+p
chain_code = hashValue [64:128]




# computation of the fingerprint
"""
Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256) of the
serialized ECDSA public key K, ignoring the chain code.
The first 32 bits of the identifier are called the key fingerprint.
"""

h1 = hashlib.sha256(P).digest()
h2 = hashlib.new('ripemd160', h1).digest()

fingerprint_byte = h2[:4]

version='0488ade4'
depth = '04'
fingerprint = fingerprint_byte.hex()
# The index of this child is 1
child_number = index


extended_pr_key = version + depth + fingerprint + child_number + chain_code + '00' + p
extended_pr_key_bytes = from_hex_to_bytes(extended_pr_key)
# We need to add a checksum at the end of the extended private key (double sha256)
checksum = hashlib.sha256(hashlib.sha256(extended_pr_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pr_key_checked = extended_pr_key + checksum[0:8]
extended_pr_key_checked_bytes = from_hex_to_bytes(extended_pr_key_checked)
# We will rapresent the extended private key in base 58
extended_pr_key_58=base58.b58encode(extended_pr_key_checked_bytes)

print('Child extended private Key:',extended_pr_key_58)
expected = 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'
print('Expected extended private Key:',expected)
print('Are the two string equal?',expected == extended_pr_key_58,'\n')


###############################################################################
###############################################################################

p_int = int(p,16)
P_int = pointMultiply(p_int , G)
prefix = b'\x03' if (P_int[0] % 2 == 0) else b'\x02'
# Master Public Key:
P = prefix + P_int[0].to_bytes(32, byteorder='big')
P_hex = P.hex()

###############################################################################
###############################################################################
###############################################################################
################## Derivation of the child of the child ...####################
###############################################################################
###############################################################################
###############################################################################



print ('     (m/0\'/1/2\/2\'/1000000000)\n')

index = hex(1000000000)[2:]
data = P_hex + index

chain_code_bytes = from_hex_to_bytes(chain_code)
data_bytes = from_hex_to_bytes(data)

hashValue=hmac.HMAC(key=chain_code_bytes, msg=data_bytes, digestmod=hashlib.sha512).hexdigest()

p_int = (int(p,16) + int(hashValue[0:64] ,16) ) % order
p = hex(p_int)[2:]
while len(p)<64:
    p='0'+p
chain_code = hashValue [64:128]




# computation of the fingerprint
"""
Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256) of the
serialized ECDSA public key K, ignoring the chain code.
The first 32 bits of the identifier are called the key fingerprint.
"""

h1 = hashlib.sha256(P).digest()
h2 = hashlib.new('ripemd160', h1).digest()

fingerprint_byte = h2[:4]

version='0488ade4'
depth = '05'
fingerprint = fingerprint_byte.hex()
# The index of this child is 1
child_number = index


extended_pr_key = version + depth + fingerprint + child_number + chain_code + '00' + p
extended_pr_key_bytes = from_hex_to_bytes(extended_pr_key)
# We need to add a checksum at the end of the extended private key (double sha256)
checksum = hashlib.sha256(hashlib.sha256(extended_pr_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pr_key_checked = extended_pr_key + checksum[0:8]
extended_pr_key_checked_bytes = from_hex_to_bytes(extended_pr_key_checked)
# We will rapresent the extended private key in base 58
extended_pr_key_58=base58.b58encode(extended_pr_key_checked_bytes)

print('Child extended private Key:',extended_pr_key_58)
expected = 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
print('Expected extended private Key:',expected)
print('Are the two string equal?',expected == extended_pr_key_58,'\n')
