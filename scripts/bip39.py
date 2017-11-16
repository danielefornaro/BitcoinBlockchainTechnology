# -*- coding: utf-8 -*-
"""
Created on Mon Oct 16 09:29:43 2017

@author: dfornaro
"""

from hashlib import sha256
import pbkdf2
import hmac
import hashlib
from hmac import HMAC


#b=os.urandom(10000)
#for i in range(0,12):
#    print(b[i])
#
#print(max(b))
#print(min(b))
#
#s=[0]*256
#for i in range(0,255):
#    s[i]=random.randint(0, 1)
    
#### suppose to have a Entropy input of 128 bits


def from_entropy_to_mnemonic(entropy, ENT):  
  entropy_bytes = entropy.to_bytes(int(ENT/8), byteorder='big')
  checksum = sha256(entropy_bytes).digest()
  checksum_int = int.from_bytes(checksum, byteorder='big')
  checksum_bin = bin(checksum_int)
  while len(checksum_bin)<258:
    checksum_bin = '0b0' + checksum_bin[2:]
  print("\n",checksum,"\n",type(checksum),checksum_bin)
  entropy_bin = bin(entropy)
  while len(entropy_bin)<ENT+2:
    entropy_bin = '0b0' + entropy_bin[2:]
  print("\nentropy bin",entropy_bin)
  entropy_checked = entropy_bin[2:] + checksum_bin[2:2+int(ENT/32)]
  print(entropy_checked)
  number_mnemonic = (ENT/32 + ENT)/11
  assert number_mnemonic %1 == 0
  number_mnemonic = int(number_mnemonic)
  mnemonic = [0]*number_mnemonic
  for i in range(0,number_mnemonic):
    mnemonic[i] = int(entropy_checked[i*11:(i+1)*11],2)
  return mnemonic

def from_mnemonic_to_seed(mnemonic, passphrase=''):
  PBKDF2_ROUNDS = 2048
  return pbkdf2.PBKDF2(mnemonic, 'mnemonic' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = hashlib.sha512).read(64).hex()


entropy=0x0c1e24e5917779d297e14d45f14e1a1a
entropy = 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f

ENT = 128
print(from_entropy_to_mnemonic(entropy, ENT))

#
#entropy='0c1e24e5917779d297e14d45f14e1a1a'
#checksum=sha256(entropy.encode()).hexdigest()
#
#entropy_base10 = [0]*int(len(entropy)/2)
#for i in range(0,int(len(entropy)/2)):
#    entropy_base10[i] = int(entropy[i*2:(i+1)*2],16)
#
#entropy_bytes = bytes(entropy_base10)
#
#checksum2=sha256(entropy_bytes).hexdigest()
#
#entropy_checked = entropy + checksum2[0]
#
#base2=''
#
#for i in range(0,33):
#  base10_entropy = int(entropy_checked[i],16)
#  base2_entropy = bin(base10_entropy)
#    
#  if len(base2_entropy)==6:
#    base2 = base2 + base2_entropy[2:6] 
#  elif len(base2_entropy)==5:
#    base2 = base2 + '0' + base2_entropy[2:5]
#  elif len(base2_entropy)==4:
#    base2 = base2 + '00' + base2_entropy[2:4]
#  elif len(base2_entropy)==3:
#    base2 = base2 + '000' + base2_entropy[2]
#


#checksum=sha256(base2.encode()).hexdigest()
#
#
#base10_checksum = int(checksum[0],16)
#base2_checksum = bin(base10_checksum)
#
#if len(base2_checksum)==6:
#    base2 = base2 + base2_checksum[2:6] 
#elif len(base2_checksum)==5:
#    base2 = base2 + '0' + base2_checksum[2:5]
#elif len(base2_checksum)==4:
#    base2 = base2 + '00' + base2_checksum[2:4]
#elif len(base2_checksum)==3:
#    base2 = base2 + '000' + base2_checksum[2]


#
#word = [0] * 12
#for i in range(0,12):
#  word[i] = int(base2[i*11 : (i+1)*11] , 2)
#
##print(word)
##### https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt ####
#
## these words corrispond to the follow mnemonic code
#    
#mnemonic= 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will'
#
#
#
#seed = from_mnemonic_to_seed(mnemonic)
#print(seed)
#seed_true = "b059400ce0f55498a5527667e77048bb482ff6daa16c37b4b9e8af70c85b3f4df588004f19812a1a027c9a51e5e94259a560268e91cd10e206451a129826e740"
#print(seed == seed_true)



