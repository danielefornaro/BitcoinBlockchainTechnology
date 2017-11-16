# -*- coding: utf-8 -*-
"""
Created on Thu Nov 16 16:04:32 2017

@author: dfornaro
"""

import hashlib, re
from binascii import hexlify, unhexlify

# get the 2048 word wordlist
def get_wordlist():

    # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
  BIP0039_ENG_WORDLIST = make_request("https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt").split('\n')
  assert len(BIP0039_ENG_WORDLIST) == 2048
  return BIP0039_ENG_WORDLIST

BIP39WORDS = get_wordlist()