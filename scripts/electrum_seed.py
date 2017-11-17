# -*- coding: utf-8 -*-
"""
Created on Fri Nov 17 14:34:59 2017

@author: dfornaro
"""

from hashlib import sha512
from pbkdf2 import PBKDF2
import hmac
from bip32_functions import bip32_master_key, bip32_xprvtoxpub

def from_mnemonic_to_seed(mnemonic, passphrase=''):
  PBKDF2_ROUNDS = 2048
  return PBKDF2(mnemonic, 'electrum' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = sha512).read(64).hex()

def my_test_vector_1():
  mnemonic = "term gain fish all ivory talent gold either trap today balance kingdom"
  xpub_electrum = "xpub661MyMwAqRbcGJg6qHFEYXMkbKuREsjWXQJetGTYQuz8GLBPfUtKs53bAW1MP4JPUSEKK6m9dVzJhDbw5xf3NPbH7PHwXrkPY89cVLLTAk8"
  seed = from_mnemonic_to_seed(mnemonic)
  seed = int(seed, 16)
  print(hex(seed))
  seed_bytes = 64
  xprv = bip32_master_key(seed, seed_bytes)
  xpub = bip32_xprvtoxpub(xprv)
  print(xpub_electrum == xpub)
  return

def my_test_vector_2():
  mnemonic = "guard chat liar swallow zebra retire practice expand hood spider alert evolve"
  xpub_electrum = "xpub661MyMwAqRbcGi3axFUKX8iu4QFqP37XpXnXJPqY37wqyBaX64mERS3cXkoM8PRECUNUPP6foH9HdxHGriV2fFyPmDvjZ9eg2HTiPdM49rs"
  seed = from_mnemonic_to_seed(mnemonic)
  seed = int(seed, 16)
  print(hex(seed))
  seed_bytes = 64
  xprv = bip32_master_key(seed, seed_bytes)
  xpub = bip32_xprvtoxpub(xprv)
  print(xpub_electrum == xpub)
  return

def my_test_vector_3():
  mnemonic = "kind hazard heavy super novel book horn price bone misery moon depend"
  passphrase = "danielefornaro"
  xpub_electrum = "xpub661MyMwAqRbcFv1yFk3WaqMFpHUKNvn1qGDyJhdp7yL18V9pwibKWVUebSCzwPSMEioVWKzcyktvyMaYN3Lips4zyu5idw7keWi7pmZSfwq"
  seed = from_mnemonic_to_seed(mnemonic, passphrase)
  seed = int(seed, 16)
  print(hex(seed))
  seed_bytes = 64
  xprv = bip32_master_key(seed, seed_bytes)
  xpub = bip32_xprvtoxpub(xprv)
  print(xpub_electrum == xpub)
  return

my_test_vector_1()
my_test_vector_2()
my_test_vector_3()