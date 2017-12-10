# -*- coding: utf-8 -*-
"""
Created on Fri Nov 17 14:34:59 2017

@author: dfornaro
"""

from hashlib import sha512
from pbkdf2 import PBKDF2
import hmac
from bip32_functions import bip32_master_key, bip32_xprvtoxpub, bip32_ckd
import binascii

def from_entropy_to_mnemonic_int_electrum(entropy, number_words):
  assert entropy < 2**(11*number_words)
  entropy_bin = bin(entropy)
  while len(entropy_bin)< number_words*11+2:
    entropy_bin = '0b0' + entropy_bin[2:]
  entropy_checked = entropy_bin[2:]
  mnemonic_int = [0]*number_words
  for i in range(0,number_words):
    mnemonic_int[i] = int(entropy_checked[i*11:(i+1)*11],2)
  return mnemonic_int

def from_mnemonic_int_to_mnemonic_electrum(mnemonic_int, dictionary_txt):
  dictionary  = open(dictionary_txt, 'r').readlines()
  mnemonic = ''
  for j in mnemonic_int:
    mnemonic = mnemonic + ' ' +  dictionary[j][:-1]
  mnemonic = mnemonic[1:]
  return mnemonic

def from_mnemonic_to_seed_eletrcum(mnemonic, passphrase=''):
  PBKDF2_ROUNDS = 2048
  return PBKDF2(mnemonic, 'electrum' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = sha512).read(64).hex()

def bh2u(x):
  return binascii.hexlify(x).decode('ascii')


def verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version = "standard", passphrase = ''):
  s = bh2u(hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).digest())
  seed = from_mnemonic_to_seed_eletrcum(mnemonic, passphrase)
  seed = int(seed, 16)
  seed_bytes = 64  
  if s[0:2] == '01':
    assert version == "standard"
    xprv = bip32_master_key(seed, seed_bytes)
  elif s[0:3] == '100':
    assert version == "segwit"
    xprv = bip32_master_key(seed, seed_bytes, b'\x04\xb2\x43\x0c')
    xprv = bip32_ckd(xprv, 0x80000000)
  else:
    print("\nVersion unknown")
    return False
  xpub = bip32_xprvtoxpub(xprv)
  assert xpub_electrum == xpub
  return seed

def verify_mnemonic_electrum(mnemonic, version = "standard"):
  s = bh2u(hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).digest()) 
  if s[0:2] == '01':
    return version == "standard"
  elif s[0:3] == '100':
    return version == "segwit"
  else:
    return False
  return True


def my_test_vector_1():
  mnemonic = "term gain fish all ivory talent gold either trap today balance kingdom"
  xpub_electrum = "xpub661MyMwAqRbcGJg6qHFEYXMkbKuREsjWXQJetGTYQuz8GLBPfUtKs53bAW1MP4JPUSEKK6m9dVzJhDbw5xf3NPbH7PHwXrkPY89cVLLTAk8"
  version = "standard"
  return verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version)

def my_test_vector_2():
  mnemonic = "guard chat liar swallow zebra retire practice expand hood spider alert evolve"
  xpub_electrum = "xpub661MyMwAqRbcGi3axFUKX8iu4QFqP37XpXnXJPqY37wqyBaX64mERS3cXkoM8PRECUNUPP6foH9HdxHGriV2fFyPmDvjZ9eg2HTiPdM49rs"
  version = "standard"
  return verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version)

def my_test_vector_3():
  mnemonic = "kind hazard heavy super novel book horn price bone misery moon depend"
  passphrase = "danielefornaro"
  xpub_electrum = "xpub661MyMwAqRbcFv1yFk3WaqMFpHUKNvn1qGDyJhdp7yL18V9pwibKWVUebSCzwPSMEioVWKzcyktvyMaYN3Lips4zyu5idw7keWi7pmZSfwq"
  version = "standard"
  return verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version, passphrase)

def my_test_vector_4():
  mnemonic = "glad shoulder possible elder route remind suit unable hedgehog pistol era define"
  xpub_electrum = "zpub6nnNomZvczQDUvRZh1xThQTcSaV54NJiQBhvswqC5jG32fWm2LnURBDSM1Argj2B2fR6xAKEAMj1PuZ2wEZzjGZcbAPhbGa2RtDoMKaTE7L"
  version = "segwit"
  return verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version)

def my_test_vector_5():
  mnemonic = "slogan detect embark famous flip middle impact normal price artwork program power"
  passphrase = "danielefornaro"
  xpub_electrum = "zpub6nC6GjnipUB41rp3yS2TozLkyoHiR4jCHJiZ69GhsJRNEeXJR63fV5sCoHTkhc999fevr5S78b6XPydetbe5w2b5HHpUoWCLHCfe55VknvX"
  version = "segwit"
  return verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version, passphrase)

def my_test_vector_6():
  mnemonic = "miss mixed vibrant cheap riot comfort pulse forum pet injury slogan fame"
  passphrase = "fatti non foste a viver come bruti"
  xpub_electrum = "zpub6nfRLg2gunSr2LyRpGxzW5pdrvtHxLS5JzNtGWdef5M7wKs3m4CiyzPDe3zXGFLqABKK1gA41mXgKq3jyfgcH4nsCzWfBVsPSpJvFEDCUzT"
  version = "segwit"
  return verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version, passphrase)



def test_vector():
  my_test_vector_1()
  my_test_vector_2()
  my_test_vector_3()
  my_test_vector_4()
  my_test_vector_5()
  my_test_vector_6()
  
  
test_vector()