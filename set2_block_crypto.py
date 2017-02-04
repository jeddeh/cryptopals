#!/usr/bin/python

import binascii
import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

dir_path = os.path.dirname(os.path.realpath(__file__))

# Challenge 9 - Implement PKCS#7 padding
print('Challenge 9')

def pad_block(plaintext, blocksize):
	return plaintext.ljust(blocksize, chr(04))

print('%s\n' % pad_block('YELLOW SUBMARINE', 20))

# Challenge 10 - Implement CBC mode
print('Challenge 10')

def str_xor(a, b):
	if len(a) != len(b):
		return 0
	
	return ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])  

def encrypt_aes_128_ecb(plaintext, key):
	plaintext = pad_block(plaintext, len(plaintext) + 16 - len(plaintext) % 16)
	aes_crypto = AES.new(key, AES.MODE_ECB)
	ct = aes_crypto.encrypt(plaintext)
	return ct

def decrypt_aes_128_ecb(ciphertext, key):
	aes_crypto = AES.new(key, AES.MODE_ECB)
	pt = aes_crypto.decrypt(ciphertext)
	pt = pt.strip(chr(4)) # remove padding
	return pt

with open(dir_path + '/challenge10.txt') as f:
	base64_ct = ''.join([x.strip() for x in f.readlines()])
	ct = binascii.a2b_base64(base64_ct)

iv = chr(0) * 16
key = 'YELLOW SUBMARINE'

def decrypt_aes_128_cbc(ciphertext, key, iv):
# Method:
# Get the first pt block by xor-ing the iv and the ecb decryption of the first 16 bytes of ct

# Get the second pt block by xor-ing the ecb decryption of the second 16 bytes of ct
# and the first 16 bytes of ct

	pt = []
	pt.append(str_xor(decrypt_aes_128_ecb(ciphertext[0:16], key), iv))

	for x in xrange(0, len(ciphertext) - 16, 16):
		pt_block = str_xor(decrypt_aes_128_ecb(ciphertext[x + 16:x + 32], key), ciphertext[x:x + 16])
		pt.append(pt_block)

	return ''.join(pt).strip(chr(4))

print(decrypt_aes_128_cbc(ct, key, iv))

# Challenge 11 - An ECB/CBC detection oracle
print('Chapter 11')

def get_random_key(num_bytes):
	rnd = Random.new()
	iv = rnd.read(num_bytes)
	return iv

def encryption_oracle(plaintext):
	key = get_random_key(16)
	
	rnd = Random.new()
	encryption_mode = random.randint(0,1)
	prepend_bytes = rnd.read(random.randint(5, 10))
	append_bytes = rnd.read(random.randint(5,10))

	plaintext = prepend_bytes + plaintext + append_bytes

	print encryption_mode
	print prepend_bytes
	print append_bytes	


	if encryption_mode == 0:
		ct = encrypt_aes_128_ecb(plaintext, key)
	else:
		ct = 0

	print ct
	return ct

for i in xrange(0, 10):
	print 'round %d' % i
	encryption_oracle('hello there')


