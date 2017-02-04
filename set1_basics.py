#!/usr/bin/python

import binascii
import os
from Crypto.Cipher import AES

dir_path = os.path.dirname(os.path.realpath(__file__))

# Challenge 1 - Hex to Base64
print('Challenge 1')

def hex_to_base64(hexstring):
	return binascii.b2a_base64(binascii.unhexlify(hexstring))

hexstring = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
print(hex_to_base64(hexstring))

# Challenge 2 - Fixed XOR
print('Challenge 2')

# Function to XOR two hex strings of equal length
def hex_xor(a, b):
	if (len(a) != len(b)) or len(a) % 2 != 0:
		return 0

	a_ascii = binascii.unhexlify(a)
	b_ascii = binascii.unhexlify(b)
	xor_ascii =  ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a_ascii, b_ascii)])
	
	return binascii.hexlify(xor_ascii)  

    # return ''.join([(hex(int(x, 16) ^ int(y, 16)))[2:] for (x, y) in zip(a, b)])

a = '1c0111001f010100061a024b53535009181c'
b = '686974207468652062756c6c277320657965'
result = hex_xor(a, b)
print('%s\n' % result)

# Challenge 3 - Single-byte XOR cipher
print('Challenge 3')
hexstring = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
charstring = binascii.unhexlify(hexstring)

freq = {
' ':10, # (estimate)
'a':8.167,
'b':1.492,
'c':2.782,	
'd':4.253,	
'e':12.70,	
'f':2.228,	
'g':2.015,	
'h':6.094,	
'i':6.966,	
'j':0.153,	
'k':0.772,	
'l':4.025,	
'm':2.406,	
'n':6.749,	
'o':7.507,	
'p':1.929,	
'q':0.095,	
'r':5.987,	
's':6.327,	
't':9.056,	
'u':2.758,	
'v':0.978,	
'w':2.360,	
'x':0.150,	
'y':1.974,	
'z':0.074
}

def testDecryption(charstring, charNum):
	return ''.join([chr(ord(x) ^ charNum) for x in charstring])

def scorePlaintext(pt):
	return sum([freq.get(x, -1) for x in pt])

bestScore = 0
bestCharNum = 0

for x in xrange(ord('A'), ord('z') + 1):
	plaintext = testDecryption(charstring, x)
	score = scorePlaintext(plaintext.lower())

	if (score > bestScore):
		bestScore = score
		bestCharNum = x

print('Key is %s\nScore is %d\n%s\n' % (chr(bestCharNum), bestScore, testDecryption(charstring, bestCharNum)))

# Challenge 4 - Detect single-character XOR
print('Challenge 4')

with open(dir_path + '/challenge4.txt', 'r') as f:
	bestScore = 0
	bestCharNum = 0
	bestLine = ''
	bestLineNum = 0

	for line in f:
		bestLineNum += 1
		charstring = binascii.unhexlify(line.strip())

		for x in xrange(0, 256):
			plaintext = testDecryption(charstring, x)
			score = scorePlaintext(plaintext.lower())

			if (score > bestScore):
				bestScore = score
				bestCharNum = x
				bestLine = charstring

print('Key is %s\nScore is %d\nLine is %d\n%s' % (bestCharNum, bestScore, bestLineNum, testDecryption(bestLine, bestCharNum)))

# Challenge 5 - Implement repeating-key XOR
print('Challenge 5')

dir_path = os.path.dirname(os.path.realpath(__file__))
key = 'ICE'
index = 0
ct = []

with open(dir_path + '/challenge5.txt', 'r') as f:
	for line in f:		
		for char in line:
			ct.append(binascii.hexlify(chr(ord(key[index]) ^ ord(char))))
			index = (index + 1) % len(key)

print(''.join(ct))
print

# Challenge 6 - Break repeating-key XOR
print('Challenge 6')

ct = ''
with open(dir_path + '/challenge6.txt') as f:
	hex_ct = ''.join([x.strip() for x in f.readlines()])
	ct = binascii.a2b_base64(hex_ct)

# The Hamming distance is just the number of differing bits.
def getHammingDistance(a, b):
	diff = [bin(ord(x) ^ ord(y)) for (x, y) in zip(a, b)]
	return ''.join(diff).count('1')

def testHammingDistance():
	print(getHammingDistance('this is a test', 'wokka wokka!!!'))

# testHammingDistance()

print('Length of ciphertext is %s' % len(ct))

best_keysize = 0
best_norm_dist = 10000

for keysize in xrange(2, 41):
	norm_dist = 0
	
	for start in xrange (0, 71):
		block_1 = ct[start * keysize:(start + 1) * keysize]
		block_2 = ct[(start + 1) * keysize:(start + 2) * keysize]
		norm_dist += getHammingDistance(block_1, block_2) / float(keysize)
		
	if (norm_dist < best_norm_dist):
		best_norm_dist = norm_dist
		best_keysize = keysize

	# print 'Keysize %d - Distance %f' % (keysize, norm_dist)

print('\nProbable keysize %d - Distance %f\n' % (best_keysize, best_norm_dist))

# Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
ct_blocks = []

for x in xrange(0, len(ct), best_keysize):
	ct_blocks.append(ct[x:x + best_keysize])

# print [len(x) for x in ct_blocks]
# print 'Checking total blocks length - %d' % sum([len(x) for x in ct_blocks])

ct_blocks = ct_blocks[:len(ct_blocks) - 1] # delete last block

# Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
ct_trans = map(list, zip(*ct_blocks))

# print [len(x) for x in trans]

# Solve each block as if it was single-character XOR. You already have code to do this.
key = ''

for i in xrange(0, len(ct_trans)):
	bestScore = 0
	bestCharNum = 0
	
	for x in xrange(0, 256):
		plaintext = testDecryption(ct_trans[i], x)
		score = scorePlaintext(plaintext.lower())

		if (score > bestScore):
			bestScore = score
			bestCharNum = x

	key = key + chr(bestCharNum)
	# print 'Best score - %d, best chr - %s' % (bestScore, chr(bestCharNum))

print('%s\n' % key)
print(len(key))

# Get the plaintext
index = 0
pt = ''

for char in ct:
	pt = pt + chr(ord(key[index]) ^ ord(char))
	index = (index + 1) % len(key)

print(pt)

# Challenge 7 - AES in ECB mode
# See https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.CipherContext
print('Challenge 7')

key = 'YELLOW SUBMARINE'
ct = ''

with open(dir_path + '/challenge7.txt') as f:
	base64_ct = ''.join([x.strip() for x in f.readlines()])
	ct = binascii.a2b_base64(base64_ct)

# with (open(dir_path + '/challenge7_ct.txt', 'w')) as f:
# 	f.write(ct)

# openssl aes-128-ecb -d -in challenge7_ct.txt -out challenge7_pt.txt -K 59454c4c4f57205355424d4152494e45

def decrypt_aes_128_ecb(ciphertext, key):
	aes_crypto = AES.new(key, AES.MODE_ECB)
	pt = aes_crypto.decrypt(ciphertext)
	pt = pt.strip(chr(4)) # remove padding
	return pt

print(decrypt_aes_128_ecb(ct, 'YELLOW SUBMARINE'))

# Challenge 8 - Detect AES in ECB mode
print('Challenge 8')

with (open(dir_path + '/challenge8.txt')) as f:
	hex_ct = [x.strip() for x in f.readlines()]

for ct_line in hex_ct:
	num_identical_blocks = [ct_line.count(ct_line[x:x + 16]) for x in range(0, len(ct_line), 16)]
	
	if max(num_identical_blocks) > 1:
		print(ct_line)
		print(num_identical_blocks)

