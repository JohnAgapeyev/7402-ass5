#!/bin/python3

import sys
import secrets
import random

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

round_count = 8

#Master secret key
#Keeping it fixed for simplicity, and to avoid having to pad/KDF the thing
K = bytearray("yellow submarine", 'utf8')

def pkcs7_pad(x):
    padding = 16 - ((len(x) % 16 != 0) * (len(x) % 16))
    return x + bytes([padding]) * padding

def pkcs7_strip(x):
    for i in range(x[-1]):
        if x[-(i + 1)] != x[-1]:
            raise ValueError('Input is not padded or padding is corrupt')
    return x[:-x[-1]]

#This is completely arbitrary, and bad
def easy(i, k, x):
    x = bytearray(x)
    for j in range(len(x)):
        x[j] = (x[j] * i) & 0xff
        x[j] = (x[j] << k[i]) & 0xff
    return x

def rotate_byte(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff;

#This is solidly amateur, but I obviously lack the capability to analyze/break it
def medium(i, k, x):
    x = bytearray(x)
    random.Random(i).shuffle(x)
    #Since I know this will be 8 bytes, I can use it for bitslicing majority function
    for j in range(len(x)):
        for n in range(8):
            count = 0
            for elem in x:
                count += (elem & (1 << j)) != 0
            x[j] ^= (-(count >= 0) ^ x[j]) & (1 << n)
        x[j] = (x[j] + x[i]) & 0xff
        x[j] = rotate_byte(x[j], i)
        x[j] = x[j] ^ k[j]
        x[j] = rotate_byte(x[j], 3)
        x[j] = (x[j] + k[j+8]) & 0xff
        for kb in k:
            x[j] = rotate_byte(((x[j] ^ kb) + 0x3a) & 0xff, 7)
        random.Random(j).shuffle(x)
    random.Random(-i).shuffle(x)
    return x

#This is actually secure, just a waste of time
def hard(i, k, x):
    return bytearray(AES.new(k, AES.MODE_CTR, nonce=bytes([i])*8).encrypt(bytearray(x)))

def easy_subkey(master):
    k = []
    for i in range(round_count):
        x = bytearray([a ^ b for (a,b) in zip(master, [i]*16)])
        k.append(x);
    return k

def medium_subkey(master):
    k = []
    for i in range(round_count):
        tmp_master = master
        for j in range(len(tmp_master)):
            random.Random(j).shuffle(tmp_master)
            tmp_master[j] = rotate_byte(tmp_master[j], tmp_master[i] % 8)
            tmp_master[j] = tmp_master[j] ^ 0xc3
            random.Random(j).shuffle(tmp_master)
            tmp_master[j] = rotate_byte(tmp_master[len(tmp_master) - j - 1], random.Random(sum(tmp_master)).getrandbits(3))
            tmp_master[j] = (tmp_master[j] + (i * 176)) & 0xff
        random.Random(i).shuffle(tmp_master)
        k.append(bytearray(tmp_master));
    return k

def hard_subkey(master):
    k = []
    for i in range(round_count):
        h = HMAC.new(master, digestmod=SHA256)
        h.update(bytearray([i]*16))
        k.append(bytearray(h.digest()[:16]))
    return k

def round(i, k, L, R):
    return R, [a ^ b for (a,b) in zip(L, hard(i, k, R))]

def process_block(B, rounds, subkeys):
    #Split the block
    L, R = B[:8], B[8:]
    for j in rounds:
        L, R = round(j, subkeys[j], L, R)
    return bytearray(R + L)

def ecb_encrypt(plain, subkeys):
    #i is block num
    for i in range(len(plain) // 16):
        start_block = i * 16
        end_block = start_block + 16
        #Grab the block
        B = plain[start_block : end_block]
        B = process_block(B, range(round_count), subkeys)
        #Write the block back
        plain[start_block : end_block] = B
    return plain

def ecb_decrypt(plain, subkeys):
    #i is block num
    for i in range(len(plain) // 16):
        start_block = i * 16
        end_block = start_block + 16
        #Grab the block
        B = plain[start_block : end_block]
        B = process_block(B, reversed(range(round_count)), subkeys)
        #Write the block back
        plain[start_block : end_block] = B
    plain = pkcs7_strip(plain)
    return plain

def cbc_encrypt(plain, subkeys):
    iv = bytearray(secrets.randbits(128).to_bytes(16, sys.byteorder))
    plain = iv + plain
    prev = iv
    for i in range(1, len(plain) // 16):
        start_block = i * 16
        end_block = start_block + 16
        #Grab the block
        B = plain[start_block : end_block]
        #Xor the iv in
        B = [a ^ b for (a,b) in zip(B, prev)]
        B = process_block(B, range(round_count), subkeys)
        #Save the resulting block as the "new" iv
        prev = B
        #Write the block back
        plain[start_block : end_block] = B
    return plain

def cbc_decrypt(plain, subkeys):
    if len(plain) < 32:
        raise ValueError('Input is not padded or does not contain an IV')
    iv = plain[:16]
    prev = iv
    #i is block num
    for i in range(1, len(plain) // 16):
        start_block = i * 16
        end_block = start_block + 16
        #Grab the block
        PB = plain[start_block : end_block]
        B = process_block(PB, reversed(range(round_count)), subkeys)
        #Xor the iv in
        B = [a ^ b for (a,b) in zip(B, prev)]
        #Save the resulting block as the "new" iv
        prev = PB
        #Write the block back
        plain[start_block : end_block] = B
    plain = pkcs7_strip(plain)
    return plain[16:]

def ctr_encrypt(plain, subkeys):
    iv = secrets.randbits(128)
    plain = bytearray(iv.to_bytes(16, sys.byteorder)) + plain
    #i is block num
    for i in range(1, len(plain) // 16):
        start_block = i * 16
        end_block = start_block + 16
        #Grab the block
        B = plain[start_block : end_block]
        iv_block = bytearray((iv + i).to_bytes(16, sys.byteorder))
        encrypted_block = process_block(iv_block, range(round_count), subkeys)
        #Xor the ciphertext in
        B = bytearray([a ^ b for (a,b) in zip(B, encrypted_block)])
        #Write the block back
        plain[start_block : end_block] = B
    return plain

def ctr_decrypt(plain, subkeys):
    if len(plain) < 32:
        raise ValueError('Input is not padded or does not contain an IV')
    iv = int.from_bytes(plain[:16], byteorder=sys.byteorder, signed=False)
    #i is block num
    for i in range(1, len(plain) // 16):
        start_block = i * 16
        end_block = start_block + 16
        #Grab the block
        B = plain[start_block : end_block]
        iv_block = bytearray((iv + i).to_bytes(16, sys.byteorder))
        encrypted_block = process_block(iv_block, range(round_count), subkeys)
        #Xor the ciphertext in
        B = bytearray([a ^ b for (a,b) in zip(B, encrypted_block)])
        #Write the block back
        plain[start_block : end_block] = B
    plain = pkcs7_strip(plain)
    return plain[16:]

# Args are [mode] [input filename] [output filename]
# mode is 'e' for encrypt, else decrypt
if __name__ == '__main__':
    if len(sys.argv[1:]) != 3:
        print("give me args!")
        sys.exit(1)

    #k = easy_subkey(K)
    #k = medium_subkey(K)
    k = hard_subkey(K)

    if sys.argv[1] == 'e':
        P = pkcs7_pad(bytearray(open(sys.argv[2], 'rb').read()))
        #P = ecb_encrypt(P, k);
        #P = cbc_encrypt(P, k);
        P = ctr_encrypt(P, k);
        with open(sys.argv[3], 'wb') as out:
            out.write(P)
    else:
        P = bytearray(open(sys.argv[2], 'rb').read())
        if len(P) % 16 != 0:
            raise ValueError('Ciphertext is not a valid length, it must be corrupted')
        #P = ecb_decrypt(P, k)
        #P = cbc_decrypt(P, k)
        P = ctr_decrypt(P, k)
        with open(sys.argv[3], 'wb') as out:
            out.write(P)
