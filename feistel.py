#!/bin/python3

import sys
import secrets
import random
import matplotlib.pyplot as plt

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

subkey_generator = hard_subkey
round_function = hard

def round(i, k, L, R):
    return R, [a ^ b for (a,b) in zip(L, round_function(i, k, R))]

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

def cbc_encrypt(plain, subkeys, iv=None):
    iv = iv if iv else bytearray(secrets.randbits(128).to_bytes(16, sys.byteorder))
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
    return plain, iv

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

def ctr_encrypt(plain, subkeys, iv=None):
    iv = iv if iv else secrets.randbits(128)
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
    return plain, iv

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

encrypt_function = ctr_encrypt
decrypt_function = ctr_decrypt

def run_test(mode, data):
    original = data

    #this is the base test case
    K = bytearray("yellow submarine", 'utf8')
    k = subkey_generator(K)

    #if there is an iv use it to seed the next call
    encrypt = None
    iv = None
    if mode in ['ctr','cbc']:
        encrypt, iv = encrypt_function(bytearray(original), k)
    else:
        encrypt = encrypt_function(bytearray(original), k)
    #flip one bit in the key and reencrypt
    K = bytearray("yellow sucmarine", 'utf8')
    k = subkey_generator(K)

    encrypt_key1 = None
    if iv:
        encrypt_key1 = encrypt_function(bytearray(original), k, iv)
    else:
        encrypt_key1 = encrypt_function(bytearray(original), k)

    def m1_n_avg(base, compare):
        m1 = []
        for index, byte in enumerate(base):
            if byte in compare:
                start = compare.index(byte)
                matching = 0
                for i in range(index, len(base)):
                    if base[i] == compare[i]:
                        matching += 1
                    else:
                        break
                    m1.append(matching)
        aml1 = sum(m1)/len(m1) if m1 else 0
        return m1, aml1

    #how many preserved multi byte sequences are there
    m1, aml1 = m1_n_avg(original, encrypt)

    m2, aml2 = m1_n_avg(encrypt, encrypt_key1)

    return m1, aml1, m2, aml2

funcmap ={
    "ecb":(ecb_encrypt, ecb_decrypt),
    "ctr":(ctr_encrypt, ctr_decrypt),
    "cbc":(cbc_encrypt, cbc_decrypt),
    "e":(easy_subkey, easy),
    "m":(medium_subkey, medium),
    "h":(hard_subkey, hard)
}
if __name__ == '__main__':
    def print_help():
        print('''usage:
    ./feistel.py [function] [mode] [quality] [input filename] [output filename]
            function is 'e' for encrypt, 'd' for decrypt
            mode is 'ecb' for ecb, 'cbc' for cbc, and 'ctr' for ctr
            quality is 'e' for easy, 'm' for medium, 'h' for hard

    ./feistel.py t [input filename]
            runs automated tests to compare the different modes using a given file''')
        sys.exit(1)
    if len(sys.argv) == 1:
        print_help()

    if sys.argv[1] == 't' and len(sys.argv) == 3:
        data = pkcs7_pad(bytearray(open(sys.argv[2], 'rb').read()))
        ms = []
        mks = []
        ms2 = []
        mks2 = []
        names=[]
        for mode in ['ecb', 'ctr', 'cbc']:
            for diff in ['e', 'm', 'h']:
                encrypt_function, decrypt_function = funcmap[mode]
                subkey_generator, round_function = funcmap[diff]
                m1, aml1, m2, aml2 = run_test(mode, bytearray(data))
                ms.append(len(m1))
                mks.append(aml1)
                ms2.append(len(m2))
                mks2.append(aml2)
                names.append(f'{mode}:{diff}')
                print(f'''
__/{mode} {diff}\__
==>diffusion<==
matches: {len(m1)}
average match len: {aml1}
==>confusion<==
matches: {len(m2)}
average match len: {aml2}
''')
        plt.style.use('dark_background')

        sp = plt.subplot(2,1,1)
        plt.title("Matches Per Mode")
        pm1 = plt.bar(names, ms, log=True, label='Confusion')
        pm2 = plt.bar(names, ms2, log=True, label='Diffusion')
        plt.legend([pm1, pm2], ['Confusion', 'Diffusion'])

        sp2 = plt.subplot(2,1,2)
        plt.title("Average Match Length")
        pl1 = plt.bar(names, mks, log=True, label='Confusion')
        pl2 = plt.bar(names, mks2, log=True, label='Diffusion')
        plt.legend([pl1, pl2], ['Confusion', 'Diffusion'])

        plt.show()

        sys.exit(0)
    if len(sys.argv[1:]) != 5:
        print_help()

    if sys.argv[2] in funcmap:
        encrypt_function, decrypt_function = funcmap[sys.argv[2]]
    else:
        print_help()

    if sys.argv[3] in funcmap:
        subkey_generator, round_function = funcmap[sys.argv[3]]
    else:
        print_help()

    k = subkey_generator(K)

    if sys.argv[1] == 'e':
        P = pkcs7_pad(bytearray(open(sys.argv[4], 'rb').read()))
        P = encrypt_function(P, k)
        with open(sys.argv[5], 'wb') as out:
            out.write(P)
    elif sys.argv[1] == 'd':
        P = bytearray(open(sys.argv[4], 'rb').read())
        if len(P) % 16 != 0:
            raise ValueError('Ciphertext is not a valid length, it must be corrupted')
        P = decrypt_function(P, k)
        with open(sys.argv[5], 'wb') as out:
            out.write(P)
    else:
        print_help()
