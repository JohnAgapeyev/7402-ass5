#!/bin/python3

import sys
import secrets

def pkcs7_pad(x):
    padding = 16 - ((len(x) % 16 != 0) * (len(x) % 16))
    return x + bytes([padding]) * padding

def pkcs7_strip(x):
    for i in range(x[-1]):
        if x[-(i + 1)] != x[-1]:
            raise ValueError('Input is not padded or padding is corrupt')
    return x[:-x[-1]]

#This is completely arbitrary, and bad
def f(i, k, x):
    for elem in x:
        elem *= i
        elem <<= k
    return x

def round(i, k, L, R):
    return R, [a ^ b for (a,b) in zip(L, f(i, k, R))]

def process_block(B, rounds, subkeys):
    #Split the block
    L, R = B[:8], B[8:]
    for j in rounds:
        L, R = round(j, subkeys[j], L, R)
    return R + L

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
        B = process_block(B, reversed(range(round_count)), subkeys[::-1])
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
        B = process_block(PB, reversed(range(round_count)), subkeys[::-1])
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
        B = [a ^ b for (a,b) in zip(B, encrypted_block)]
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
        encrypted_block = process_block(iv_block, reversed(range(round_count)), subkeys[::-1])
        #Xor the ciphertext in
        B = [a ^ b for (a,b) in zip(B, encrypted_block)]
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

    round_count = 8

    #Master secret key
    K = 7

    #Subkey generation, not really lol
    k = [K] * round_count

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
