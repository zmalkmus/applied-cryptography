import struct
import binascii
import numpy as np

class SHA:

    # ====================================================
    # Initialize SHA
    # ====================================================

    def __init__(self):

        self.IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

        return

    # ====================================================
    # SHA Functions
    # ====================================================

    def sha_function(self, t, x, y, z):
        try:
            if (0 <= t < 20):
                return self.ch(x, y, z)
            elif (t < 40):
                return self.parity(x, y, z)
            elif (t < 60):
                return self.maj(x, y, z)
            elif (t < 80):
                return self.parity(x, y, z)
            else:
                raise Exception("t not in range.")
        except Exception as e:
            print(f"SHA_FUNCTION: {e}")
            exit(1)

    def ch(self, x, y, z):
        return (x ^ y) ^ (~x ^ z)

    def parity(self, x, y, z):
        return (x ^ y ^ z)

    def maj(self, x, y, z):
        return (x ^ y) ^ (x ^ z) ^ (y ^ z)

    # ====================================================
    # SHA Konstants
    # ====================================================

    def K(self, t):
        try:
            if (0 <= t < 20):
                return 0x5a827999
            elif (t < 40):
                return 0x6ed9eba1
            elif (t < 60):
                return 0x8f1bbcdc
            elif (t < 80):
                return 0xca62c1d6
            else:
                raise Exception("t not in range.")
        except Exception as e:
            print(f"K: {e}")
            exit(1)

    # ===================================================
    # Padding
    # ===================================================

    def append_bits(self, word, b, n):
        for i in range(n):
            word = (word << 1) | b
        return word

    def sha_pad(self, s):
        m = self.str_to_int(s)

        l = len(s) * 8
        k = 448 % 512 - l - 1

        m = self.append_bits(m, 1, 1)
        m = self.append_bits(m, 0, k)

        m = self.append_bits(m, 0, 64)
        m = m ^ l

        # print("l:", l)

        # print(m.bit_length())

        return m
    
    # ===================================================
    # Message parsing
    # ===================================================

    def parse_message(self, m):
        # Parsed into N 512 bit blocks
        return
    
    # ===================================================
    # Messaging Schedule
    # ===================================================



    # ===================================================
    # Utility Functions
    # ===================================================

    def bytes_to_int(self, bytes):
        return int(bytes, 16)

    def int_to_bytes(self, integer):
        return integer.to_bytes()

    def str_to_int(self, str):
        encoded_bytes = str.encode('utf-8')
        return int(binascii.hexlify(encoded_bytes), 16)
    

if __name__ == "__main__":
    print("Welcome to MAC attack")
    sha = SHA()
    print(bin(sha.sha_pad("abc")))
    # print(bin(sha.append_bits(0b1111, 0, 4)))