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
    

    # ===================================================
    # Utility Functions
    # ===================================================

    def bytes_to_int(self, bytes):
        return int.from_bytes(bytes)
    
    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

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

    def pad(self, bytes):
        m = self.bytes_to_int(bytes)

        l = len(bytes) * 8
        k = (448 - l - 1) % 512

        m = self.append_bits(m, 1, 1)
        m = self.append_bits(m, 0, k)

        m = self.append_bits(m, 0, 64)
        m = m ^ l

        return self.int_to_bytes(m)
    
    # ===================================================
    # Message parsing
    # ===================================================

    def parse(self, bytes):
        # Parsed into N 512 bit blocks (16, 32 bit words)
        n = (len(bytes) * 8) // 512

        M = []

        for i in range(n):
            block = []
            for j in range(0, 64, 4):
                word = bytes[(64*i) + j: (64 * i) + j + 4]
                block.append(word)

            M.append(block)

        return M
    
    # ===================================================
    # SHA-1
    # ===================================================
    
    def sha(M):
        # Preprocessing

        # for i in range(M):


        # Hash Computation
        return

if __name__ == "__main__":
    print("Welcome to MAC attack")
    sha = SHA()
    
    # m = b'This is a test of SHA-1.'
    m = b"Kerckhoff's principle is the foundation on which modern cryptography is built."

    print("Message:     ", m)

    padded_m = sha.pad(m)
    print("Padded:      ", padded_m)

    print("Starting IV: ", sha.IV)

    parsed_m = sha.parse(padded_m)
    print("Parsed:      ", parsed_m)