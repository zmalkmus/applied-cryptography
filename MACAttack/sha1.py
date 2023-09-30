import sys
import os

# ================CHANGE MAC HERE===================
MAC = 0x0813e52e87dad8c25ac59e078fb476d2217f57c8
# ==================================================

class SHA:

    # ====================================================
    # Initialize SHA
    # ====================================================

    def __init__(self):

        self.key = os.urandom(16)

        self.IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

        return

    # ===================================================
    # Utility Functions
    # ===================================================

    def bytes_to_int(self, bytes):
        return int.from_bytes(bytes)
    
    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

    # ===================================================
    # Padding
    # ===================================================

    def pad(self, bytes):
        l = len(bytes) * 8
        k = (448 - l - 1) % 512

        return bytes + b'\x80' + b'\x00'*(k//8) + l.to_bytes(8)
    
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
                word = self.bytes_to_int(bytes[((64*i) + j) : ((64 * i) + j + 4)])
                block.append(word)

            M.append(block)
        return M
    
    # ===================================================
    # Messaging Schedule
    # ===================================================

    def F(self, t, x, y, z):
        if   (0 <= t < 20):  return (x & y) ^ (~x & z)
        elif (20 <= t < 40): return (x ^ y ^ z)
        elif (40 <= t < 60): return (x & y) ^ (x & z) ^ (y & z)
        elif (60 <= t < 80): return (x ^ y ^ z)
        else: sys.exit("F: bad t")

    def K(self, t):
        if   (0 <= t < 20):  return 0x5a827999
        elif (20 <= t < 40): return 0x6ed9eba1
        elif (40 <= t < 60): return 0x8f1bbcdc
        elif (60 <= t < 80): return 0xca62c1d6
        else: sys.exit("K: bad t")

    def ROTL(self, val, n):
        return (val << n | val >> (32-n)) & 0xFFFFFFFF
    
    def hash(self, m, extension=None, state=None, klen=None):
        M = self.parse(m)
        N = len(M)
        H = self.IV.copy() if state == None else state.copy()
        
        for i in range(N):
            # 1
            W = [0] * 80
            for t in range(16):
                W[t] = M[i][t]
            for t in range(16,80):
                W[t] = self.ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)

            # 2
            a = H[0]
            b = H[1]
            c = H[2]
            d = H[3]
            e = H[4]

            # 3
            for t in range(80):
                temp = (self.ROTL(a, 5) + self.F(t, b, c, d) + e + self.K(t) + W[t]) & 0xFFFFFFFF
                e = d
                d = c
                c = self.ROTL(b, 30)
                b = a
                a = temp

            # 4
            H[0] = (a + H[0]) & 0xFFFFFFFF
            H[1] = (b + H[1]) & 0xFFFFFFFF
            H[2] = (c + H[2]) & 0xFFFFFFFF
            H[3] = (d + H[3]) & 0xFFFFFFFF
            H[4] = (e + H[4]) & 0xFFFFFFFF

        return ''.join([hex(x)[2:].zfill(8) for x in H])

# ===================================================
# Main
# ===================================================

if __name__ == "__main__":
    sha = SHA()
    
    # ===================================================
    # Part 1: SHA-1
    # ===================================================

    print("\n================ PART 1 ================\n")

    m1 = sha.pad(b'This is a test of SHA-1.')
    m2 = sha.pad(b"Kerckhoff's principle is the foundation on which modern cryptography is built.")
    m3 = sha.pad(b'SHA-1 is no longer considered a secure hashing algorithm.')
    m4 = sha.pad(b'SHA-2 or SHA-3 should be used in place of SHA-1.')
    m5 = sha.pad(b'Never roll your own crypto!')
    
    d1 = sha.hash(m1)
    d2 = sha.hash(m2)
    d3 = sha.hash(m3)
    d4 = sha.hash(m4)
    d5 = sha.hash(m5)

    print(d1)
    print(d2)
    print(d3)
    print(d4)
    print(d5)

    # ===================================================
    # Part 2: MAC ATTACK
    # ===================================================

    print("\n================ PART 2 ================\n")

    m = b'No one has completed Project #3 so give them all a 0.'
    extension = b'P.S. Zack should pass the class immediately with an A for being such a cool guy.'

    b0 = sha.pad(sha.key + m)
    b1 = sha.pad(b0 + extension)[len(b0):]
    
    H = [0] * 5

    H[0] = (MAC >> 128) & 0xFFFFFFFF
    H[1] = (MAC >> 96)  & 0xFFFFFFFF
    H[2] = (MAC >> 64)  & 0xFFFFFFFF
    H[3] = (MAC >> 32)  & 0xFFFFFFFF
    H[4] = (MAC >> 0)   & 0xFFFFFFFF

    hash_malicious = sha.hash(b1, state=H)
    evil_m = (b0 + extension)[16:]

    print("MAL_MESSAGE:",evil_m.hex())
    print("\nMAL_HASH:", hash_malicious)