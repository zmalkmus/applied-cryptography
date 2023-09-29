import sys

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

    def ROTL(self, n, val):
        return (val << n | val >> (32-n)) & 0xFFFFFFFF
    
    def hash(self, m):
        padded_m = self.pad(m)
        M = self.parse(padded_m)
        N = len(M)
        H = self.IV.copy()
        
        for i in range(N):
            # 1
            W = [0] * 80
            for t in range(16):
                W[t] = M[i][t]
            for t in range(16,80):
                W[t] = self.ROTL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])

            # 2
            a = H[0]
            b = H[1]
            c = H[2]
            d = H[3]
            e = H[4]

            # 3
            for t in range(80):
                temp = (self.ROTL(5, a) + self.F(t, b, c, d) + e + self.K(t) + W[t]) & 0xFFFFFFFF
                e = d
                d = c
                c = self.ROTL(30, b)
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
    
    m1 = b'This is a test of SHA-1.'
    m2 = b"Kerckhoff's principle is the foundation on which modern cryptography is built."
    m3 = b'SHA-1 is no longer considered a secure hashing algorithm.'
    m4 = b'SHA-2 or SHA-3 should be used in place of SHA-1.'
    m5 = b'Never roll your own crypto!'
    
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