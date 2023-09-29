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

    def evil_pad(self, k, bytes):
        m = self.bytes_to_int(bytes)

        l = len(bytes) * 8 + k
        print("Evil Length:",l)
        k = (448 - l - 1) % 512

        print("K Padding:",k)

        m = self.append_bits(m, 1, 1)
        m = self.append_bits(m, 0, k)

        m = self.append_bits(m, 0, 64)
        m = m ^ l

        return self.int_to_bytes(m)
    
    def pad(self, bytes):
        m = self.bytes_to_int(bytes)

        l = len(bytes) * 8
        # print("Extension length:",l)
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
    
    def evil_hash(self, original, extension, start):
        padded_m = self.evil_pad(original, 128)
        evil_m = padded_m + extension
        padded_evil_m = self.evil_pad(evil_m, 128)

        M = self.parse(padded_evil_m)
        N = len(M)
        H = start
        
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

        return evil_m, ''.join([hex(x)[2:].zfill(8) for x in H])

# ===================================================
# Main
# ===================================================

if __name__ == "__main__":
    sha = SHA()

    # MAC = SHA-1(Key || Message).
    # len(key) = 128 bits
    # MAC = b30f8776 7a856960 fa8b3ed1 c0b6ecc7 77683e97
    # M(hex) = 4e6f206f6e652068617320636f6d706c657465642050726f6a65637420233320736f2067697665207468656d20616c6c206120302e
    
    original = b'No one has completed Project #3 so give them all a 0.'
    # original = b'Send Tina $100.'
    extension = b'P.S. Zack should pass the class immediately for being such a cool guy.'
    # extension = b'Also, send Malory $1M'

    MAC = [0xb30f8776, 0x7a856960, 0xfa8b3ed1, 0xc0b6ecc7, 0x77683e97]

    evil_m, evil_MAC = sha.evil_hash(original, extension, MAC)

    print("Evil Message:", evil_m)
    print("Evil MAC:", evil_MAC)