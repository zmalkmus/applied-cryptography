import secrets     # Cryptography library. RNG
import numpy as np # Math

class AES:

    # =============================================
    # Constructor
    # =============================================

    def __init__(self, numBits=None, key=None):
        # Error check input
        if (numBits not in [128,192,256]):
            print("Invalid cipher key length. Exiting.")
            exit()

        if (key != None and len(key) != numBits/8):
            print(len(key))
            print("Invalid key length. Exiting.")
            exit()

        # Initialize class variables
        self.rcon = [ 
           0x00000000,
           0x01000000, 0x02000000, 0x04000000, 0x08000000,
           0x10000000, 0x20000000, 0x40000000, 0x80000000,
           0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
           0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000,
           0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
           0x97000000, 0x35000000, 0x6A000000, 0xD4000000,
           0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000,
           0xC5000000, 0x91000000, 0x39000000, 0x72000000,
           0xE4000000, 0xD3000000, 0xBD000000, 0x61000000,
           0xC2000000, 0x9F000000, 0x25000000, 0x4A000000,
           0x94000000, 0x33000000, 0x66000000, 0xCC000000,
           0x83000000, 0x1D000000, 0x3A000000, 0x74000000,
           0xE8000000, 0xCB000000, 0x8D000000
        ]
        self.sBox = [
            [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 ],          
            [ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 ],
            [ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 ],
            [ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 ],
            [ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 ],
            [ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf ],
            [ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 ],
            [ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 ],
            [ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 ],
            [ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb ],
            [ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 ],
            [ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 ],
            [ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a ],
            [ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e ],
            [ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf ],
            [ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
        ]
        self.iSBox = [
            [ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb ],
            [ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb ],
            [ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e ],
            [ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 ],
            [ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 ],
            [ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 ],
            [ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 ],
            [ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b ],
            [ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 ],
            [ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e ],
            [ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ],
            [ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 ],
            [ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f ],
            [ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef ],
            [ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 ],
            [ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d ]
        ]

        self.key = self.generateRandomBytes(round(numBits/8)) if key == None else key
        self.nk  = round(numBits/32)
        self.nb  = 4    
        self.nr  = {128:10, 192:12, 256:14}[numBits]
        self.w   = self.keyExpansion()
        
        return


    # Created a method in case I want to change how I generate bytes later
    def generateRandomBytes(self, n):
        return secrets.token_bytes(n)

    # =============================================
    # Finite Field Arithmetic
    # =============================================
    def ffAdd(self, a, b):
        return a ^ b

    def xtime(self, a):
        a <<= 1

        if (a & 0x100):
            a = (a ^ 0x1b) & 0xff

        return a
    
    def ffMultiply(self, a, b):
        sum = 0

        for i in range(8):
            
            if (a & (1 << i)):
                sum ^= b

            if (i != 7):
                b = self.xtime(b)

        return sum
    
    # =============================================
    # Key Expansion
    # =============================================

    def subWord(self, word):
        out_ = 0

        for i in range(4):
            shift = i*8
            
            # Get the row and column of the sBox
            c = (word >> shift) & 0x0f
            r = (word >> shift + 4) & 0x0f
            out_ += self.sBox[r][c] << shift

        return out_

    def rotWord(self, word):
        a_0 = (word >> 24) & 0xff
        a_1 = (word >> 16) & 0xff
        a_2 = (word >> 8)  & 0xff
        a_3 = (word >> 0)  & 0xff

        return (a_1 << 24) + (a_2 << 16) + (a_3 << 8) + (a_0 << 0)
    
    def keyExpansion(self):
        w = [0] * (self.nb * (self.nr + 1))

        # Key expansion as described in FIPS 197 Figure 11
        i = 0
        while (i < self.nk):
            a = self.key[4*i]
            b = self.key[4*i+1]
            c = self.key[4*i+2]
            d = self.key[4*i+3]

            w[i] = (a << 24) + (b << 16) + (c << 8) + d
            i += 1

        i = self.nk

        while (i < self.nb * (self.nr + 1)):
            temp = w[i-1]

            if (i % self.nk == 0):
                temp = self.subWord(self.rotWord(temp)) ^ self.rcon[round(i/self.nk)]
            elif (self.nk > 6 and i % self.nk == 4):
                temp = self.subWord(temp)

            w[i] = w[i-self.nk] ^ temp
            i += 1
        
        return w
    
    # =============================================
    # Cipher
    # =============================================

    def cipher(self, plaintext, w):
        # Cipher Algorithm as described in FIPS 197 Figure 5

        print("CIPHER (ENCRYPT):")

        state = self.generateStateMatrix(plaintext)
        print("round[ 0].input    ", self.getStateString(state))

        state = self.addRoundKey(state, w[0:self.nb], 0)

        for r in range(1, self.nr):
            print("round[{:2d}].start    ".format(r), self.getStateString(state))
            state = self.subBytes(state, r)
            state = self.shiftRows(state, r)
            state = self.mixColumns(state, r)
            state = self.addRoundKey(state, w[r*self.nb:(r+1)*self.nb], r)

        print("round[{:2d}].start    ".format(self.nr), self.getStateString(state))

        state = self.subBytes(state, self.nr)
        state = self.shiftRows(state, self.nr)
        state = self.addRoundKey(state, w[self.nr*self.nb:(self.nr+1)*self.nb], self.nr)

        print("round[{:2d}].output   ".format(self.nr), self.getStateString(state))
        print("")

        return self.generateBytesFromState(state)
    
    def subBytes(self, state, r=None):
        out_ = np.zeros((4, 4), dtype=int)

        for i in range(len(state)):
            for j in range(len(state[i])):
                col = state[i][j] & 0x0f
                row = state[i][j] >> 4 & 0x0f
                out_[i][j] = self.sBox[row][col]

        if (r != None):
            print("round[{:2d}].s_box    ".format(r), self.getStateString(out_))

        return out_
    
    def shiftRows(self, state, r=None):
        out_ = np.zeros((4, 4), dtype=int)

        out_[0] = state[0]
        out_[1] = np.roll(state[1], -1)
        out_[2] = np.roll(state[2], -2)
        out_[3] = np.roll(state[3], -3)

        if (r != None):
            print("round[{:2d}].s_row    ".format(r), self.getStateString(out_))

        return out_
    
    def mixColumns(self, state, r=None):
        out_ = np.zeros((4, 4), dtype=int)

        for c in range(self.nb):
            out_[0,c] = self.ffMultiply(0x02, state[0,c]) ^ self.ffMultiply(0x03, state[1,c]) ^ state[2,c] ^ state[3,c]
            out_[1,c] = state[0,c] ^ self.ffMultiply(0x02, state[1,c]) ^ self.ffMultiply(0x03, state[2,c]) ^ state[3,c]
            out_[2,c] = state[0,c] ^ state[1,c] ^ self.ffMultiply(0x02, state[2,c]) ^ self.ffMultiply(0x03, state[3,c])
            out_[3,c] = self.ffMultiply(0x03, state[0,c]) ^ state[1,c] ^ state[2,c] ^ self.ffMultiply(0x02, state[3,c])

        if (r != None):
            print("round[{:2d}].m_col    ".format(r), self.getStateString(out_))

        return out_
    
    def addRoundKey(self, state, roundKey, r=None, inv=False):
        out_ = np.zeros((4, 4), dtype=int)

        for i in range(len(state)):
            for j in range(len(state[i])):
                keyByte = (roundKey[j] >> 24 - i*8) & 0xff
                out_[i][j] = state[i][j] ^ keyByte

        if (r != None):
            if (inv):
                print("round[{:2d}].ik_sch   ".format(r), self.getRoundKeyString(roundKey))
            else:
                print("round[{:2d}].k_sch    ".format(r), self.getRoundKeyString(roundKey))

        return out_
    
    # =============================================
    # Inverse Cipher
    # =============================================

    def invCipher(self, ciphertext, w):
        # Cipher Algorithm as described in FIPS 197 Figure 12

        print("INVERSE CIPHER (DECRYPT):")

        state = self.generateStateMatrix(ciphertext)
        print("round[ 0].iinput   ", self.getStateString(state))

        state = self.addRoundKey(state, w[self.nr*self.nb:(self.nr+1)*self.nb], 0, True)

        rCount = 1
        for r in range(self.nr-1, 0, -1):
            print("round[{:2d}].istart   ".format(rCount), self.getStateString(state))
            state = self.invShiftRows(state, rCount)
            state = self.invSubBytes(state, rCount)
            state = self.addRoundKey(state, w[r*self.nb:(r+1)*self.nb], rCount, True)
            state = self.invMixColumns(state, rCount)
            rCount += 1

        print("round[{:2d}].istart   ".format(rCount), self.getStateString(state))

        state = self.invShiftRows(state, self.nr)
        state = self.invSubBytes(state, self.nr)
        state = self.addRoundKey(state, w[0:self.nb], self.nr, True)

        print("round[{:2d}].ioutput  ".format(self.nr), self.getStateString(state))
        print("")

        return self.generateBytesFromState(state)
    
    def invSubBytes(self, state, r=None):
        out_ = np.zeros((4, 4), dtype=int)

        for i in range(len(state)):
            for j in range(len(state[i])):
                col = state[i][j] & 0x0f
                row = state[i][j] >> 4 & 0x0f
                out_[i][j] = self.iSBox[row][col]

        if (r != None):
            print("round[{:2d}].is_box   ".format(r), self.getStateString(out_))

        return out_
    
    def invShiftRows(self, state, r=None):
        out_ = np.zeros((4, 4), dtype=int)

        out_[0] = state[0]
        out_[1] = np.roll(state[1], 1)
        out_[2] = np.roll(state[2], 2)
        out_[3] = np.roll(state[3], 3)

        if (r != None):
            print("round[{:2d}].is_row   ".format(r), self.getStateString(out_))

        return out_
    
    def invMixColumns(self, state, r=None):
        out_ = np.zeros((4, 4), dtype=int)

        for c in range(self.nb):
            out_[0,c] = self.ffMultiply(0x0e, state[0,c]) ^ self.ffMultiply(0x0b, state[1,c]) ^ self.ffMultiply(0x0d, state[2,c]) ^ self.ffMultiply(0x09, state[3,c])
            out_[1,c] = self.ffMultiply(0x09, state[0,c]) ^ self.ffMultiply(0x0e, state[1,c]) ^ self.ffMultiply(0x0b, state[2,c]) ^ self.ffMultiply(0x0d, state[3,c])
            out_[2,c] = self.ffMultiply(0x0d, state[0,c]) ^ self.ffMultiply(0x09, state[1,c]) ^ self.ffMultiply(0x0e, state[2,c]) ^ self.ffMultiply(0x0b, state[3,c])
            out_[3,c] = self.ffMultiply(0x0b, state[0,c]) ^ self.ffMultiply(0x0d, state[1,c]) ^ self.ffMultiply(0x09, state[2,c]) ^ self.ffMultiply(0x0e, state[3,c])

        if (r != None):
            print("round[{:2d}].ik_add   ".format(r), self.getStateString(state))

        return out_
    
    # =============================================
    # General Utility
    # =============================================

    def generateStateMatrix(self, byteArray):
        state = np.zeros((4, 4), dtype=int)
        temp = int.from_bytes(byteArray, byteorder='big')

        # Convert bytearray to 4 by 4 matrix of bytes
        for i in range(4):
            for j in range(4):
                state[i][j] = temp >> (120 - j*32 - i*8) & 0xff

        return state
    
    def generateBytesFromState(self, state):
        out_ = bytearray()

        for i in range(4):
            for j in range(4):
                out_.append(state[j][i])

        return out_
    
    def getStateString(self, state):
        return self.generateBytesFromState(state).hex()
    
    def getRoundKeyString(self, roundKey):
        keyString = bytearray()

        for i in range(len(roundKey)):
            keyString.append(roundKey[i] >> 24 & 0xff)
            keyString.append(roundKey[i] >> 16 & 0xff)
            keyString.append(roundKey[i] >> 8 & 0xff)
            keyString.append(roundKey[i] >> 0 & 0xff)
        
        return keyString.hex()


    def int_to_hex(x):
        return hex(x)
        
    matrix_to_hex = np.vectorize(int_to_hex)

if __name__ == "__main__":
    # C.1 AES-128(nk=4, nr=10)
    print("C.1   AES-128 (Nk=4, Nr=10)\n")
    print("PLAINTEXT:          00112233445566778899aabbccddeeff")
    print("KEY:                000102030405060708090a0b0c0d0e0f\n")

    c1 = AES(128, bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    ciphertext = c1.cipher(bytes.fromhex("00112233445566778899aabbccddeeff"), c1.w)
    c1.invCipher(ciphertext, c1.w)

    # C.2 AES-192(nk=6, nr=12)
    print("C.2   AES-192 (Nk=6, Nr=12)\n")
    print("PLAINTEXT:          00112233445566778899aabbccddeeff")
    print("KEY:                000102030405060708090a0b0c0d0e0f1011121314151617\n")

    c2 = AES(192, bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"))
    ciphertext = c2.cipher(bytes.fromhex("00112233445566778899aabbccddeeff"), c2.w)
    c2.invCipher(ciphertext, c2.w)

    # C.3 AES-256(nk=8, nr=14)
    print("C.3   AES-256 (Nk=8, Nr=14)\n")
    print("PLAINTEXT:          00112233445566778899aabbccddeeff")
    print("KEY:                000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")
    
    c3 = AES(256, bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
    ciphertext = c3.cipher(bytes.fromhex("00112233445566778899aabbccddeeff"), c3.w)
    c3.invCipher(ciphertext, c3.w)
