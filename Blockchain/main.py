from helper import *
import random

class BC:
    def __init__(self, genesis):
        self.chain = []
        self.chain.append(genesis)
        return

    def proof(self, hash, d):
        zeros = (256 - hash.bit_length())
        return True if zeros >= d else False
        
    def generate_nonce(self):
        nonce = bytes([random.randint(0, 255) for _ in range(32)])
        return nonce

    def hash_block(self, quote, d):
        p1 = H(int_to_bytes(self.chain[-1]))
        p2 = self.generate_nonce()
        p3 = quote.encode('ascii')

        while(1):    
            hash = bytes_to_int(H(p1 + p2 + p3))

            if self.proof(hash, d):
                self.chain.append(hash)

                print_val(bytes_to_int(p2), "Nonce")
                print_val(hash, "Block hash")

                return hash
            else:
                p2 = self.generate_nonce()

if (__name__ == "__main__"):
    genesis = 0x2a201ad6f1caeb8f5e6aba5a952ed72c7c3505e7863623821d7f29fdcb1d1b32

    quotechain = BC(genesis)

    h1 = quotechain.hash_block("Photography is painting with light. -- Eric Hamilton", 24)

    print_val(hex(h1), "H1")
