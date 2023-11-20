from helper import *
import random

class QuoteChain:
    def __init__(self, genesis, d):
        self.chain = [genesis]
        self.d = d
        return

    def proof(self, block_hash):
        zeros = (256 - block_hash.bit_length())
        return zeros >= self.d
        
    def generate_nonce(self):
        nonce = random.randint(0, 2**256 - 1)
        return nonce

    def hash_block(self, quote):
        nonce = self.generate_nonce()

        p1 = self.chain[-1]
        p2 = int_to_bytes(nonce)
        p3 = quote.encode('ascii')

        print("Generating nonce...\n")

        while(1):    
            block_hash = H(p1 + p2 + p3)
            block_hex = bytes_to_int(block_hash)

            if self.proof(block_hex):
                print_val(nonce, "Nonce (int)")
                print_val(block_hash.hex(), "Block hash (hex)")
                return block_hash
            else:
                nonce += 1
                p2 = int_to_bytes(nonce)
        
    def add_block(self, quote):
        block_hash = self.hash_block(quote)
        self.chain.append(block_hash)

if (__name__ == "__main__"):
    print("Welcome to QuoteChain.\n")
    print("Enter the following information from the passoff server:\n")
    genesis = get_val('h', "Enter genesis: ")
    d = get_val('d', "Enter difficulty parameter: ")

    quotechain = QuoteChain(int_to_bytes(genesis), d)

    for i in range(10):
        print("#####################################################")
        print(f"                      BLOCK {i+1}")
        print("#####################################################\n")
        quote = get_val('s', "Enter Quote: ")
        h = quotechain.add_block(quote)

        input("Press Enter to continue...\n")

    print("\nQuoteChain complete. Exiting.")