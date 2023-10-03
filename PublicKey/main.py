import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util import number as gen
import hashlib
import csv

# ==============================================
# Part 1 PRIMALITY
# ==============================================

def fastModExp(b, e, m):
    product = 1 # Running product between rounds
    bit_sum = 0 # Builds e from bits so we know when to stop
    i = 0       # Current round

    # loop through bits of e
    while (bit_sum != e):
        if (e & (1 << i)):
            product = product * b % m
            bit_sum |= (1 << i)

        b = b * b % m
        i += 1

    return product

def fast_power(base, power, m):
    result = 1
    while power > 0:
        # If power is odd
        if power % 2 == 1:
            result = (result * base) % m

        # Divide the power by 2
        power = power // 2
        # Multiply base to itself
        base = (base * base) % m

    return result

def is_prime(p, k):
    if (p == 1): return False

    # Factor powers of 2 out from p-1
    s = 0
    d = p-1

    while d%2 == 0:
        s+=1
        d//=2
        
    # Perform the test k times
    for i in range(k):
        # pick a: {1 <= a <= p-1}
        a = random.randint(1,p-1)

        # calculate x
        x = fastModExp(a, d, p)

        # continue outer loop
        if ( (x == (1 % p)) or (x == (-1 % p)) ): continue

        # square x, s-1 times
        for j in range(s-1):
            x = fastModExp(x, 2, p)

            # continue outer loop
            if (x == (-1 % p)): 
                break
        else:
            return False

    return True

def gcd(a, b):
    if b == 0: return a
    return gcd (b, a % b)

def extgcd(a, b):
    # if the remainder being passed in == 0 then we are done
    if (b == 0):
        s = 1
        t = 0
        return s, t

    # get q and r for the current iteration
    q = a // b
    r = a % b

    # recursively call extgcd until we get no remainder
    rminus2, rminus1 = extgcd(b, r)

    # calculate s and t
    s = rminus1
    t = rminus2 - rminus1 * q

    return s, t

# ==============================================
# Part 2 DH
# ==============================================

def read_primes(file_name):
    primes = []
    with open(file_name, mode='r', newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            primes.append(int(row[0]))

    return primes

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def get_val(type, message):
    if type == 'h':
        x = int(input(message), 16)
    elif type == 'd':
        x = int(input(message))
    elif type == 'b':
        x = int_to_bytes(int(input(message), 16))
    else:
        raise Exception("Invalid type")
    print("")
    return x

def print_val(val, message):
    print(f"=========== {message} ===========")
    print(val, end="\n\n")
    return

def DF():
    print ("\nDiffie-Hellman:\n")

    # =========================================================================
    # 2. Select a strong prime number p and a generator g
    # =========================================================================
    # NOTE: I would have used the generateStrongPrime function from 
    # generate_primes.py, but it takes a long to generate prime numbers. For 
    # the ease of grading, I generated primes and added them to a list on my 
    # own computing time, andjust pulled one randomly from the list. 
    # =========================================================================
    g = get_val('d', "Enter g: ")
    strong_primes = read_primes("strong_primes.csv")
    p = random.choice(strong_primes) # generated from generate_strong_primes.py

    print_val(p, "Prime Modulus (p)")

    # =========================================================================    
    # 3. Select a random a as a private key and calculate the public key
    # =========================================================================
    private = random.randint(gen.getRandomInteger(512), p)
    public = fastModExp(g, private, p)

    print_val(public, "Public Key (g^a)")

    # Get variables from server
    server_public = get_val('d', "Enter the server's public key: ")
    iv            = get_val('b', "Enter the iv: ")
    ciphertext    = get_val('b', "Enter the ciphertext: ")

    # =========================================================================
    # 4. Calculate the shared key
    # =========================================================================
    shared_key = fastModExp(server_public, private, p)
    print_val(shared_key, "Shared Key (g^ab)")

    # =========================================================================
    # 5. Transform your shared key into a symmetric encryption key by taking 
    #   the SHA-256 hash of shared_key and using the first 16 bytes (128-bits) 
    # =========================================================================

    # SHA-256 hash of shared_key
    sha256 = hashlib.sha256()
    sha256.update(int_to_bytes(shared_key))

    key = sha256.digest()[:16]

    # 6. Decrypt the message
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('ASCII')

    print_val(plaintext, "Plaintext")

    return

# ==============================================
# Part 3 RSA
# ==============================================

def RSA():
    primes = read_primes()

    # Generate primes until one works

    
    return

if __name__ == "__main__":
    print("Welcome to Public-Key Cryptography.")
    DF()

