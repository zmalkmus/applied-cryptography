import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util import number as gen
import hashlib
import csv

# ==============================================
# Part 1
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
# Part 2
# ==============================================

def read_primes(file_name):
    primes = []
    with open(file_name, mode='r', newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            primes.append(int(row[0]))

    return primes

def DF():
    # 2. Select a strong prime number p (generated from generate_primes.py)

    #    I would have used the generateStrongPrime function from generate_primes.py, but it takes a long to generate prime
    #    numbers. For the ease of grading, I generated primes and added them to a list on my own computing time, and
    #    just pulled one randomly from the list.

    primes = read_primes("primes.csv")
    # p = random.choice(primes)
    p = primes[0]
    g = 5

    # print("=========== Prime ===========")
    # print(p, end="\n\n")
        
    # 3. Select a random a as a private key and calculate the public key
    # private = random.randint(gen.getRandomInteger(512), p)
    private = 85828796062933845478302735406133425915054122841056058194110285606809213226125417691645239999933656258898831125541750795964074182624872958455633639610022137708042526798464334113306213947890478663269953036616281875903097865446632620756851169393070036370834068873347001062050007859884144299504248798545250394374
    public = fastModExp(g, private, p)

    # print("=========== private ===========")
    # print(private, end="\n\n")
    # print("=========== public ===========")
    # print(public, end="\n\n")

    # 4. Calculate the shared key
    server_public = 41158451850699340807602194352800210488407926296090248268094596960033679852278570862115266457972106711787382889921604694294213897843975541273776666769016415211481689891975308093846839483966181151264213133193022042544572157101767976558803911754485031970729270407625864776479009663480879652002462438938407437138
    shared_key = fastModExp(server_public, private, p)

    # print("=========== shared ===========")
    # print(shared_key, end="\n\n")

    # 5. Transform your shared key into an symmetric encryption key by taking the SHA-256 hash of sharedkey and using the first 16 bytes (128-bits) of the digest.
    sha256 = hashlib.sha256()
    bytes = str(shared_key).encode()
    sha256.update(bytes)

    key = sha256.digest()[:16]

    print("=========== bytes ===========")
    print(bytes.hex(), end="\n\n")
    print("=========== key ===========")
    print(key.hex(), end="\n\n")

    # 6. Decrypt the message
    cipher = AES.new(key, AES.MODE_CBC)
    cipher.iv = 0xfe6b19e50b04bbbdbb7678af4ae5ae22

    ciphertext = 0xfef74daa391e446111c431fadfea98cbbcf19289e1db76fbc6cf618f163f027e15d43cae02f2264c208f54694198d503af876cf2316e7a34397e2e886cbeb449354b0eff0bc469e48a7b1e4103622f08a2035fd09ef007407fd3f68a91eadfaf691bf683445c3015d412fe5dbc1616aa08458ce3bbc46ed847d78f387c9397788f71460931c99c028d0e0d86406f7e5d69e10dfb3cacca8730a065ae1413da68a8efadbbc89066998eda6059af06360b83d8b4c2b1b452c8c5de4313a006a9dcba2ad7375be5aa318fa51ffb0e135802e3f1d02ac0788834bffc3a296d9227c38a778ec8c5acb7a60ae6c53fc3591e10
    bytes = str(ciphertext).encode()
    plaintext = unpad(cipher.decrypt(bytes), AES.block_size).decode('ASCII')

    print("=========== plaintext ===========")
    print(plaintext.hex(), end="\n\n")

    return

if __name__ == "__main__":
    print("====================================")
    print("Welcome to Public-Key Cryptography.")
    print("====================================\n\n")
    DF()
