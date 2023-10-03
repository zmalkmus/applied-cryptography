import numpy as np
import random

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
            product = product * b % m # not needed if i =l 
            bit_sum |= (1 << i)

        b = b * b % m
        i += 1

    return product

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
            x = ((x ** 2) % p)

            # continue outer loop
            if (x == (-1 % p)): 
                break
        else:
            return False

    return True

def gcd(a, b):
    if b == 0: return a
    return gcd (b, a % b)

def gcdExtend(a, b, s, t):

    # a = r-2 b = r-1
    # r[i-1] = r[i-2]*q[i] + r[i]
    #       a = b*q[0] + r[0]
    #       b = r[0]*q[1] + r[1]

    if a == 0: return b, 0, 1

    gcd = r[i-1]*s + r[i]*t
    
    x = s - (b//a) * r
    y = r
     
    return gcd,x,y

if __name__ == "__main__":
    print("Welcome to Public-Key Cryptography.")
    # print(fastModExp(11, 13, 19))

    ## prime testing
    # for i in range(100000):
    #     primes = ""
    #     for p in range(1,100):
    #         if (prime(p, 30)):
    #             primes += str(p)

    #     if primes != "2357111317192329313741434753596167717379838997":
    #         print("INCORRECT")



    