from Crypto.Util import number as gen
import csv
from main import is_prime

def generateStrongPrime(size):
    print("Finding Prime...")
    while True:
        p = gen.getPrime(1024)

        sub_p = (p-1) // 2

        # Filter easy ones out
        if (is_prime(sub_p, 4)):
            print("Candidate prime found. Testing...")
            # Make sure, beyond a reasonable doubt, that it is prime
            if (is_prime(sub_p, 100)):
                break
            else:
                print("Bad prime. Continuing...")

    
    print("======== STRONG PRIME ========")
    print(p)
    print("==============================")

    return p

if __name__ == "__main__":
    file_name = "strong_primes.csv"
    for i in range(100):
        with open(file_name, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([generateStrongPrime(1024)])