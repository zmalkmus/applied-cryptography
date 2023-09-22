import hashlib
import secrets
import string
import csv

# ==================================================
# Helper functions
# ==================================================

def generate_random_string(length):
    alphabet = string.ascii_letters + string.digits
    random = ''.join(secrets.choice(alphabet) for i in range(8))

    return random

def truncate_sha(input_string, n_bits):
    # Compute the SHA hash of the input string
    sha_hash = hashlib.sha1(input_string.encode()).hexdigest()
    
    # Convert the hexadecimal hash to a binary string
    binary_hash = bin(int(sha_hash, 16))[2:]

    # Truncate the binary string to n bits
    truncated_binary_hash = binary_hash[:n_bits]
    
    # Convert the truncated binary string back to hexadecimal
    truncated_hex_hash = hex(int(truncated_binary_hash, 2))[2:]
    
    return truncated_hex_hash

# ==================================================
# Preimage attack
# ==================================================

def preimage(n_bits, rand_len):
    match_string = truncate_sha(generate_random_string(rand_len), n_bits)
    print("Matching string:", match_string)

    tries = 0

    while True:
        tries += 1

        random_string = truncate_sha(generate_random_string(rand_len), n_bits)

        if random_string == match_string:
            return tries

# ==================================================
# Collision attack
# ==================================================

def collision(n_bits, rand_len):
    collision_table = set()

    initial_string = truncate_sha(generate_random_string(rand_len), n_bits)
    print("Initial string:", initial_string)

    collision_table.add(initial_string)

    tries = 0

    while True:
        tries += 1

        random_string = truncate_sha(generate_random_string(rand_len), n_bits)

        if random_string in collision_table:
            return tries
        else:
            collision_table.add(random_string)

# ==================================================
# Main
# ==================================================

if __name__ == "__main__":
    print("Welcome to hash attack")

    rand_len = 20

    with open('preimage.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['n_bits', 'n_tries'])

        for n_bits in range(8, 23, 2):
            for i in range(50):
                n_tries = preimage(n_bits, rand_len)
                writer.writerow([n_bits, n_tries])

    with open('collision.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['n_bits', 'n_tries'])

        for n_bits in range(8, 23, 2):
            for i in range(50):
                n_tries = collision(n_bits, rand_len)
                writer.writerow([n_bits, n_tries])
