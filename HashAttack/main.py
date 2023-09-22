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

def preimage(n_bits):
    rand_len = 20

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

def collision(n_bits):
    collision_table = set()
    rand_len = 20

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

    # Your report should include two graphs summarizing your results, one for the preimage attack and one for the collision attack.
    # Your graph should include a line showing the expected number of iterations to conduct the attack for each of your tested bit sizes.
    # Your graph should also summarize the average number of iterations needed to produce a collision for each tested bit size.
    # The graph should also include details about the variance in your results. This could be done by plotting all samples, using a violin plot, or using a box and whisker plot. Recommendation: Use a logarithmic axis for iterations.

    with open('preimage.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['n_bits', 'n_tries'])

        for n_bits in range(2, 23, 2):
            for i in range(50):
                n_tries = preimage(n_bits)
                writer.writerow([n_bits, n_tries ])

    with open('collision.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['n_bits', 'n_tries'])

        for n_bits in range(2, 23, 2):
            for i in range(50):
                n_tries = collision(n_bits)
                writer.writerow([n_bits, n_tries])
