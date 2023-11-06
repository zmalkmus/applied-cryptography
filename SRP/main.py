import random
import hashlib
from Crypto.Util import number as gen
from publickey import int_to_bytes, print_val, get_val, fastModExp

def bytes_to_int(bytes):
    return int.from_bytes(bytes)

def H(val):
    return hashlib.sha256(val).digest()

# =================================================
# Step 1 - DH
# =================================================

print("##############################################################################################")
print("PART 1")
print("##############################################################################################\n")

a = gen.getRandomInteger(512)
g = get_val('d', "Enter g: ")
p = get_val('d', "Enter p: ")

# Calculate public key
public_a = fastModExp(g, a, p)

# Print values for step 1
print_val(public_a, "DH Public Key")

# ================================================
# Step 2 - Shared Key
# ================================================

print("\n##############################################################################################")
print("PART 2")
print("##############################################################################################\n")

password      = get_val('s', "Enter Password: ")
salt          = get_val('h', "Enter Salt(hex): ")
B             = get_val('d', "Enter B: ")

passwordBytes = password.encode('ascii')
saltBytes     = int_to_bytes(salt)

# Calculate hashed password
x = saltBytes + passwordBytes

for i in range(1000):
    x = H(x)

x = bytes_to_int(x)

# Calculate k
pBytes = int_to_bytes(p)
gBytes = int_to_bytes(g)
k = bytes_to_int(H(pBytes + gBytes))

# Convert bytes to integers and calculate g^b
public_b = (B - k * fastModExp(g, x, p)) % p

# Calculate u
aBytes = int_to_bytes(public_a)
bBytes = int_to_bytes(public_b)
u = bytes_to_int(H(aBytes + bBytes))

# Calculate Shared Key
e = a + u * x
shared_key = fastModExp(public_b, e, p)

# Print values for step 2
print_val(x, "x")
print_val(k, "k")
print_val(public_b, "gb")
print_val(u, "u")
print_val(shared_key, "Shared Key")

# ================================================
# Step 3 - Calculate M1
# ================================================

print("\n##############################################################################################")
print("PART 3")
print("##############################################################################################\n")

username = get_val('s', "Enter Username: ")

# Calculate M1 and M2
p1 = bytes(a ^ b for a, b in zip (H(int_to_bytes(p)), H(int_to_bytes(g))))
p2 = H(username.encode('ascii'))
p3 = int_to_bytes(salt)
p4 = int_to_bytes(public_a)
p5 = int_to_bytes(public_b)
p6 = int_to_bytes(shared_key)

M1 = H(p1 + p2 + p3 + p4 + p5 + p6)
M2 = H(p4 + M1 + p6)

# Print values for part 3
print_val(M1.hex(), "M1")
print_val(M2.hex(), "M2")