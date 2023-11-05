import random
import hashlib
from Crypto.Util import number as gen
from publickey import int_to_bytes, print_val, get_val, fastModExp

def bytes_to_int(bytes):
    return int.from_bytes(bytes)

# =================================================
# Step 1 - DH
# =================================================

# a = gen.getRandomInteger(512)
# g = get_val('d', "Enter g: ")
# p = get_val('d', "Enter p: ")

# # Calculate public key
# public = fastModExp(g, a, p)

# # Print Values for step 1
# print_val(public, "public key")

g = 5
p = 233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407
public_a = 218206913485058019251447852723834631844526922901582642005881447606808140074057490788948108460908275595773649576070692930544112573608603696498025943613649734410205512797695930561782120252175985549766979346743624631860955789298988461718377110538994759908360996013617541167487713379326735282460835827173386805013
# ================================================
# Step 2 - Shared Key
# ================================================

# password      = get_val('s', "Enter Password: ")
# salt          = get_val('h', "Enter Salt(hex): ")
# B             = get_val('d', "Enter B: ")

password = "classlessness"
salt = 0xcc9c3159
B = 	162380196164451247053671561203163037917626839386173726140112888406007558841587111295015200216034634092326009170829737280602954621736797859472826553659021489993753578305399355684871573391095705378792001477228565612600396126900518691914213059177727106041142450691702342150552451382945941013910046477997414274188

passwordBytes = password.encode('ascii')
saltBytes     = int_to_bytes(salt)

# Calculate Hashed Password
x = saltBytes + passwordBytes

for i in range(1000):
    x = hashlib.sha256(x).digest()

# Calculate k
pBytes = int_to_bytes(p)
gBytes = int_to_bytes(g)
k = hashlib.sha256(pBytes + gBytes).digest()

# Convert bytes to integers and calculate g^b
x = bytes_to_int(x)
k = bytes_to_int(k)
public_b = (B - k * fastModExp(g, x, p)) % p

# Calculate u
aBytes = int_to_bytes(public_a)
bBytes = int_to_bytes(public_b)
u = hashlib.sha256(aBytes + bBytes).digest()

# Print Values for step 2
print_val(x, "x")
print_val(k, "k")
print_val(public_b, "gb")
print_val(u.hex(), "u")