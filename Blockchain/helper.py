import hashlib

# =========================================================
# Helper Functions
# =========================================================

def bytes_to_int(bytes):
    return int.from_bytes(bytes)

def H(val):
    return hashlib.sha256(val).digest()

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def get_val(type, message):
    if type == 'h':
        x = int(input(message), 16)
    elif type == 'd':
        x = int(input(message))
    elif type == 'b':
        x = int_to_bytes(int(input(message), 16))
    elif type == 's':
        x = input(message)
    else:
        raise Exception("Invalid type")
    print("")
    return x

def print_val(val, message):
    print(f"=========== {message} ===========")
    print(val, end="\n\n")
    return