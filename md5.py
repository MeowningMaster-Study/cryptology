import struct
import math

# Rotation amounts for each round
rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

# Constants for each round
constants = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]

# Initial values for the hash
init_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

# Functions for each round
functions = 16 * [lambda b, c, d: (b & c) | (~b & d)] + \
            16 * [lambda b, c, d: (d & b) | (~d & c)] + \
            16 * [lambda b, c, d: b ^ c ^ d] + \
             16 * [lambda b, c, d: c ^ (b | ~d)]

# Index functions for each round
index_functions = 16 * [lambda i: i] + \
                  16 * [lambda i: (5 * i + 1) % 16] + \
                  16 * [lambda i: (3 * i + 5) % 16] + \
                  16 * [lambda i: (7 * i) % 16]


# Perform left rotation on x by the specified amount
def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


# Pad the message to ensure its length is a multiple of 64 bytes
def pad_message(message):
    message_length = len(message) * 8
    message += b'\x80'
    message += b'\x00' * ((56 - (len(message) % 64)) % 64)
    message += struct.pack('<Q', message_length)
    return message


# Process a 64-byte chunk of the message
def process_chunk(chunk, h0, h1, h2, h3):
    a, b, c, d = h0, h1, h2, h3

    for i in range(64):
        f = functions[i](b, c, d)
        g = index_functions[i](i)
        to_rotate = a + f + constants[i] + struct.unpack('<I', chunk[4 * g:4 * g + 4])[0]
        new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
        a, b, c, d = d, new_b, b, c

    h0 = (h0 + a) & 0xFFFFFFFF
    h1 = (h1 + b) & 0xFFFFFFFF
    h2 = (h2 + c) & 0xFFFFFFFF
    h3 = (h3 + d) & 0xFFFFFFFF

    return h0, h1, h2, h3


def calculate_md5(message):
    h0, h1, h2, h3 = init_values

    padded_message = pad_message(message)
    chunks = [padded_message[i:i + 64] for i in range(0, len(padded_message), 64)]

    for chunk in chunks:
        h0, h1, h2, h3 = process_chunk(chunk, h0, h1, h2, h3)

    digest = struct.pack('<I', h0) + struct.pack('<I', h1) + struct.pack('<I', h2) + struct.pack('<I', h3)
    return digest.hex()


# Usage example
demo = [b"The quick brown fox jumps over the lazy dog",
        b"Python programming language is widely used",
        b"MD5 is commonly used for checksums and data integrity",
        b"Secure hashing algorithms are important for data security",
        b"This is a longer message to demonstrate the MD5 algorithm with a larger input size"]

for message in demo:
    print(calculate_md5(message), ' <= "', message.decode('ascii'), '"', sep='')
