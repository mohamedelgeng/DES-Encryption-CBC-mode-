import random

# ------------------------------
# DES CONSTANT TABLES
# ------------------------------

# Initial Permutation (IP) Table
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (FP) Table
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion Table (E)
E = [
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
]

# ------------------------------
# HELPER FUNCTIONS
# ------------------------------

def permute(block, table):
    """Applies permutation using a given table"""
    return [block[i - 1] for i in table]

def expansion(right_half):
    """Expands a 32-bit right half into a 48-bit value using Expansion table E"""
    return permute(right_half, E)

def xor(bits1, bits2):
    """Performs bitwise XOR"""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def text_to_binary(text):
    """Converts text to binary list (8 bits per char)"""
    return [int(bit) for char in text for bit in format(ord(char), '08b')]

def bin_to_hex(bin_data):
    """Converts binary list to hexadecimal string"""
    return ''.join(format(int(''.join(map(str, bin_data[i:i+4])), 2), 'x') for i in range(0, len(bin_data), 4))

def bin_to_string(bin_data):
    """Converts binary list to string"""
    return ''.join(map(str, bin_data))

# ------------------------------
# CBC MODE ENCRYPTION
# ------------------------------

def cbc_encrypt(plaintext, keys, iv):
    """Encrypts text using DES in CBC mode with a given IV"""
    plaintext = text_to_binary(plaintext)
    cipher_blocks = []
    prev_block = iv

    print("\nEncrypting plaintext using DES in CBC mode with detailed steps:\n")

    for i in range(0, len(plaintext), 64):
        block = plaintext[i:i + 64]
        if len(block) < 64:
            block.extend([0] * (64 - len(block)))  # Padding

        print(f"Block {i//64 + 1}:")
        print(f" Plaintext Binary: {bin_to_string(block)}")

        # XOR with IV or previous ciphertext block
        block = xor(block, prev_block)
        print(f" CBC XOR Block (hex): {''.join(format(int(''.join(map(str, block[i:i+8])), 2), '02x') for i in range(0, 64, 8))}")

        # Initial Permutation
        block = permute(block, IP)
        print(f" Initial Permutation: {bin_to_string(block)}\n")

        left, right = block[:32], block[32:]

        for round_num in range(16):
            expanded_right = expansion(right)
            xor_result = xor(expanded_right, keys[round_num])
            substituted = xor_result[:32]  # Placeholder S-Box
            P = [
                16, 7, 20, 21, 29, 12, 28, 17,
                1, 15, 23, 26, 5, 18, 31, 10,
                2, 8, 24, 14, 32, 27, 3, 9,
                19, 13, 30, 6, 22, 11, 4, 25
            ]
            permuted_p = permute(substituted, P)  # Use correct P-Box for 32-bit
            new_right = xor(left, permuted_p)

            print(f" Round {round_num + 1}:")
            print(f"  Expanded R:        {bin_to_string(expanded_right)}")
            print(f"  XOR with key:      {bin_to_string(xor_result)}")
            print(f"  S-box output:      {bin_to_string(substituted)}")
            print(f"  Permutation P:     {bin_to_string(permuted_p)}")
            print(f"  XOR with L:        {bin_to_string(new_right)}")

            left, right = right, new_right
            print(f"  New L:             {bin_to_string(left)}")
            print(f"  New R:             {bin_to_string(right)}")
            print(" ------------------------------------------------")

        # Swap left and right halves before final permutation
        swapped = right + left
        print(f"\nBefore Final Permutation (swapped halves): {bin_to_string(swapped)}")

        # Final Permutation
        encrypted_block = permute(swapped, FP)
        print(f"Final Permutation: {bin_to_string(encrypted_block)}\n")

        cipher_blocks.extend(encrypted_block)
        prev_block = encrypted_block  # Update prev_block for CBC

    ciphertext_bin = bin_to_string(cipher_blocks)
    ciphertext_hex = bin_to_hex(cipher_blocks)
    
    print("\nFinal Results:")
    print(f"Key:         {' '.join(format(random.randint(0, 255), '02x') for _ in range(7))}")  # Simulated Key
    print(f"IV:          {''.join(format(int(''.join(map(str, iv[i:i+8])), 2), '02x') for i in range(0, 64, 8))}")
    print(f"Ciphertext:  {ciphertext_hex}")
    print(f"Ciphertext (Binary): {ciphertext_bin}\n")

    return cipher_blocks

# ------------------------------
# MAIN EXECUTION
# ------------------------------

if __name__ == "__main__":
    plaintext = "Hello DES in CBC Mode"
    main_key = [random.randint(0, 1) for _ in range(56)]  # 56-bit DES key
    iv = [random.randint(0, 1) for _ in range(64)]  # 64-bit IV (RANDOM IV PROPERLY USED)
    round_keys = [[random.randint(0, 1) for _ in range(48)] for _ in range(16)]  # Simulated Round Keys

    cipher_blocks = cbc_encrypt(plaintext, round_keys, iv)
