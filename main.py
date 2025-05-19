import binascii
from Crypto.Util.Padding import pad
from random import randint

# -------------------------------
# DES Standard Tables
# -------------------------------

# Initial Permutation (IP) Table - Rearranges the 64 bits of the input block
# Each number represents the position from which to take the bit (1-based indexing)
INITIAL_PERMUTATION = [
    58, 50, 42, 34, 26, 18, 10, 2,  # First 8 bits of output
    60, 52, 44, 36, 28, 20, 12, 4,  # Second 8 bits
    62, 54, 46, 38, 30, 22, 14, 6,  # Third 8 bits
    64, 56, 48, 40, 32, 24, 16, 8,  # Fourth 8 bits
    57, 49, 41, 33, 25, 17, 9, 1,   # Fifth 8 bits
    59, 51, 43, 35, 27, 19, 11, 3,  # Sixth 8 bits
    61, 53, 45, 37, 29, 21, 13, 5,  # Seventh 8 bits
    63, 55, 47, 39, 31, 23, 15, 7   # Eighth 8 bits
]

# Final Permutation (FP) Table - Inverse of IP, used at the end of encryption
# Rearranges the 64 bits to produce the final ciphertext block
FINAL_PERMUTATION = [
    40, 8, 48, 16, 56, 24, 64, 32,  # First 8 bits of output
    39, 7, 47, 15, 55, 23, 63, 31,  # Second 8 bits
    38, 6, 46, 14, 54, 22, 62, 30,  # Third 8 bits
    37, 5, 45, 13, 53, 21, 61, 29,  # Fourth 8 bits
    36, 4, 44, 12, 52, 20, 60, 28,  # Fifth 8 bits
    35, 3, 43, 11, 51, 19, 59, 27,  # Sixth 8 bits
    34, 2, 42, 10, 50, 18, 58, 26,  # Seventh 8 bits
    33, 1, 41, 9, 49, 17, 57, 25    # Eighth 8 bits
]

# Expansion Table (E) - Expands 32-bit right half to 48 bits for key mixing
# Some bits are duplicated to achieve the expansion from 32 to 48 bits
EXPANSION_TABLE = [
    32, 1, 2, 3, 4, 5,        # First 6 bits of output
    4, 5, 6, 7, 8, 9,         # Second 6 bits
    8, 9, 10, 11, 12, 13,     # Third 6 bits
    12, 13, 14, 15, 16, 17,   # Fourth 6 bits
    16, 17, 18, 19, 20, 21,   # Fifth 6 bits
    20, 21, 22, 23, 24, 25,   # Sixth 6 bits
    24, 25, 26, 27, 28, 29,   # Seventh 6 bits
    28, 29, 30, 31, 32, 1     # Eighth 6 bits
]

# P-Box Table - Used after S-box substitution to further scramble bits
P_TABLE = [
    16, 7, 20, 21, 29, 12, 28, 17,  # First 8 bits of output
    1, 15, 23, 26, 5, 18, 31, 10,   # Second 8 bits
    2, 8, 24, 14, 32, 27, 3, 9,     # Third 8 bits
    19, 13, 30, 6, 22, 11, 4, 25    # Fourth 8 bits
]

# ------------------------------
# HELPER FUNCTIONS
# ------------------------------

def apply_permutation(bits, table):
    """
    Rearranges bits according to the given permutation table.
    
    Args:
        bits: String of bits to be permuted
        table: Permutation table defining the new positions
        
    Returns:
        String of bits after permutation
    """
    return ''.join(bits[i - 1] for i in table)  # -1 because table uses 1-based indexing

def xor_bits(a, b):
    """
    Performs XOR operation between two equal-length binary strings.
    Used for combining key with expanded block and for combining L with f(R,K).
    
    Args:
        a, b: Strings of bits of equal length
        
    Returns:
        String of bits after XOR operation
    """
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))

def text_to_binary(text):
    """
    Converts text string to binary string (8 bits per char).
    
    Args:
        text: String to convert
        
    Returns:
        String of bits representing the text
    """
    return ''.join(f"{ord(char):08b}" for char in text)

# ------------------------------
# DES CORE FUNCTIONALITY
# ------------------------------

def des_single_round(L, R, key):
    """
    Executes one round of the Feistel DES structure.
    
    Args:
        L: Left half of the block (32 bits)
        R: Right half of the block (32 bits)
        key: Round key (48 bits)
        
    Returns:
        Tuple of new (L, R) after this round
    """
    # 1. Expansion: Expand right half from 32 to 48 bits
    expanded = apply_permutation(R, EXPANSION_TABLE)
    
    # 2. Key mixing: XOR expanded right half with round key
    mixed = xor_bits(expanded, key)
    
    # 3. Substitution: Apply S-boxes (simplified here as a placeholder)
    # In a full implementation, this would use the 8 S-boxes
    substituted = ''.join(mixed[i] for i in range(32))  # Simulated S-box
    
    # 4. Permutation: Apply P-box to scramble bits
    permuted = apply_permutation(substituted, P_TABLE)
    
    # 5. Combine: XOR left half with the result of f(R,K)
    new_R = xor_bits(L, permuted)
    
    # Return R as new L, and new_R as new R (for next round)
    return R, new_R

def des_encrypt_one_block(block, round_keys):
    """
    Encrypts a 64-bit block using 16 rounds of DES.
    
    Args:
        block: 64-bit string representing one block of plaintext
        round_keys: List of 16 round keys (each 48 bits)
        
    Returns:
        Tuple of (encrypted_block, rounds_trace)
    """
    # Initial Permutation
    initial = apply_permutation(block, INITIAL_PERMUTATION)
    
    # Split block into left and right halves (32 bits each)
    L, R = initial[:32], initial[32:]
    rounds_trace = []

    # 16 rounds of DES
    for idx, key in enumerate(round_keys):
        # Apply Feistel function and swap L,R
        L, R = des_single_round(L, R, key)
        rounds_trace.append(f"Round {idx+1}: L = {L[:8]}...{L[-8:]}, R = {R[:8]}...{R[-8:]}")

    # Swap left and right halves before final permutation (DES standard)
    final_block = R + L
    
    # Final Permutation
    encrypted = apply_permutation(final_block, FINAL_PERMUTATION)
    return encrypted, rounds_trace

# ------------------------------
# CBC MODE ENCRYPTION
# ------------------------------

def des_cbc_encrypt(message, round_keys, iv_text):
    """
    Encrypts message using DES in CBC mode.
    CBC mode XORs each plaintext block with the previous ciphertext block
    before encryption, which adds security by making identical plaintext
    blocks encrypt to different ciphertext blocks.
    
    Args:
        message: Text to encrypt
        round_keys: List of 16 round keys (each 48 bits)
        iv_text: 8-character initialization vector
        
    Returns:
        Tuple of (ciphertext_binary, block_logs)
    """
    # Pad the message to ensure it's a multiple of 8 bytes (64 bits)
    padded = pad(message.encode(), 8)
    
    # Convert plaintext and IV to binary
    binary_input = text_to_binary(padded.decode())
    iv_bin = text_to_binary(iv_text)
    
    output_cipher = ""
    previous = iv_bin  # First block uses IV
    block_logs = []

    print("\nEncrypting plaintext using DES in CBC mode with detailed steps:\n")

    # Process plaintext in 64-bit blocks
    for i in range(0, len(binary_input), 64):
        # Extract current block and pad if necessary
        block = binary_input[i:i+64].ljust(64, '0')  # Pad block if needed
        
        print(f"Block {i//64 + 1}:")
        print(f" Plaintext Binary: {block}")
        
        # XOR with IV or previous ciphertext block (CBC mode)
        chained = xor_bits(block, previous)
        print(f" CBC XOR Block: {chained}")
        
        # Encrypt the block
        encrypted_block, trace = des_encrypt_one_block(chained, round_keys)
        print(f" Initial Permutation: {apply_permutation(chained, INITIAL_PERMUTATION)}\n")
        
        # Print round details
        for round_detail in trace:
            print(f" {round_detail}")
        
        print(f"\n Final Permutation: {encrypted_block}\n")
        
        # Add to ciphertext and update previous block for next iteration
        output_cipher += encrypted_block
        previous = encrypted_block  # Update previous for CBC
        block_logs.append((f"Block {i//64 + 1} Encryption Trace", trace))

    # Convert binary ciphertext to readable formats
    ciphertext_bytes = int(output_cipher, 2).to_bytes(len(output_cipher) // 8, byteorder='big')
    ciphertext_hex = binascii.hexlify(ciphertext_bytes).decode()
    
    # Display final results
    print("\nFinal Results:")
    print(f"Key:         {' '.join(format(randint(0, 255), '02x') for _ in range(7))}")  # Simulated Key
    print(f"IV:          {' '.join(format(ord(c), '02x') for c in iv_text)}")
    print(f"Ciphertext:  {ciphertext_hex}")
    print(f"Ciphertext (Binary): {output_cipher}\n")

    return output_cipher, block_logs

# ------------------------------
# MAIN EXECUTION
# ------------------------------

if __name__ == "__main__":
    # Sample plaintext to encrypt
    plaintext = "DES in CBC Mode"
    
    # 8-character initialization vector (64 bits)
    iv = "initvect"
    
    # Generate 16 round keys (48 bits each) - simplified for demonstration
    simulated_keys = [''.join(str(randint(0, 1)) for _ in range(48)) for _ in range(16)]

    # Perform encryption
    ciphertext_binary, logs = des_cbc_encrypt(plaintext, simulated_keys, iv)
    
    # Additional output for verification
    ciphertext_bytes = int(ciphertext_binary, 2).to_bytes(len(ciphertext_binary) // 8, byteorder='big')
    
