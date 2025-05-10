# 🔐 DES Encryption-Decryption System in CBC Mode

This project demonstrates **DES (Data Encryption Standard)** encryption using **CBC (Cipher Block Chaining)** mode. It simulates block-wise DES processing with detailed output for each step in Python, including permutations, XORs, and CBC chaining logic.

## 📜 Description

- Implements **Initial and Final Permutations (IP/FP)** as per DES.
- Uses **CBC Mode**, which XORs each plaintext block with the previous ciphertext block.
- Simulates **16 rounds of DES**, each using placeholder round keys and a basic S-box substitution (for demonstration).
- Displays detailed binary and hex output for each block and round.
- Random **56-bit key** and **64-bit IV** are generated at runtime.

## 🔧 Features

- DES block size: 64 bits  
- Key size: 56 bits (simulated)
- IV size: 64 bits (randomly generated)
- Fully annotated step-by-step encryption process
- Terminal output shows:
  - XOR blocks
  - Permutations
  - S-box substitution
  - Round transformations
  - Final ciphertext

## 📦 Requirements

- Python 3.x
- No external libraries required

## 🚀 How to Run

1. Clone or download this repository.
2. Open the project in VS Code or any Python IDE.
3. Run the script:

```bash
python des_cbc.py
