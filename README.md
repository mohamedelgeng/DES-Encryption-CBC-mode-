# DES Encryption in CBC Mode (Python Implementation)

This project is a Python-based demonstration of the **Data Encryption Standard (DES)** implemented in **Cipher Block Chaining (CBC)** mode. It includes a simplified structure to illustrate the cryptographic concepts, with detailed step-by-step encryption logging for educational purposes.

## 📌 Features
- Custom implementation of core DES components:
  - Initial and Final Permutations
  - Expansion (E), XOR operations
  - Simulated S-Box substitution
  - P-Box permutation
- 16-round Feistel structure for block encryption
- Padding support for arbitrary-length plaintext
- CBC mode chaining with XOR of each block
- Detailed logging for each encryption round
- Hex and binary output formats

## 🧠 Educational Goals
This code is designed to help learners:
- Understand DES round operations step-by-step
- Visualize bit-level transformations
- See how CBC mode ensures ciphertext uniqueness
- Explore how permutation and XOR improve security

## 🛠 Technologies
- Python 3.x
- `pycryptodome` (for padding utility)
- `binascii` (for binary-to-hex conversions)

## 🚀 How to Run
1. **Install dependencies:**
   ```bash
   pip install pycryptodome
   ```

2. **Run the script:**
   ```bash
   python des_cbc.py
   ```

3. **View the output:**
   - Each encryption round's details
   - Final ciphertext in both binary and hex format

## 🔑 Example Parameters
- **Plaintext:** `"DES in CBC Mode"`
- **IV (Initialization Vector):** `"initvect"`
- **Round Keys:** Simulated 16 random 48-bit binary strings

## 📂 File Structure
```
des_cbc.py       # Main script containing DES and CBC mode implementation
```

## 📘 Sample Output (Truncated)
```
Encrypting plaintext using DES in CBC mode with detailed steps:

Block 1:
 Plaintext Binary: ...
 CBC XOR Block: ...
 Initial Permutation: ...
 Round 1: L = ... R = ...
 ...
 Final Permutation: ...

Final Results:
Key:         3f 12 6d 9a 87 45 d1
IV:          69 6e 69 74 76 65 63 74
Ciphertext:  d1e4f8a4...
```

## ⚠️ Disclaimer
This implementation **is not intended for production use** or real-world cryptographic security. It is a simplified model for learning and visualization purposes only.

## 📄 License
This project is licensed under the MIT License.

## 🙌 Acknowledgments
- [FIPS PUB 46-3](https://csrc.nist.gov/publications/detail/fips/46/3/final) - Official DES specification.
- `Crypto.Util.Padding` from PyCryptodome for PKCS#7 padding support.
