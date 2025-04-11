# RSA Encryption with SageMath

This project demonstrates a simple RSA encryption system implemented using SageMath. It includes scripts for generating keys, encrypting messages, decrypting messages, and testing the entire process.

---

## Project Overview

### 1. **Key Generation (`rsa_keygenerator.py`)**
- **Purpose:** Creates RSA public and private keys.
- **How it works:**
  - Two large prime numbers are generated.
  - These primes are used to calculate:
    - **Modulus (n):** Product of the two primes.
    - **Euler’s Totient (phi(n)):** Used for key calculations.
  - A public exponent (e) is chosen such that gcd(e, phi(n)) = 1.
  - The private key (d) is calculated using e and phi(n).
- **Output:**
  - Public key (e, n) is saved in `public_key.csv`.
  - Private key (d, n) is saved in `private_key.csv`.

---

### 2. **Encryption (`rsa_encrypt.py`)**
- **Purpose:** Encrypts a plaintext file using the RSA public key.
- **How it works:**
  - The plaintext is read and converted to UTF-8 encoding.
  - If the message is too long, it is split into smaller blocks.
  - Each block is encrypted using the formula:  
    `c = (m^e) mod n`  
    where:
    - `m` is the block of plaintext,
    - `e` is the public exponent,
    - `n` is the modulus.
- **Output:**  
  - The encrypted blocks (ciphertext) are saved in a file with `_cipher` appended to the original filename (e.g., `message_cipher.txt`).

---

### 3. **Decryption (`rsa_decrypt.py`)**
- **Purpose:** Decrypts a ciphertext file using the RSA private key.
- **How it works:**
  - The ciphertext file is read (each line contains `block_length` and `ciphertext`).
  - Each block is decrypted using the formula:  
    `m = (c^d) mod n`  
    where:
    - `c` is the ciphertext block,
    - `d` is the private exponent,
    - `n` is the modulus.
  - The decrypted blocks are combined to reconstruct the original plaintext.
- **Output:**  
  - The plaintext is saved in a file with `_decrypted` appended to the ciphertext filename (e.g., `message_cipher_decrypted.txt`).

---

### 4. **Testing (`test_rsa.py`)**
- **Purpose:** Automates the entire RSA process to verify correctness.
- **Steps:**
  1. Creates a sample plaintext file.
  2. Runs `rsa_keygenerator.py` to generate keys.
  3. Encrypts the sample plaintext using `rsa_encrypt.py`.
  4. Decrypts the ciphertext using `rsa_decrypt.py`.
  5. Compares the original plaintext with the decrypted text.
- **Output:**  
  - Prints a success message if the decrypted text matches the original, otherwise prints a failure message.

---

## Prerequisites

### 1. **SageMath**
- **Why:** All scripts are designed to run using SageMath.
- **Download:** [sagemath.org](https://www.sagemath.org)
- **Example Command:**  
  ```bash
  sage rsa_keygenerator.py 512
  ```

### 2. **Python 3**
- **Why:** The scripts are written in Python 3, which is included in SageMath.

---

## How to Use

### 1. **Generate RSA Keys**
- **Command:**  
  ```bash
  sage rsa_keygenerator.py <bit_length>
  ```
- **Example (512-bit keys):**  
  ```bash
  sage rsa_keygenerator.py 512
  ```
- **Result:**  
  - Creates `public_key.csv` and `private_key.csv`.

---

### 2. **Encrypt a Plaintext File**
- **Command:**  
  ```bash
  sage rsa_encrypt.py <plaintext_filename> <public_key_csv>
  ```
- **Example:**  
  ```bash
  sage rsa_encrypt.py message.txt public_key.csv
  ```
- **Result:**  
  - Saves the ciphertext in a file with `_cipher` appended (e.g., `message_cipher.txt`).

---

### 3. **Decrypt a Ciphertext File**
- **Command:**  
  ```bash
  sage rsa_decrypt.py <ciphertext_filename> <private_key_csv>
  ```
- **Example:**  
  ```bash
  sage rsa_decrypt.py message_cipher.txt private_key.csv
  ```
- **Result:**  
  - Saves the decrypted plaintext in a file with `_decrypted` appended (e.g., `message_cipher_decrypted.txt`).

---

### 4. **Run the Test Script**
- **Command:**  
  ```bash
  python3 test_rsa.py
  ```
- **What it does:**  
  - Runs an end-to-end test of the RSA process.
  - Verifies that the decrypted text matches the original plaintext.

---

This project provides a complete demonstration of RSA encryption and decryption using SageMath, making it easy to understand and test the RSA algorithm in practice.