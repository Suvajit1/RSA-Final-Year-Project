# RSA Encryption with SageMath

This project demonstrates a simple RSA encryption system implemented using SageMath. It consists of scripts for key generation, encryption, and decryption, along with a test driver that verifies the entire process.

## Project Structure

- **rsa_keygenerator.py**  
  Generates RSA keys using primes of a specified bit length.  
  - Two primes are generated and used to compute the modulus \( n \) and Euler’s totient \( \phi(n) \).  
  - The public exponent \( e \) is chosen as a prime with a bit length equal to half of the provided bit length (and is adjusted if necessary to ensure \(\gcd(e,\phi(n))=1\)).  
  - The public key \((e, n)\) is stored in `public_key.csv`, and the private key \((d, n)\) is stored in `private_key.csv`.

- **rsa_encrypt.py**  
  Encrypts a plaintext file using RSA and a public key from a CSV file.  
  - The plaintext is read and encoded in UTF‑8.  
  - If the message is too long for a single RSA operation, it is split into smaller blocks (each block’s integer value is guaranteed to be less than \( n \)).  
  - The ciphertext for each block is computed as \( c = m^e \mod n \) and stored in an output file with `_cipher` appended to the original filename.

- **rsa_decrypt.py**  
  Decrypts an RSA-encrypted ciphertext file using a private key from a CSV file.  
  - The ciphertext file (with each line formatted as `block_length,ciphertext`) is read, and each block is decrypted as \( m = c^d \mod n \).  
  - The decrypted blocks are reassembled into the original plaintext, which is written to an output file with `_decrypted` appended to the ciphertext filename.

- **test_rsa.py**  
  A test driver that automates the entire process:  
  1. Creates a sample plaintext file.
  2. Calls `rsa_keygenerator.py` (via Sage) to generate keys.
  3. Uses `rsa_encrypt.py` (via Sage) to encrypt the sample plaintext.
  4. Uses `rsa_decrypt.py` (via Sage) to decrypt the ciphertext.
  5. Compares the original plaintext with the decrypted text and prints a success or failure message.

## Prerequisites

- **SageMath:**  
  Ensure you have SageMath installed. Download it from [sagemath.org](https://www.sagemath.org).  
  All scripts are designed to be run using SageMath. For example:
  ```bash
  sage rsa_keygenerator.py 512
  ```

- **Python 3:**  
  The scripts are written in Python 3. SageMath includes a compatible Python environment, but you must use Sage to run the RSA scripts.

## Usage

1. **Generate RSA Keys:**
   ```bash
   sage rsa_keygenerator.py <bit_length>
   ```
   Example (for 512-bit keys):
   ```bash
   sage rsa_keygenerator.py 512
   ```
   This creates `public_key.csv` and `private_key.csv`.

2. **Encrypt a Plaintext File:**
   ```bash
   sage rsa_encrypt.py <plaintext_filename> <public_key_csv>
   ```
   Example:
   ```bash
   sage rsa_encrypt.py message.txt public_key.csv
   ```
   The encrypted ciphertext is saved to a file with `_cipher` appended (e.g., `message_cipher.txt`).

3. **Decrypt a Ciphertext File:**
   ```bash
   sage rsa_decrypt.py <ciphertext_filename> <private_key_csv>
   ```
   Example:
   ```bash
   sage rsa_decrypt.py message_cipher.txt private_key.csv
   ```
   The decrypted plaintext is saved to a file with `_decrypted` appended (e.g., `message_cipher_decrypted.txt`).

4. **Run the Test Script:**
   ```bash
   python3 test_rsa.py
   ```
   This script runs an end-to-end test by generating keys, encrypting a sample message, decrypting the ciphertext, and verifying that the decrypted text matches the original.
