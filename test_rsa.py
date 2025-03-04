#!/usr/bin/env python3
"""
test_rsa.py
-----------
Test driver for RSA key generation, encryption, and decryption using SageMath.

Usage:
    python3 test_rsa.py

This script:
  1. Writes a sample plaintext to a file.
  2. Runs rsa_keygenerator.py (via Sage) to generate keys (storing them in public_key.csv and private_key.csv).
  3. Runs rsa_encrypt.py (via Sage) using the public key to encrypt the plaintext file.
  4. Runs rsa_decrypt.py (via Sage) using the private key to decrypt the ciphertext file.
  5. Compares the original plaintext with the decrypted plaintext and prints a success or failure message.
"""

import subprocess
import os
import sys

def run_command(cmd):
    """Helper to run a command and return the CompletedProcess object."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed: {cmd}")
        print("Error output:", result.stderr)
        sys.exit(1)
    return result

def main():
    # Step 1: Write sample plaintext to a file.
    plaintext_file = "test_message.txt"
    sample_text = "This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath.This is a test message for RSA encryption and decryption using SageMath."
    with open(plaintext_file, "w", encoding="utf-8") as f:
        f.write(sample_text)
    print(f"Sample plaintext written to {plaintext_file}")

    # Step 2: Generate RSA keys using a 512-bit key (adjust as needed).
    cmd_keygen = "sage rsa_keygenerator.py 512"
    print("Running key generation...")
    result = run_command(cmd_keygen)
    print(result.stdout)

    # Step 3: Encrypt the plaintext file using the public key.
    cmd_encrypt = f"sage rsa_encrypt.py {plaintext_file} public_key.csv"
    print("Running encryption...")
    result = run_command(cmd_encrypt)
    print(result.stdout)

    # Determine the ciphertext filename (appending _cipher to the plaintext filename).
    base, ext = os.path.splitext(plaintext_file)
    ciphertext_file = f"{base}_cipher{ext}" if ext else f"{plaintext_file}_cipher"

    # Step 4: Decrypt the ciphertext file using the private key.
    cmd_decrypt = f"sage rsa_decrypt.py {ciphertext_file} private_key.csv"
    print("Running decryption...")
    result = run_command(cmd_decrypt)
    print(result.stdout)

    # Determine the decrypted filename (appending _decrypted to the ciphertext filename).
    base_dec, ext_dec = os.path.splitext(ciphertext_file)
    decrypted_file = f"{base_dec}_decrypted{ext_dec}" if ext_dec else f"{ciphertext_file}_decrypted"

    # Step 5: Compare original plaintext and decrypted plaintext.
    with open(plaintext_file, "r", encoding="utf-8") as f:
        original_text = f.read()
    with open(decrypted_file, "r", encoding="utf-8") as f:
        decrypted_text = f.read()

    if original_text == decrypted_text:
        print("SUCCESS: Decrypted text matches the original!")
    else:
        print("FAILURE: Decrypted text does not match the original.")
        print("Original text:", original_text)
        print("Decrypted text:", decrypted_text)

if __name__ == "__main__":
    main()
