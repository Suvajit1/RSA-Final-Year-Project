#!/usr/bin/env python3
"""
test_rsa.py
-----------
Test driver for RSA key generation, encryption, and decryption.

Usage:
    python3 test_rsa.py

This script:
  1. Writes a sample plaintext to a file.
  2. Runs rsa_keygenerator.py to generate keys (storing them in public_key.csv and private_key.csv).
  3. Runs rsa_encrypt.py using the public key to encrypt the plaintext file.
  4. Runs rsa_decrypt.py using the private key to decrypt the ciphertext file.
  5. Compares the original plaintext with the decrypted plaintext and prints a success or failure message.
"""

import subprocess
import os

def run_command(cmd):
    """Helper to run a command and return the CompletedProcess object."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed: {cmd}")
        print("Error output:", result.stderr)
        exit(1)
    return result

def main():
    # Step 1: Write a sample plaintext to a file.
    plaintext_file = "test_message.txt"
    sample_text = "This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption.This is a test message for RSA encryption and decryption."
    with open(plaintext_file, "w", encoding="utf-8") as f:
        f.write(sample_text)
    print(f"Sample plaintext written to {plaintext_file}")

    # Step 2: Generate RSA keys.
    # Example: Generate 512-bit primes (adjust as needed).
    cmd_keygen = "python3 rsa_keygenerator.py 512"
    print("Running key generation...")
    result = run_command(cmd_keygen)
    print(result.stdout)

    # Step 3: Encrypt the plaintext file using the public key CSV.
    cmd_encrypt = f"python3 rsa_encrypt.py {plaintext_file} public_key.csv"
    print("Running encryption...")
    result = run_command(cmd_encrypt)
    print(result.stdout)

    # Determine the ciphertext filename based on the plaintext filename.
    base, ext = os.path.splitext(plaintext_file)
    ciphertext_file = f"{base}_cipher{ext}" if ext else f"{plaintext_file}_cipher"

    # Step 4: Decrypt the ciphertext file using the private key CSV.
    cmd_decrypt = f"python3 rsa_decrypt.py {ciphertext_file} private_key.csv"
    print("Running decryption...")
    result = run_command(cmd_decrypt)
    print(result.stdout)

    # Determine the decrypted filename based on the ciphertext filename.
    base_dec, ext_dec = os.path.splitext(ciphertext_file)
    decrypted_file = f"{base_dec}_decrypted{ext_dec}" if ext_dec else f"{ciphertext_file}_decrypted"

    # Step 5: Compare the original plaintext with the decrypted plaintext.
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
