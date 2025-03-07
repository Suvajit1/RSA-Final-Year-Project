#!/usr/bin/env python3
"""
benchmark_rsa.py
----------------
Benchmark RSA key generation, encryption, and decryption using SageMath.

Task 1:
  - Run rsa_keygenerator.py repeatedly with key sizes starting from 512 bits,
    increasing by 256 bits up to 2048 bits.
  - For each key size, just run the program (each program prints its own time taken).
  - After finishing Task 1, re-run the key generator with a fixed key size (1024 bits)
    so that the resulting public_key.csv and private_key.csv are used for Tasks 2 and 3.

Task 2:
  - Create plaintext files of increasing sizes: 1 KB, 10 KB, 100 KB, and 1 MB.
  - Encrypt each plaintext file using rsa_encrypt.py (with the public key from Task 1).

Task 3:
  - Decrypt the ciphertext files (produced in Task 2) using rsa_decrypt.py (with the private key from Task 1).

Usage:
    python3 benchmark_rsa.py
"""

import subprocess
import os
import random, string, sys

def run_command(cmd):
    """Run the given command and exit if it fails."""
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print("Command failed:", cmd)
        sys.exit(1)

def main():
    # --------------------------
    # Task 1: Key Generation
    # --------------------------
    print("=== Task 1: Key Generation Benchmarking ===")
    key_sizes = list(range(512, 2048 + 1, 256))
    for ks in key_sizes:
        cmd = f"sage rsa_keygenerator.py {ks}"
        print(f"\nGenerating keys with key size {ks} bits...")
        run_command(cmd)
    
    # Re-run key generation with fixed key size 1024 for Tasks 2 and 3.
    print("\nRe-generating keys with fixed key size 1024 bits for Tasks 2 and 3...")
    run_command("sage rsa_keygenerator.py 1024")
    print("\nTask 1 complete.\n")
    
    # --------------------------
    # Task 2: Encryption
    # --------------------------
    print("=== Task 2: Encryption Benchmarking ===")
    # Define message sizes (in bytes): 1KB, 10KB, 100KB, 1MB, 10MB.
    message_sizes = {
        "1KB": 1024,
        "10KB": 10 * 1024,
        "100KB": 100 * 1024,
        "1MB": 1024 * 1024,
        "10MB": 10 * 1024 * 1024
    }
    
    for label, size in message_sizes.items():
        # Create a plaintext file with random alphanumeric characters.
        message_text = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        message_filename = f"message_{label}.txt"
        with open(message_filename, "w", encoding="utf-8") as f:
            f.write(message_text)
        print(f"\nEncrypting {label} message (size: {size} bytes) from {message_filename} ...")
        cmd = f"sage rsa_encrypt.py {message_filename} public_key.csv"
        run_command(cmd)
    print("\nTask 2 complete.\n")
    
    # --------------------------
    # Task 3: Decryption
    # --------------------------
    print("=== Task 3: Decryption Benchmarking ===")
    for label in message_sizes.keys():
        ciphertext_filename = f"message_{label}_cipher.txt"
        print(f"\nDecrypting ciphertext for {label} message from {ciphertext_filename} ...")
        cmd = f"sage rsa_decrypt.py {ciphertext_filename} private_key.csv"
        run_command(cmd)
    print("\nTask 3 complete.\n")
    
    print("Benchmarking completed.")

if __name__ == "__main__":
    main()
