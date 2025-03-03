#!/usr/bin/env python3
"""
rsa_decrypt.py
--------------
Decrypts an RSA-encrypted ciphertext file using a private key stored in a CSV file.

Usage:
    python rsa_decrypt.py <ciphertext_filename> <private_key_csv>
Example:
    python rsa_decrypt.py message_cipher.txt private_key.csv

The script:
    - Reads the ciphertext file. Each line should be formatted as "block_length,ciphertext".
    - Reads the private key (d, n) from the CSV file.
    - Decrypts each block using RSA: m = c^d mod n.
    - Converts each decrypted integer back to its original bytes (using the stored block length).
    - Reassembles the blocks into the original plaintext.
    - Writes the recovered plaintext to an output file (with "_decrypted" appended to the original ciphertext filename).
"""

import sys, os, time, csv

def usage():
    print("Usage: python rsa_decrypt.py <ciphertext_filename> <private_key_csv>")
    print("Example: python rsa_decrypt.py message_cipher.txt private_key.csv")
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()
    
    ciphertext_filename = sys.argv[1]
    private_key_csv = sys.argv[2]
    
    # Read private key from CSV file.
    try:
        with open(private_key_csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)  # Skip header.
            row = next(reader)     # Read key values.
            if len(row) < 2:
                print("Error: Invalid private key file format.")
                sys.exit(1)
            d = int(row[0])
            n = int(row[1])
    except Exception as ex:
        print("Error reading private key CSV file:", ex)
        sys.exit(1)
    
    if not os.path.exists(ciphertext_filename):
        print("Error: File", ciphertext_filename, "does not exist.")
        sys.exit(1)
    
    # Read ciphertext file.
    encrypted_blocks = []
    block_lengths = []
    with open(ciphertext_filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                length_str, c_str = line.split(",")
                block_lengths.append(int(length_str))
                encrypted_blocks.append(int(c_str))
            except Exception as ex:
                print("Error parsing line:", line)
                sys.exit(1)
    
    decrypted_bytes = b""
    dec_start_time = time.time()
    for length, c_int in zip(block_lengths, encrypted_blocks):
        m_int = pow(c_int, d, n)
        block = m_int.to_bytes(length, byteorder="big")
        decrypted_bytes += block
    dec_end_time = time.time()

    try:
        plaintext = decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        print("Error: Decrypted bytes do not form valid UTF-8.")
        sys.exit(1)
    
    # Prepare output filename: insert _decrypted before file extension.
    base, ext = os.path.splitext(ciphertext_filename)
    output_filename = f"{base}_decrypted{ext}" if ext else f"{ciphertext_filename}_decrypted"
    
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(plaintext)
    
    print("Decryption complete.")
    print("Decrypted file:", output_filename)
    print("Time taken to decrypt: {:.6f} seconds".format(dec_end_time - dec_start_time))

if __name__ == "__main__":
    main()
