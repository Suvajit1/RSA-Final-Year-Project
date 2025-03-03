#!/usr/bin/env python3
"""
rsa_encrypt.py
--------------
Encrypts a plaintext file using RSA encryption and a public key stored in a CSV file.

Usage:
    python3 rsa_encrypt.py <plaintext_filename> <public_key_csv>
Example:
    python3 rsa_encrypt.py message.txt public_key.csv

The script:
    - Reads the plaintext from the specified file.
    - Reads the public key (e, n) from the CSV file.
    - Encodes the text to UTF-8 bytes.
    - Determines the maximum block size based on n's bit length so that each block's integer value is less than n.
    - Splits the plaintext bytes into blocks if needed.
    - Encrypts each block using RSA: c = m^e mod n.
    - Writes the ciphertext to an output file (with "_cipher" appended to the original filename).
      Each line in the output file contains the block's original byte length and the ciphertext, separated by a comma.
"""

import sys, os, time, csv

def usage():
    print("Usage: python3 rsa_encrypt.py <plaintext_filename> <public_key_csv>")
    print("Example: python3 rsa_encrypt.py message.txt public_key.csv")
    sys.exit(1)

def split_bytes(b, size):
    """
    Splits the bytes object 'b' into a list of chunks of maximum length 'size'.
    """
    return [b[i:i+size] for i in range(0, len(b), size)]

def main():
    if len(sys.argv) != 3:
        usage()
    
    plaintext_filename = sys.argv[1]
    public_key_csv = sys.argv[2]
    
    # Read public key from CSV file.
    try:
        with open(public_key_csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)  # Skip header.
            row = next(reader)     # Read key values.
            if len(row) < 2:
                print("Error: Invalid public key file format.")
                sys.exit(1)
            e = int(row[0])
            n = int(row[1])
    except Exception as ex:
        print("Error reading public key CSV file:", ex)
        sys.exit(1)
    
    # Read plaintext from file.
    if not os.path.exists(plaintext_filename):
        print("Error: File", plaintext_filename, "does not exist.")
        sys.exit(1)
    with open(plaintext_filename, "r", encoding="utf-8") as f:
        plaintext = f.read()
    
    plaintext_bytes = plaintext.encode("utf-8")
    
    # Determine block size.
    # Maximum number of bytes per block is floor(n.bit_length()/8) minus one byte.
    max_block_size = n.bit_length() // 8
    block_size = max_block_size - 1 if max_block_size > 1 else max_block_size

    blocks = split_bytes(plaintext_bytes, block_size)
    
    encrypted_blocks = []
    block_lengths = []  # Store the length of each block for later decryption.
    enc_start_time = time.time()
    for block in blocks:
        block_lengths.append(len(block))
        m_int = int.from_bytes(block, byteorder="big")
        c_int = pow(m_int, e, n)
        encrypted_blocks.append(c_int)
    enc_end_time = time.time()

    # Prepare output filename: insert _cipher before file extension.
    base, ext = os.path.splitext(plaintext_filename)
    output_filename = f"{base}_cipher{ext}" if ext else f"{plaintext_filename}_cipher"

    with open(output_filename, "w", encoding="utf-8") as f:
        for length, c in zip(block_lengths, encrypted_blocks):
            f.write(f"{length},{c}\n")
    
    print("Encryption complete.")
    print("Encrypted file:", output_filename)
    print("Time taken to encrypt: {:.6f} seconds".format(enc_end_time - enc_start_time))

if __name__ == "__main__":
    main()
