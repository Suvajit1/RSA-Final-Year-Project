#!/usr/bin/env sage -python
"""
rsa_decrypt.py
--------------
Usage:
    sage rsa_decrypt.py <ciphertext_filename> <private_key_csv>
Example:
    sage rsa_decrypt.py message_cipher.txt private_key.csv

Decrypts an RSA-encrypted ciphertext file using a private key stored in a CSV file.
Each ciphertext corresponds to a fixed-size block of length block_size, where:
    block_size = (n.nbits() - 1) // 8.
After decryption, the block is interpreted as follows:
  - The first byte (header) gives L, the actual number of message bytes in this block.
  - The next L bytes are the true message.
  - The remaining bytes are random padding and are discarded.
The recovered message blocks are concatenated and then written to an output file.
"""

from sage.all import *
import sys, os, time, csv

def usage():
    print("Usage: sage rsa_decrypt.py <ciphertext_filename> <private_key_csv>")
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()
    
    ciphertext_filename = sys.argv[1]
    private_key_csv = sys.argv[2]
    
    # Read private key (d, n) from CSV.
    try:
        with open(private_key_csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            row = next(reader)
            if len(row) < 2:
                print("Error: Invalid private key file format.")
                sys.exit(1)
            d = Integer(row[0])
            n = Integer(row[1])
    except Exception as ex:
        print("Error reading private key CSV file:", ex)
        sys.exit(1)
    
    if not os.path.exists(ciphertext_filename):
        print("Error: File", ciphertext_filename, "does not exist.")
        sys.exit(1)
    
    # Determine block size.
    block_size = (n.nbits() - 1) // 8
    if block_size < 15:
        print("Error: Block size too small.")
        sys.exit(1)
    data_size = block_size - 15  # number of bytes allocated for actual message
    
    # Read ciphertext file.
    encrypted_blocks = []
    with open(ciphertext_filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                c_int = Integer(line)
                encrypted_blocks.append(c_int)
            except Exception as ex:
                print("Error parsing line:", line)
                sys.exit(1)
    
    decrypted_bytes = b""
    dec_start_time = time.time()
    for c_int in encrypted_blocks:
        m_int = power_mod(c_int, d, n)
        # Convert decrypted integer back to a full block (block_size bytes).
        block_bytes = int(m_int).to_bytes(block_size, byteorder="big")
        # Extract header (first byte): actual message length L.
        L = block_bytes[0]
        # Extract the actual message bytes: next L bytes.
        message_part = block_bytes[1:1+L]
        decrypted_bytes += message_part
    dec_end_time = time.time()

    try:
        plaintext = decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        print("Error: Decrypted bytes do not form valid UTF-8.")
        sys.exit(1)
    
    # Prepare output filename.
    base, ext = os.path.splitext(ciphertext_filename)
    output_filename = f"{base}_decrypted{ext}" if ext else f"{ciphertext_filename}_decrypted"
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(plaintext)
    
    print("Decryption complete.")
    print("Decrypted file:", output_filename)
    print("Time taken to decrypt: {:.6f} seconds".format(dec_end_time - dec_start_time))

if __name__ == "__main__":
    main()
