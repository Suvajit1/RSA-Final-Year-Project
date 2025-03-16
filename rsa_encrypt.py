#!/usr/bin/env sage -python
"""
rsa_encrypt.py
--------------
Usage:
    sage rsa_encrypt.py <plaintext_filename> <public_key_csv>
Example:
    sage rsa_encrypt.py message.txt public_key.csv

Encrypts a plaintext file using RSA encryption and a public key stored in a CSV file.
Now, each plaintext block is constructed as follows:
  - 1 byte: the actual length (L) of the message chunk.
  - (block_size - 15) bytes: message data (if shorter than this, padded with random bytes).
  - 14 bytes: random tail padding.
Thus, each block has a fixed size = block_size, where:
    block_size = (n.nbits() - 1) // 8
Each block is then converted to an integer and encrypted.
The ciphertext file contains one ciphertext integer per line.
Intermediate steps are printed for demonstration.
"""

from sage.all import *
import sys, os, time, csv

def usage():
    print("Usage: sage rsa_encrypt.py <plaintext_filename> <public_key_csv>")
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()
    
    plaintext_filename = sys.argv[1]
    public_key_csv = sys.argv[2]
    
    # Read public key (e, n) from CSV.
    try:
        with open(public_key_csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            row = next(reader)
            if len(row) < 2:
                print("Error: Invalid public key file format.")
                sys.exit(1)
            e = Integer(row[0])
            n = Integer(row[1])
    except Exception as ex:
        print("Error reading public key CSV file:", ex)
        sys.exit(1)
    
    # Read plaintext.
    if not os.path.exists(plaintext_filename):
        print("Error: File", plaintext_filename, "does not exist.")
        sys.exit(1)
    with open(plaintext_filename, "r", encoding="utf-8") as f:
        plaintext = f.read()
    plaintext_bytes = plaintext.encode("utf-8")
    
    # Determine block size: ensure m < n.
    block_size = (n.nbits() - 1) // 8
    # print("Block size:", block_size)
    if block_size < 15:
        print("Error: Block size too small for padding requirements.")
        sys.exit(1)
    data_size = block_size - 15  # available bytes for actual message in each block
    
    # Split plaintext into chunks of size <= data_size.
    chunks = [plaintext_bytes[i:i+data_size] for i in range(0, len(plaintext_bytes), data_size)]
    
    encrypted_blocks = []
    enc_start_time = time.time()
    
    # print("=== Encrypting Blocks ===")
    for i, chunk in enumerate(chunks):
        L = len(chunk)  # actual message length for this block
        # Header: 1 byte indicating L.
        header = bytes([L])
        # Pad the message chunk (if necessary) to exactly data_size bytes.
        if L < data_size:
            pad_len = data_size - L
            pad_bytes = os.urandom(pad_len)
        else:
            pad_bytes = b""
        # Tail: 14 random bytes.
        tail = os.urandom(14)
        # Construct the full block.
        block_bytes = header + chunk + pad_bytes + tail
        if len(block_bytes) != block_size:
            print("Error: Block length mismatch. Expected:", block_size, "Got:", len(block_bytes))
            sys.exit(1)
        
        # # Print intermediate block details for demonstration.
        # print(f"\nBlock {i+1}:")
        # print(" Header (L):", header.hex(), f"-> Actual length = {L}")
        # print(" Message Chunk:", chunk.hex())
        # if len(pad_bytes) > 0:
        #     print(" Padding:", pad_bytes.hex())
        # else:
        #     print(" Padding: (none)")
        # print(" Tail (14 bytes):", tail.hex())
        # print(" Full Block (hex):", block_bytes.hex())
        
        # Convert block bytes to integer.
        m_int = Integer(int.from_bytes(block_bytes, byteorder="big"))
        c_int = power_mod(m_int, e, n)
        encrypted_blocks.append(c_int)
    enc_end_time = time.time()

    # Prepare output filename.
    base, ext = os.path.splitext(plaintext_filename)
    output_filename = f"{base}_cipher{ext}" if ext else f"{plaintext_filename}_cipher"
    with open(output_filename, "w", encoding="utf-8") as f:
        for c in encrypted_blocks:
            # Write each ciphertext (as an integer) on its own line.
            f.write(f"{int(c)}\n")
    
    print("\nEncryption complete.")
    print("Encrypted file:", output_filename)
    print("Time taken to encrypt: {:.6f} seconds".format(enc_end_time - enc_start_time))

if __name__ == "__main__":
    main()
