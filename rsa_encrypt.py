#!/usr/bin/env sage -python
"""
rsa_encrypt.py
--------------
Usage:
    sage rsa_encrypt.py <input_filename> <public_key_csv>
Example:
    sage rsa_encrypt.py 'Cover Letter.pdf' 'public_key.csv'
    sage rsa_encrypt.py 'image.png' 'public_key.csv'

Encrypts any input file using RSA encryption and a public key stored in a CSV file.
Each input data block is constructed as follows:
  - 1 byte: the actual length (L) of the data chunk.
  - (block_size - 15) bytes: data chunk (if shorter than this, padded with random bytes).
  - 14 bytes: random tail padding.
Thus, each block has a fixed size = block_size, where:
    block_size = (n.nbits() - 1) // 8
Each block is then converted to an integer and encrypted.
The ciphertext file contains one ciphertext integer per line.
Intermediate steps (commented out) can be printed for demonstration.
"""

from sage.all import *
import sys, os, time, csv

def usage():
    print("Usage: sage rsa_encrypt.py <input_filename> <public_key_csv>")
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()
    
    input_filename = sys.argv[1] # Changed from plaintext_filename
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
    except FileNotFoundError:
        print(f"Error: Public key file '{public_key_csv}' not found.")
        sys.exit(1)
    except Exception as ex:
        print(f"Error reading public key CSV file '{public_key_csv}': {ex}")
        sys.exit(1)
    
    # Read input file in binary mode.
    if not os.path.exists(input_filename):
        print(f"Error: File '{input_filename}' does not exist.")
        sys.exit(1)
    
    try:
        with open(input_filename, "rb") as f: # Read as binary
            input_bytes = f.read() # Changed from plaintext and plaintext_bytes
    except Exception as ex:
        print(f"Error reading input file '{input_filename}': {ex}")
        sys.exit(1)
        
    # Determine block size: ensure m < n.
    block_size = (n.nbits() - 1) // 8
    # print("Block size:", block_size) # Kept commented
    if block_size < 15: # 1 byte for L + 14 bytes for tail padding
        print("Error: Block size too small for padding requirements (must be at least 15 bytes).")
        print(f"       Calculated block_size based on key: {block_size} bytes.")
        sys.exit(1)
    data_size = block_size - 15  # available bytes for actual data in each block

    # Ensure each chunk fits in one byte for length (max 255)
    max_chunk_size = min(data_size, 255)
    # Split input_bytes into chunks of size <= max_chunk_size.
    chunks = [input_bytes[i:i+max_chunk_size] for i in range(0, len(input_bytes), max_chunk_size)]
    
    encrypted_blocks = []
    enc_start_time = time.time()

    # print("=== Encrypting Blocks ===") # Kept commented
    for i, chunk in enumerate(chunks):
        L = len(chunk)  # actual data length for this block
        # Header: 1 byte indicating L.
        header = bytes([L])
        # Pad the data chunk (if necessary) to exactly data_size bytes.
        if L < data_size:
            pad_len = data_size - L
            pad_bytes = os.urandom(pad_len)
        else:
            pad_bytes = b"" # No intermediate padding needed if chunk fills data_size
        # Tail: 14 random bytes.
        tail = os.urandom(14)
        # Construct the full block.
        block_bytes = header + chunk + pad_bytes + tail
        
        if len(block_bytes) != block_size:
            # This should ideally not happen if logic is correct
            print(f"Error: Internal block length mismatch during encryption. Expected: {block_size}, Got: {len(block_bytes)}")
            sys.exit(1)
        
        # # Print intermediate block details for demonstration.
        # # These are useful for debugging the padding and block formation.
        # print(f"\nBlock {i+1}/{len(chunks)}:")
        # print(f"  Original Chunk Length (L): {L}")
        # print(f"  Header (1 byte, value L): {header.hex()}")
        # print(f"  Data Chunk ({len(chunk)} bytes): {chunk.hex()[:60]}..." if len(chunk) > 30 else chunk.hex()) # Display part of chunk if long
        # if len(pad_bytes) > 0:
        #     print(f"  Intermediate Padding ({len(pad_bytes)} bytes): {pad_bytes.hex()[:60]}..." if len(pad_bytes) > 30 else pad_bytes.hex())
        # else:
        #     print(f"  Intermediate Padding: (none, chunk filled data_size)")
        # print(f"  Tail Padding (14 bytes): {tail.hex()}")
        # print(f"  Full Padded Block ({len(block_bytes)} bytes, hex): {block_bytes.hex()[:80]}..." if len(block_bytes) > 40 else block_bytes.hex())
        
        # Convert block bytes to integer.
        m_int = Integer(int.from_bytes(block_bytes, byteorder="big"))
        
        # Encrypt the integer.
        c_int = power_mod(m_int, e, n)
        encrypted_blocks.append(c_int)
        
    enc_end_time = time.time()

    # Prepare output filename.
    base, ext = os.path.splitext(input_filename)
    # Ensures the output filename clearly indicates it's a cipher and preserves original extension if any.
    # e.g., input.jpg -> input_cipher.jpg, input.dat -> input_cipher.dat, input -> input_cipher
    output_filename = f"{base}_cipher{ext}" 
    
    try:
        with open(output_filename, "w", encoding="utf-8") as f: # Ciphertext is text lines of numbers
            for c in encrypted_blocks:
                # Write each ciphertext (as an integer) on its own line.
                f.write(f"{int(c)}\n")
    except Exception as ex:
        print(f"Error writing ciphertext file '{output_filename}': {ex}")
        sys.exit(1)
    
    print("\nEncryption complete.")
    print(f"Encrypted file: {output_filename}")
    print(f"Original file size: {len(input_bytes)} bytes")
    print(f"Number of blocks processed: {len(chunks)}")
    print(f"Time taken to encrypt: {enc_end_time - enc_start_time:.6f} seconds")

if __name__ == "__main__":
    main()