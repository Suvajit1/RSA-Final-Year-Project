#!/usr/bin/env sage -python
"""
rsa_keygenerator.py
-------------------
Generates RSA keys using primes of a specified bit length and stores keys in CSV files.

Usage:
    sage rsa_keygenerator.py <bit_length>
Example:
    sage rsa_keygenerator.py 512

This script:
    - Generates two prime numbers (p and q) of the given bit length.
    - Computes the RSA modulus n and Euler's totient phi.
    - Sets the public exponent e as a prime with bit length equal to (bits*2)-1 of the provided bit length.
    - Ensures gcd(e, phi) = 1 (if not, e is adjusted to the next prime).
    - Computes the private exponent d as the modular inverse of e modulo phi.
    - Stores the public key (e, n) in public_key.csv and the private key (d, n) in private_key.csv.
"""

from sage.all import *
import sys, random, csv, time

def generate_prime(bits):
    """
    Generate a prime number with exactly 'bits' bits.
    It randomly selects a candidate in the range [2^(bits-1), 2^bits-1] and returns the next prime.
    """
    while True:
        candidate = randint(2**(bits-1), 2**bits - 1)
        p = next_prime(candidate)
        if p.nbits() == bits:
            return p

def main():
    if len(sys.argv) != 2:
        print("Usage: sage rsa_keygenerator.py <bit_length>")
        sys.exit(1)
    try:
        bits = int(sys.argv[1])
    except ValueError:
        print("Error: bit_length must be an integer (e.g., 512, 1024).")
        sys.exit(1)

    start_time = time.time()  # Start timer for key generation

    # Generate two primes of the given bit length.
    p = generate_prime(bits)
    q = generate_prime(bits)
    print(f"p = {p} ({len(str(p))} digits)")
    print(f"q = {q} ({len(str(q))} digits)")
    n = p * q
    phi = (p - 1) * (q - 1)

    # Set e as a prime with bit length equal to the provided bit length.
    e = generate_prime((bits*2)-1)
    while gcd(e, phi) != 1:
        e = next_prime(e)

    # Compute private exponent d as the modular inverse of e modulo phi.
    d = inverse_mod(e, phi)

    # Write the public key (e, n) to public_key.csv.
    with open("public_key.csv", "w", newline="") as pub_file:
        writer = csv.writer(pub_file)
        writer.writerow(["e", "n"])
        writer.writerow([int(e), int(n)])
    
    # Write the private key (d, n) to private_key.csv.
    with open("private_key.csv", "w", newline="") as priv_file:
        writer = csv.writer(priv_file)
        writer.writerow(["d", "n"])
        writer.writerow([int(d), int(n)])
    
    end_time = time.time()  # End timer after keys are generated and saved
    elapsed = end_time - start_time

    # Output the keys.
    print("Public key (e, n):")
    print("e =", e)
    print("n =", n)
    print("\nPrivate key (d, n):")
    print("d =", d)
    print("n =", n)

    print("Keys generated successfully.")
    print("Public key stored in public_key.csv")
    print("Private key stored in private_key.csv")
    print("Time taken to generate keys: {:.6f} seconds".format(elapsed))

if __name__ == "__main__":
    main()
