#!/usr/bin/env python3
"""
rsa_keygenerator.py
-------------------
Generates RSA keys using primes of a specified bit length and stores keys in CSV files.

Usage:
    python3 rsa_keygenerator.py <bit_length>
Example:
    python3 rsa_keygenerator.py 512

This script:
    - Generates two prime numbers (p and q) of the given bit length.
    - Computes the RSA modulus n and Euler's totient phi.
    - Sets the public exponent e as a prime of bit length equal to half the provided bit length.
    - Ensures gcd(e, phi) = 1 (if not, e is adjusted to the next prime).
    - Computes the private exponent d as the modular inverse of e modulo phi.
    - Stores the public key (e, n) in public_key.csv and the private key (d, n) in private_key.csv.
"""

import sys
import random
import csv
from sympy import nextprime, gcd

def generate_prime(bits):
    """
    Generate a prime number with exactly 'bits' bits.
    It generates a random number of the desired bit length and finds the next prime.
    """
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))  # Ensure the candidate has the desired bit length.
        p = nextprime(candidate)
        if p.bit_length() == bits:
            return p

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 rsa_keygenerator.py <bit_length>")
        sys.exit(1)
    try:
        bits = int(sys.argv[1])
    except ValueError:
        print("Error: bit_length must be an integer (e.g., 512, 1024).")
        sys.exit(1)

    # Generate two primes of the given bit length.
    p = generate_prime(bits)
    q = generate_prime(bits)
    print("p =", p)
    print("q =", q)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Set e as a prime with bit length equal to half of the provided bit length.
    e = generate_prime((bits*2)-1)
    while gcd(e, phi) != 1:
        e = nextprime(e)

    # Compute private exponent d (modular inverse of e modulo phi).
    d = pow(e, -1, phi)

    # Write the public key (e, n) to public_key.csv.
    with open("public_key.csv", "w", newline="") as pub_file:
        writer = csv.writer(pub_file)
        writer.writerow(["e", "n"])
        writer.writerow([e, n])
    
    # Write the private key (d, n) to private_key.csv.
    with open("private_key.csv", "w", newline="") as priv_file:
        writer = csv.writer(priv_file)
        writer.writerow(["d", "n"])
        writer.writerow([d, n])

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

if __name__ == "__main__":
    main()