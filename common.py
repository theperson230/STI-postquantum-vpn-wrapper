#!/usr/bin/env python3
# common.py - PQ KEM helpers + AES-GCM helpers

import hashlib
import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- PQ KEM helpers (liboqs-python) ----------

def create_kem(kem_name="Kyber512"):
    """Return a KeyEncapsulation object (context manager style not required)."""
    return oqs.KeyEncapsulation(kem_name)

def generate_keypair(kem):
    """
    For server: return public_key bytes.
    liboqs KeyEncapsulation.generate_keypair() returns public_key bytes.
    """
    return kem.generate_keypair()

def encapsulate_secret(kem, public_key):
    """
    For client: returns (ciphertext, shared_secret).
    Uses encap_secret (liboqs naming encap_secret / decap_secret).
    """
    ct, ss = kem.encap_secret(public_key)
    return ct, ss

def decapsulate_secret(kem, ciphertext):
    """
    For server: decapsulate ciphertext -> shared_secret
    """
    return kem.decap_secret(ciphertext)

# ---------- AES-GCM helpers ----------

def derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 256-bit AES key from the shared secret using SHA-256."""
    return hashlib.sha256(shared_secret).digest()

def encrypt(message: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt message using AES-GCM.
    Returns (nonce, ciphertext_with_tag).
    Nonce length is 12 bytes (recommended).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)  # ciphertext includes tag
    return nonce, ciphertext

def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-GCM. Raises cryptography.exceptions.InvalidTag on failure.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
