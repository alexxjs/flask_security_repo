# encryption.py

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext)  # Store nonce with ciphertext

def decrypt_data(encoded: bytes, key: bytes) -> bytes:
    data = base64.b64decode(encoded)
    nonce, ciphertext = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
