# secure_kms.py

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv

load_dotenv()

# Load password + salt from .env
PASSWORD = os.getenv("KEYSTORE_PASSWORD")
SALT = base64.b64decode(os.getenv("KEYSTORE_SALT"))
KEY_FILE = "secure_aes.key"

def derive_kek(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    return kdf.derive(password.encode())

def generate_aes_key():
    return AESGCM.generate_key(bit_length=256)

def encrypt_and_store_key(aes_key: bytes):
    kek = derive_kek(PASSWORD, SALT)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    encrypted_key = aesgcm.encrypt(nonce, aes_key, None)
    with open(KEY_FILE, "wb") as f:
        f.write(nonce + encrypted_key)

def load_decrypted_key() -> bytes:
    kek = derive_kek(PASSWORD, SALT)
    with open(KEY_FILE, "rb") as f:
        raw = f.read()
    nonce = raw[:12]
    encrypted_key = raw[12:]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, encrypted_key, None)
