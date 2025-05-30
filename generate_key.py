# generate_secure_key.py

from secure_kms import generate_aes_key, encrypt_and_store_key
from dotenv import load_dotenv
import os

def main():
    print("Secure Key Generation Utility")
    
    # Load environment variables
    load_dotenv()
    password = os.getenv("KEYSTORE_PASSWORD")
    salt = os.getenv("KEYSTORE_SALT")

    if not password or not salt:
        print("KEYSTORE_PASSWORD or KEYSTORE_SALT missing in .env")
        return


    aes_key = generate_aes_key()
    encrypt_and_store_key(aes_key)

    print("Key securely stored in 'secure_aes.key' using derived KEK")

if __name__ == "__main__":
    main()
