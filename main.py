from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
from base64 import b64encode, b64decode
import os

def generate_key(password: str, salt: bytes) -> bytes:
    """Derive a secure encryption key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(password: str, long_password: str) -> str:
    """Encrypt a long password and return a base64-encoded encrypted string with salt."""
    # Generate a random salt
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)  # Random initialization vector for AES-CBC

    # Pad the long password to match AES block size
    padder = padding.PKCS7(128).padder()
    padded_long_password = padder.update(long_password.encode()) + padder.finalize()

    # Encrypt the padded password
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_long_password) + encryptor.finalize()

    # Combine salt, iv, and encrypted data, then encode to base64
    encrypted_data = salt + iv + encrypted
    return b64encode(encrypted_data).decode()

def decrypt(password: str, encrypted_data_b64: str) -> str:
    """Decrypt a base64-encoded encrypted string using the provided password."""
    # Decode the base64-encoded data
    encrypted_data = b64decode(encrypted_data_b64)
    
    # Extract salt, iv, and encrypted content
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_content = encrypted_data[32:]

    # Regenerate the key from the password and salt
    key = generate_key(password, salt)

    # Decrypt the encrypted content
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_long_password = decryptor.update(encrypted_content) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    long_password = unpadder.update(padded_long_password) + unpadder.finalize()
    
    return long_password.decode()

# Example usage
password = "securepassword"  # The password used to encrypt and decrypt
long_password = "ThisIsAVeryLongPasswordThatNeedsToBeEncrypted"

# Encrypt the long password
encrypted = encrypt(password, long_password)
print("Encrypted:", encrypted)

# Decrypt to get the original long password
decrypted = decrypt(password, encrypted)
print("Decrypted:", decrypted)
