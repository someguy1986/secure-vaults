import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    """Derives a key from the user's password using PBKDF2HMAC."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def store_key_and_salt(key: bytes, salt: bytes, file_path: str):
    """Stores the key and salt securely (file simulated)."""
    with open(file_path, 'wb') as f:
        f.write(key + b':' + salt)

def load_key_and_salt(file_path: str) -> tuple:
    """Loads the key and salt from storage."""
    with open(file_path, 'rb') as f:
        data = f.read()
        key, salt = data.split(b':')
    return key, salt

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypts data using a Fernet key."""
    cipher = Fernet(key)
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypts data using a Fernet key."""
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data).decode()

def save_encrypted_data(file_path: str, encrypted_data: bytes):
    """Saves encrypted data to a file."""
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

def load_encrypted_data(file_path: str) -> bytes:
    """Loads encrypted data from a file."""
    with open(file_path, 'rb') as f:
        return f.read()

def validate_data(data: str) -> bool:
    """Validates data format."""
    try:
        json.loads(data)
        return True
    except json.JSONDecodeError:
        return False

# Usage Example
user_data = {
    'username': 'john_doe',
    'email': 'john.doe@example.com',
    'preferences': {
        'theme': 'dark',
        'notifications': 'enabled'
    }
}

user_data_str = json.dumps(user_data)
if validate_data(user_data_str):
    password = "secure_user_password"
    key, salt = derive_key_from_password(password)
    store_key_and_salt(key, salt, 'user_key_store.dat')

    encrypted_data = encrypt_data(user_data_str, key)
    save_encrypted_data('user_secure_vault.dat', encrypted_data)

    key, salt = load_key_and_salt('user_key_store.dat')
    encrypted_data_from_vault = load_encrypted_data('user_secure_vault.dat')
    decrypted_data = decrypt_data(encrypted_data_from_vault, key)
    user_data_retrieved = json.loads(decrypted_data)

    print(user_data_retrieved)
else:
    print("Invalid data format.")