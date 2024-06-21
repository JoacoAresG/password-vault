# vault/password_manager/utils.py

from cryptography.fernet import Fernet
import random
import string

def generate_key(filepath):
    key = Fernet.generate_key()
    with open(filepath, 'wb') as key_file:
        key_file.write(key)

def load_key(filepath):
    with open(filepath, 'rb') as key_file:
        return key_file.read()

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data)

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))
