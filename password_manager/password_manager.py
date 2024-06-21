# vault/password_manager/password_manager.py

import os
import json
from .utils import generate_key, encrypt_data, decrypt_data

VAULT_DIR = os.path.join(os.path.dirname(__file__), '../data')
PASSWORD_FILE = os.path.join(VAULT_DIR, 'keys.json')
ENCRYPTION_KEY_FILE = os.path.join(VAULT_DIR, 'encryption_key.key')

def initialize_vault():
    if not os.path.exists(VAULT_DIR):
        os.makedirs(VAULT_DIR)

    if not os.path.exists(ENCRYPTION_KEY_FILE):
        generate_key(ENCRYPTION_KEY_FILE)

    encryption_key = load_key(ENCRYPTION_KEY_FILE)

    if os.path.exists(PASSWORD_FILE):
        passwords = load_passwords(PASSWORD_FILE, encryption_key)
    else:
        passwords = []

    return encryption_key, passwords

def load_key(filepath):
    with open(filepath, 'rb') as file:
        return file.read()

def save_passwords(passwords, encryption_key):
    encrypted_data = encrypt_data(json.dumps(passwords).encode(), encryption_key)
    with open(PASSWORD_FILE, 'wb') as file:
        file.write(encrypted_data)

def load_passwords(filepath, encryption_key):
    with open(filepath, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = decrypt_data(encrypted_data, encryption_key)
    return json.loads(decrypted_data)

def add_password(passwords, title, username, password, description, category, encryption_key):
    passwords.append({
        "title": title,
        "username": username,
        "password": password,
        "description": description,
        "category": category
    })
    save_passwords(passwords, encryption_key)

