import requests
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
import os
import base64
import json
import secrets
import logging
 
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
 
FILE_IO_BASE_URL = 'https://file.io/'
 
def generate_salt():
    """Generates a secure random salt."""
    return secrets.token_bytes(16)
 
def derive_key_from_passphrase(passphrase, salt):
    """Derives a key from a passphrase using PBKDF2."""
    key = pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key[:32])
 
def encrypt_message(message, key):
    """Encrypts the message with the key."""
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())
 
def decrypt_message(encrypted_message, key):
    """Decrypts the message using the key."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()
 
def save_message_to_file(encrypted_message, salt, filename):
    """Saves the encrypted message and salt to a file."""
    with open(filename, 'wb') as file:
        data = json.dumps({
            'encrypted_message': base64.b64encode(encrypted_message).decode(),
            'salt': base64.b64encode(salt).decode()
        })
        file.write(data.encode())
 
def load_message_from_file(filename):
    """Loads the encrypted message and salt from a file."""
    with open(filename, 'rb') as file:
        data = json.load(file)
        encrypted_message = base64.b64decode(data['encrypted_message'])
        salt = base64.b64decode(data['salt'])
    return encrypted_message, salt
 
def upload_file(filename):
    """Uploads a file using file.io and returns the URL suffix."""
    try:
        with open(filename, 'rb') as file:
            response = requests.post(FILE_IO_BASE_URL, files={filename: file})
        response.raise_for_status()
        full_url = response.json().get('link')
        if full_url:
            return full_url.split('/')[-1]  # Extract and return the URL suffix
        return None
    except requests.RequestException as e:
        logging.error(f"Error during file upload: {e}")
        return None
 
def download_file(url_suffix, filename):
    """Downloads a file from file.io using the URL suffix."""
    url = f"{FILE_IO_BASE_URL}{url_suffix}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(filename, 'wb') as file:
            file.write(response.content)
    except requests.RequestException as e:
        logging.error(f"Error during file download: {e}")
 
def send_message():
    """Encrypts the message, saves it to a file, and uploads it."""
    message = input("Enter your message: ").strip()
    if not message:
        print("Message cannot be empty.")
        return
 
    passphrase = input("Enter your passphrase: ").strip()
    if not passphrase:
        print("Passphrase cannot be empty.")
        return
 
    salt = generate_salt()
    key = derive_key_from_passphrase(passphrase, salt)
    encrypted_message = encrypt_message(message, key)
    filename = 'message.enc'
 
    save_message_to_file(encrypted_message, salt, filename)
    url_suffix = upload_file(filename)
    if url_suffix:
        print(f"Message sent! Sharebyte: {url_suffix}")  # Changed to Sharebyte
    else:
        print("Failed to send message.")
 
def receive_message():
    """Downloads and decrypts the message file."""
    url_suffix = input("Sharebyte of the message file: ").strip()  # Changed prompt to Sharebyte
    if not url_suffix:
        print("Sharebyte must be provided for receiving a message.")
        return
 
    filename = 'received_message.enc'
    download_file(url_suffix, filename)
 
    if os.path.exists(filename):
        passphrase = input("Enter the passphrase to decrypt the message: ").strip()
        if not passphrase:
            print("Passphrase cannot be empty.")
            return
 
        encrypted_message, salt = load_message_from_file(filename)
 
        try:
            key = derive_key_from_passphrase(passphrase, salt)
            decrypted_message = decrypt_message(encrypted_message, key)
            print(f"Received message:\n{decrypted_message}")
        except Exception as e:
            logging.error(f"Error during decryption: {e}")
    else:
        print("Failed to receive message.")
 
def main():
    print("Welcome to the Encrypted Terminal Chat Application!")
 
    while True:
        action = input("Do you want to [send] or [receive] a message? (Type 'exit' to quit): ").strip().lower()
        if action == 'send':
            send_message()
        elif action == 'receive':
            receive_message()
        elif action == 'exit':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please type 'send', 'receive', or 'exit'.")
 
if __name__ == "__main__":
    main()
