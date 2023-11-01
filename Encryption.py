from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import base64

# Function to generate public and private key pairs
def generate_key_pairs():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt a message with a symmetric key
def encrypt_message_with_symmetric_key(message, symmetric_key):
    f = Fernet(symmetric_key)
    ciphertext = f.encrypt(message.encode('utf-8'))
    return ciphertext

# Function to decrypt a message with a symmetric key
def decrypt_message_with_symmetric_key(ciphertext, symmetric_key):
    f = Fernet(symmetric_key)
    plaintext = f.decrypt(ciphertext)
    return plaintext.decode('utf-8')

# Get user inputs
user1_private_key, user1_public_key = generate_key_pairs()
user2_private_key, user2_public_key = generate_key_pairs()

# Generate a symmetric key
symmetric_key = Fernet.generate_key()

user1_message = input("User 1, enter your message: ")
user2_message = input("User 2, enter your message: ")

user1_encrypted_symmetric_key = user1_public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
user2_encrypted_symmetric_key = user2_public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

user1_ciphertext = encrypt_message_with_symmetric_key(user1_message, symmetric_key)
user2_ciphertext = encrypt_message_with_symmetric_key(user2_message, symmetric_key)

# Decrypt messages
user1_decrypted_message = decrypt_message_with_symmetric_key(user1_ciphertext, symmetric_key)
user2_decrypted_message = decrypt_message_with_symmetric_key(user2_ciphertext, symmetric_key)

print(f"User 1 sent: {user1_message}")
print(f"User 2 received and decrypted: {user1_decrypted_message}")
print(f"User 2 sent: {user2_message}")
print(f"User 1 received and decrypted: {user2_decrypted_message}")

# Print the encrypted codes
print(f"User 1's encrypted message: {base64.b64encode(user1_ciphertext).decode()}")
print(f"User 2's encrypted message: {base64.b64encode(user2_ciphertext).decode()}")