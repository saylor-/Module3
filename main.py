import hashlib
from Crypro.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from urllib.parse import quote
import os

# Define q and alpha
q = 37
alpha = 5

# Create Private Keys, chosen randomly and less than q
bob_private_key = os.urandom(16)
alice_private_key = os.urandom(16)

# Compute Public Keys
bob_public_key = pow(alpha, int.from_bytes(bob_private_key, 'big'), q)
alice_public_key = pow(alpha, int.from_bytes(alice_private_key, 'big'), q)

# Exchange and compute the shared secret
s_bob = pow(alice_public_key, int.from_bytes(bob_private_key, 'big'), q)
s_alice = pow(bob_public_key, int.from_bytes(alice_private_key, 'big'), q)

# Verify that both shared secrets are equal
assert s_bob == s_alice

# Hash the secret to create the AES key
shared_key = s_alice.to_bytes((s_alice.bit_length() + 7) // 8, byteorder='big')
aes_key = SHA256.new(shared_key).digest()[:16]


# Encrypt a message with AES-CBC, Make sure padded, Can use builtin
def encrypt(message, key):
    # Convert String to bytes
    message_bytes = message.encode('utf-8')
    message_bytes = pad(message_bytes, AES.block_size)

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(message_bytes)
    return iv + encrypted_message


def decrypt(encrypted_message, key):
    # Decrypt a message with AES-CBC, then unpad, can use builtin
    iv = encrypted_message[:AES.block_size]
    encrypted_data = encrypted_message[AES.block_size:]

    # New cipher for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)

    # Unpad message
    decrypted_data = unpad(decrypted_data, AES.block_size)

    # Return message in string form
    return decrypted_data.decode('utf-8')


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    alice_message = "Hello Bob!"
    encrypted_message = encrypt(alice_message, aes_key)
    decrypted_message = decrypt(encrypted_message, aes_key)
    print(decrypted_message)


# See PyCharm help at https://www.jetbrains.com/help/pycharm/

# Task 2, Man in the Middle attack. Mallory gets in the middle, sends Q to Bob
# Then Bob sends public key to Mallory instead of Alice,
