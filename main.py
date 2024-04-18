import hashlib
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from urllib.parse import quote
from Crypto.Util import number
import os

# Define q and alpha
q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
alpha = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5


# regular Diffie-Hellman key exchange to get same secret key
def task1():
    # Create Private Keys, chosen randomly and less than q
    bob_private_key = os.urandom(16)
    alice_private_key = os.urandom(16)

    # Compute Public Keys
    bob_public_key = pow(alpha, int.from_bytes(bob_private_key, 'big'), q)
    alice_public_key = pow(alpha, int.from_bytes(alice_private_key, 'big'), q)

    # print(bob_public_key)
    # print(alice_public_key)

    # Exchange and compute the shared secret
    s_bob = pow(alice_public_key, int.from_bytes(bob_private_key, 'big'), q)
    s_alice = pow(bob_public_key, int.from_bytes(alice_private_key, 'big'), q)

    # Verify that both shared secrets are equal
    assert s_bob == s_alice

    # print(s_bob)

    # Hash the secret to create the AES key
    shared_key = s_alice.to_bytes((s_alice.bit_length() + 7) // 8, byteorder='big')
    aes_key = SHA256.new(shared_key).digest()[:16]

    # print(aes_key)
    return aes_key


# man in the middle attack; public key transmission attack swapping for q
def task2_1():
    # Create Private Keys, chosen randomly and less than q
    bob_private_key = os.urandom(16)
    alice_private_key = os.urandom(16)

    # Compute Public Keys
    bob_public_key = pow(alpha, int.from_bytes(bob_private_key, 'big'), q)
    alice_public_key = pow(alpha, int.from_bytes(alice_private_key, 'big'), q)

    # Mallory gets in the middle
    print("Mallory gets in the middle and sends bob and alice q instead of each others' public keys!")

    # Mallory intercepts alice public key and instead sends bob q
    what_bob_gets = q

    # Mallory intercepts bob public key and instead sends alice q
    what_alice_gets = q

    # compute shared secret key for both alice and bob (and mallory)
    s_bob = pow(what_bob_gets, int.from_bytes(bob_private_key, 'big'), q)
    s_alice = pow(what_alice_gets, int.from_bytes(alice_private_key, 'big'), q)
    s_mallory = 0  # secret key formula gets changed to q^private_key mod q which will equal 0 always
    # print(s_bob)
    # print(s_alice)
    # print(s_mallory)
    assert s_alice == s_mallory == s_bob

    shared_key = s_alice.to_bytes((s_alice.bit_length() + 7) // 8, byteorder='big')
    aes_key = SHA256.new(shared_key).digest()[:16]

    # print(aes_key)

    # return the secret key
    return aes_key


# man in the middle attack; swap alpha for 1
def task2_2():
    # second part of task 2 where mallory tampers with alpha
    # alpha = 1
    print("Mallory changes alpha to 1!")
    new_alpha = 0x1

    # Create Private Keys, chosen randomly and less than q
    bob_private_key = os.urandom(16)
    alice_private_key = os.urandom(16)

    # Compute Public Keys
    bob_public_key = pow(new_alpha, int.from_bytes(bob_private_key, 'big'), q)
    alice_public_key = pow(new_alpha, int.from_bytes(alice_private_key, 'big'), q)

    # compute shared secret key for both alice and bob (and mallory)
    s_bob = pow(alice_public_key, int.from_bytes(bob_private_key, 'big'), q)
    s_alice = pow(bob_public_key, int.from_bytes(alice_private_key, 'big'), q)
    s_mallory = 1  # secret key will always come out to 1 because both public keys will be 1 and 1^x = 1 and 1 mod x = 1
    # print(s_bob)
    # print(s_alice)
    # print(s_mallory)
    assert s_alice == s_mallory == s_bob

    shared_key = s_mallory.to_bytes((s_alice.bit_length() + 7) // 8, byteorder='big')
    aes_key = SHA256.new(shared_key).digest()[:16]

    # print(aes_key)

    # return the secret key
    return aes_key


# regular rsa encryption and decryption of M
def task3_1(M: int):
    e = 65537
    prime_size = 2048
    prime1 = number.getPrime(prime_size)
    prime2 = number.getPrime(prime_size)

    n = prime1 * prime2
    phi = (prime1 - 1) * (prime2 - 1)

    d = pow(e, -1, phi)

    cipher = pow(M, e, n)

    decryption = pow(cipher, d, n)

    return decryption


# man in the middle attack
def task3_2():

    return



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


if __name__ == '__main__':
    print("-------------------- Task 1.0 --------------------")
    alice_message = "Hello Bob!"
    aes_key1 = task1()
    encrypted_message = encrypt(alice_message, aes_key1)
    decrypted_message = decrypt(encrypted_message, aes_key1)
    print("Normal message encryption with no middle tampering...")
    print("Decrypted message: " + decrypted_message)

    print("\n-------------------- Task 2.1 --------------------")
    aes_key2 = task2_1()
    encrypted_message = encrypt(alice_message, aes_key2)
    decrypted_message = decrypt(encrypted_message, aes_key2)
    print("Mallory decrypts message: " + decrypted_message)

    print("\n-------------------- Task 2.1 --------------------")
    aes_key3 = task2_2()
    encrypted_message = encrypt(alice_message, aes_key3)
    decrypted_message = decrypt(encrypted_message, aes_key3)
    print("Mallory decrypts message: " + decrypted_message)

    print("\n-------------------- Task 3.1 --------------------")
    print("Message sent: 333")
    decrypted_message = task3_1(333)
    print("Encrypted and then decrypted message: " + str(decrypted_message))


# Task 2, Man in the Middle attack. Mallory gets in the middle, sends Q to Bob
# Then Bob sends public key to Mallory instead of Alice,
