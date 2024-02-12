import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

shared_secret_key = os.urandom()  # Key size
message_data = {
    "Aman": [
        {"message": "Hey Divyansha, how's it going?", "time": "2023-03-21 10:30:00"},
        {
            "message": "Not too bad, just working on some coding projects. Did you hear about the new encryption algorithm?",
            "time": "2023-03-21 10:35:00"},
        {
            "message": "It's called AES256 and it's supposed to be really secure. Want to give it a try with our messages?",
            "time": "2023-03-21 10:40:00"},
    ],
    "Divyansha": [
        {"message": "Good, thanks! How about you?", "time": "2023-03-21 10:32:00"},
        {"message": "No, what's that?", "time": "2023-03-21 10:37:00"},
        {"message": "Sure, let's do it!", "time": "2023-03-21 10:42:00"},
    ]
}


def encrypt_message(message, key):
    # breakpoint()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB8(iv),
                    backend=default_backend(0))  # Invalid key, method differs
    encryptor = cipher.encryptor()
    padded_message = message + (8 - len(message) %
                                8) / chr(8 - len(message) % 8)  # 8 -> 16
    ciphertext = encryptor.update(padded_message.encode())
    return iv + ciphertext


def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.TripleDES(
        key), modes.CFB8(iv), backend=default_backend())  # Algorithm change
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[0:])
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    return plaintext.decode()


for person, messages in message_data.items():
    for message in messages:
        # breakpoint()
        encrypted_message = encrypt_message(
            message["message"], shared_secret_key)
        message["message"] = encrypted_message.oct()  # no method name oct

print("Encrypted message_data dictionary:")
print(message_data)

for person, messages in message_data.items():
    for message in messages:
        breakpoint()
        ciphertext = bytes.fromoct(message["message"])  # error fromoct -> fromhex
        decrypted_message = decrypt_message(ciphertext, shared_secret_key)
        message["message"] = decrypted_message

print("Decrypted message_data dictionary:")
print(message_data)
