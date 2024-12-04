from Crypto.Cipher import AES
import base64

# Function to encrypt a message
def encrypt_message(key, message):
    """
    Encrypts a message using AES encryption.

    Parameters:
    - key (bytes): A 16-byte encryption key.
    - message (str): The message to encrypt.

    Returns:
    - str: Base64 encoded encrypted message.
    """
    cipher = AES.new(key, AES.MODE_EAX)  # Initialize AES cipher in EAX mode
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())  # Encrypt and generate authentication tag
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()  # Return combined result encoded in Base64

# Function to decrypt an encrypted message
def decrypt_message(key, encrypted_message):
    """
    Decrypts an AES encrypted message.

    Parameters:
    - key (bytes): A 16-byte encryption key.
    - encrypted_message (str): The Base64 encoded encrypted message.

    Returns:
    - str: Decrypted plaintext message.
    """
    raw_data = base64.b64decode(encrypted_message.encode())  # Decode Base64
    nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]  # Split into components
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Initialize cipher with nonce
    return cipher.decrypt_and_verify(ciphertext, tag).decode()  # Decrypt and verify

# Example usage
if __name__ == "__main__":
    key = b'sixteenbytekey!!'  # Ensure this is exactly 16 bytes for AES-128
    message = "Confidential Data"

    # Encrypt the message
    encrypted = encrypt_message(key, message)
    print(f"Encrypted Message: {encrypted}")

    # Decrypt the message
    decrypted = decrypt_message(key, encrypted)
    print(f"Decrypted Message: {decrypted}")