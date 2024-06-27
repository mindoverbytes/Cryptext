# Cryptext

Cryptext is a Python GUI application that demonstrates secure text operations including AES symmetric encryption, RSA asymmetric encryption, and SHA-256 hashing. It uses the tkinter library for the graphical user interface and Crypto library for cryptographic operations.

### Features

Symmetric Encryption (AES):
- Encrypt and decrypt text using AES-256 encryption in GCM mode.

Asymmetric Encryption (RSA):
- Generate RSA public-private key pair (2048 bits).
- Encrypt and decrypt text using RSA encryption with OAEP padding.

Hashing (SHA-256):
- Generate SHA-256 hashes of input text.
- Verify if a given hash matches the SHA-256 hash of the input text.

### Usage

- **Encrypt (AES)**: Enter plaintext, click "Encrypt (AES)", and view encrypted text in the "Encrypted Text" field.

- **Decrypt (AES)**: Enter encrypted text, click "Decrypt (AES)", and view decrypted text in the "Decrypted Text" field.

- **Encrypt (RSA)**: Enter plaintext, click "Encrypt (RSA)", and view encrypted text in the "Encrypted Text" field.

- **Decrypt (RSA)**: Enter encrypted text, click "Decrypt (RSA)", and view decrypted text in the "Decrypted Text" field.

- **Generate Hash (SHA-256)**: Enter text, click "Generate Hash (SHA-256)", and view the hash value in the "Hash" field.

- **Verify Hash (SHA-256)**: Enter text and hash value, click "Verify Hash (SHA-256)", and see a message confirming if the hash matches.