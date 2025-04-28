# RSA Key Generator and Encryption/Decryption + Signing/Verification

This project implements RSA key pair generation for encryption/decryption and signing/verification, along with functionality to encrypt and decrypt messages, as well as sign and verify messages. The frontend is built using HTML, CSS, and JavaScript with the `crypto.subtle` API for cryptographic operations.

## Features

- **RSA Key Generation (Encryption/Decryption)**: Generate public and private keys for encryption and decryption.
- **Message Encryption & Decryption**: Encrypt messages using the public key and decrypt them using the private key.
- **RSA Key Generation (Signing/Verification)**: Generate signing keys (public and private) for digital signatures.
- **Message Signing & Verification**: Sign messages using the private key and verify signatures using the public key.

## Files

- `index.html`: Main HTML file with the user interface.
- `q.js`: JavaScript file containing all the functions for RSA key generation, message encryption/decryption, and signing/verification.
- `q.css`: CSS file for styling the web interface.

## How to Use

1. **Generate Encryption Keys**: Click the "Generate Encryption Keys" button to generate a pair of RSA keys for encryption and decryption.
2. **Encryption / Decryption**:
   - Enter the message you want to encrypt and click the "Encrypt" button.
   - The encrypted message (in Base64 format) will be shown. You can then decrypt it by clicking the "Decrypt" button.
3. **Generate Signing Keys**: Click the "Generate Signing Keys" button to generate a pair of RSA keys for signing and verifying messages.
4. **Sign a Message**: Enter a message and click the "Sign Message" button to generate a digital signature for the message.
5. **Verify a Signature**: Enter the original message and the signature, then click the "Verify Signature" button to verify the authenticity of the message.

## How to Run

1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
Navigate to the project folder:

bash
Copy
Edit
cd YOUR_REPO_NAME
Open the index.html file in your browser to use the RSA encryption, decryption, signing, and verification tool.

Example Use Cases
Encrypt sensitive information to be sent securely, and only the intended recipient can decrypt it with their private key.

Sign documents/messages to prove their authenticity, and anyone can verify the signature using the public key.

Dependencies
This project uses the crypto.subtle Web Cryptography API, which is built into modern web browsers (e.g., Chrome, Firefox, Edge). No external libraries are required.