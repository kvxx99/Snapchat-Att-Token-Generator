# Snapchat Att-Token Generator (Python Implementation)

This repository provides a Python script that mimics the process used to generate a Snapchat `x-snapchat-att` token. The token is produced by encrypting an "Att" message with AES‑GCM using a randomly generated key and a specially constructed initialization vector (IV).

> **Disclaimer:** No share this
## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)

## Features

- **Random Key Generation:** Generates a secure, random 16‑byte key.
- **Custom IV Construction:** Simulates the AppleIv protobuf structure by constructing an 11‑byte IV and extending it to 12 bytes.
- **AES‑GCM Encryption:** Encrypts the padded "Att" message using AES‑GCM.
- **Packaging & Encoding:** Combines the key with the ciphertext, wraps the output in a custom binary format, and encodes it as a URL‑safe Base64 string.


1. **Clone the Repository:**
   ```bash
   cd Snapchat-Att-Token-Generator
   ```

2. **(Optional) Create a Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install pycryptodome
   ```

## Usage

The Python script is contained in `generate_att_token.py`. To generate a token, simply run:

```bash
python generate_att_token.py
```

By default, the script uses a dummy "Att" message (`b"dummy_att_message"`). To generate a token based on your actual Att message, modify the `dummy_att` variable in the script with your serialized Att message bytes.

## How It Works

1. **Key Generation & IV Construction:**
   - Generates a random 16‑byte key using a secure random generator.
   - Simulates the AppleIv structure by creating an 11‑byte value (e.g., `0x0a` followed by 10 zero bytes) and extending it to a 12‑byte IV by appending `0x01`.

2. **Data Padding:**
   - The Att message is padded so that its length is a multiple of 4 bytes, ensuring proper alignment for encryption.

3. **Encryption Process:**
   - The padded data is encrypted using AES‑GCM with the generated key and constructed IV.
   - AES‑GCM encryption outputs both the ciphertext and an authentication tag, which are concatenated.

4. **Packaging & Encoding:**
   - The key is prepended to the encrypted data.
   - A custom binary structure is built:
     - 1 byte indicating the IV length.
     - The IV (11 bytes).
     - 2 bytes indicating the length of the encrypted data (big‑endian).
     - The encrypted data (key + ciphertext + tag).
   - The entire byte sequence is then URL‑safe Base64 encoded (with trailing `=` signs removed) to produce the final `x-snapchat-att` token.

## Repository Structure

In addition to the Python script, this repository includes a folder containing source files from various platforms demonstrating how the att-token generation is integrated:

- **api/**
  - `ApiService.java` – Server-side implementation that builds the Att message and generates the token.
- **ios/**
  - `ios.js` – JavaScript code for hooking and logging on the iOS client.
- **android/**
  - `Snapchat.java` – Core logic for Snapchat operations on Android.
  - `SnapchatAndroid.java` – Android client implementation including att-token generation and debugging hooks
