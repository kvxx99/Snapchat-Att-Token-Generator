#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad_data(data: bytes) -> bytes:
    # Calculate padding amount: always add 1 to 4 bytes (if data length is already multiple of 4, add 4)
    pad = 4 - (len(data) % 4)
    if pad == 0:
        pad = 4
    return data + bytes([pad] * pad)

def generate_att_token(att_bytes: bytes) -> str:
    # 1. Generate a random 16-byte key
    key = get_random_bytes(16)

    # 2. Simulate the AppleIv protobuf:
    # In the Java code, AppleIv is built with:
    #   a1 = 0xa, magic = getIvMagic(), isAndroid = false, a4 = false
    # For our purposes, we use a fixed 11-byte value (for example, 0x0a followed by 10 zeros)
    apple_iv_bytes = b'\x0a' + b'\x00' * 10  # 11 bytes

    # 3. Build a 12-byte IV for AES-GCM: copy the 11 bytes and append a 0x01 at the end
    iv = apple_iv_bytes + b'\x01'  # 12 bytes total

    # 4. Pad the Att message to a multiple of 4 bytes
    data = pad_data(att_bytes)

    # 5. Encrypt the padded data with AES-GCM using the random key and IV (no additional associated data)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # In the Java code, the ciphertext and tag are concatenated.
    encrypted_aes_gcm = ciphertext + tag

    # 6. Prepend the key to the encrypted data (as done in the Java code)
    encrypted = key + encrypted_aes_gcm

    # 7. Build the EncryptedData "structure"
    # The Java code creates a protobuf with fields:
    #    iv (set to the original apple_iv_bytes, i.e. 11 bytes)
    #    data (the combined key + encrypted payload)
    # Here we simulate a simple binary encoding:
    #   - 1 byte: length of iv (should be 11)
    #   - iv bytes (11 bytes)
    #   - 2 bytes: length of encrypted data (big-endian)
    #   - encrypted data
    iv_length = len(apple_iv_bytes)
    encrypted_length = len(encrypted)
    final_bytes = (
        iv_length.to_bytes(1, byteorder='big') +
        apple_iv_bytes +
        encrypted_length.to_bytes(2, byteorder='big') +
        encrypted
    )

    # 8. Base64 URL-safe encode the final bytes (strip any trailing '=' for URL safety)
    token = base64.urlsafe_b64encode(final_bytes).rstrip(b'=').decode('utf-8')
    return token

if __name__ == '__main__':
    # Example: use a dummy Att message.
    # In the real implementation, this should be the serialized bytes from your Att protobuf.
    dummy_att = b"dummy_att_message"
    att_token = generate_att_token(dummy_att)
    print("x-snapchat-att:", att_token)
