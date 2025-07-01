from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from PIL import Image, ImageDraw, ImageFont
import os
import base64

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def sign_metadata(metadata, private_key):
    h = SHA256.new(metadata.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(h)
    return signature  # Trả về bytes

def verify_signature(metadata, signature, public_key):
    h = SHA256.new(metadata.encode('utf-8'))
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_session_key(session_key, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(session_key)

def decrypt_session_key(encrypted_session_key, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    try:
        return cipher.decrypt(encrypted_session_key)
    except ValueError:
        return None

def add_watermark(input_path, output_path, watermark_text):
    image = Image.open(input_path)
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.text((10, 10), watermark_text, fill=(255, 255, 255))
    image.save(output_path)

def encrypt_file(file_path, session_key):
    cipher = DES.new(session_key, DES.MODE_CBC)
    iv = cipher.iv
    with open(file_path, 'rb') as f:
        data = f.read()
    padding_length = 8 - (len(data) % 8)
    data += bytes([padding_length] * padding_length)
    ciphertext = cipher.encrypt(data)
    return iv, ciphertext

def decrypt_file(iv, ciphertext, session_key, output_path):
    cipher = DES.new(session_key, DES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    with open(output_path, 'wb') as f:
        f.write(plaintext)

def calculate_hash(iv, ciphertext):
    h = SHA256.new()
    h.update(iv)
    h.update(ciphertext)
    return h.hexdigest()

def verify_hash(iv, ciphertext, hash_value):
    h = SHA256.new()
    h.update(iv)
    h.update(ciphertext)
    return h.hexdigest() == hash_value