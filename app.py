from flask import Flask, request, render_template
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

app = Flask(__name__)

def generate_key(password, salt=b'static_salt'):
    """
    Derive a 16-byte key from the password using PBKDF2.
    """
    return PBKDF2(password, salt, dkLen=16)

def encrypt_text(plain_text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce  # Used for decryption
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_text(enc_text, key):
    try:
        data = base64.b64decode(enc_text)
        nonce = data[:16]  # Extract nonce
        tag = data[16:32]  # Extract tag
        ciphertext = data[32:]  # Extract encrypted text
        
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
        
        return decrypted_text.decode()
    except (ValueError, KeyError):
        return None  # Return None for incorrect password or corrupted data

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    password = request.form.get("password")
    text = request.form.get("text")
    
    if not password or not text:
        return render_template("index.html", error="Missing password or text")
    
    key = generate_key(password)
    encrypted_text = encrypt_text(text, key)
    return render_template("index.html", encrypted_text=encrypted_text)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    password = request.form.get("password")
    enc_text = request.form.get("encrypted_text")
    
    if not password or not enc_text:
        return render_template("index.html", error="Missing password or encrypted text")
    
    key = generate_key(password)
    decrypted_text = decrypt_text(enc_text, key)
    
    if decrypted_text is None:
        return render_template("index.html", error="Invalid password or corrupted data")
    
    return render_template("index.html", decrypted_text=decrypted_text)

if __name__ == "__main__":
    app.run(debug=True)