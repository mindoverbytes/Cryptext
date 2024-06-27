import tkinter as tk
from tkinter import messagebox, simpledialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import hashlib

# Symmetric Encryption (AES)
def generate_aes_key():
    return get_random_bytes(32)

def encrypt_aes(text, key):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return b64encode(nonce + tag + ciphertext).decode('utf-8')

def decrypt_aes(enc_text, key):
    enc_data = b64decode(enc_text)
    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Asymmetric Encryption (RSA)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return b64encode(cipher.encrypt(text.encode('utf-8'))).decode('utf-8')

def decrypt_rsa(enc_text, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(b64decode(enc_text)).decode('utf-8')

# Hashing (SHA)
def generate_sha256_hash(text):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(text.encode('utf-8'))
    return sha256_hash.hexdigest()

def verify_sha256_hash(text, hash_value):
    return generate_sha256_hash(text) == hash_value

class CryptextApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptext")

        self.label_plaintext = tk.Label(root, text="Plaintext:")
        self.label_plaintext.grid(row=0, column=0, padx=10, pady=10)
        self.text_plaintext = tk.Text(root, height=5, width=50)
        self.text_plaintext.grid(row=1, column=0, padx=10, pady=10)

        self.label_encrypted = tk.Label(root, text="Encrypted Text:")
        self.label_encrypted.grid(row=0, column=1, padx=10, pady=10)
        self.text_encrypted = tk.Text(root, height=5, width=50)
        self.text_encrypted.grid(row=1, column=1, padx=10, pady=10)

        self.label_decrypted = tk.Label(root, text="Decrypted Text:")
        self.label_decrypted.grid(row=2, column=0, padx=10, pady=10)
        self.text_decrypted = tk.Text(root, height=5, width=50)
        self.text_decrypted.grid(row=3, column=0, padx=10, pady=10)

        self.label_hash = tk.Label(root, text="Hash:")
        self.label_hash.grid(row=2, column=1, padx=10, pady=10)
        self.text_hash = tk.Text(root, height=5, width=50)
        self.text_hash.grid(row=3, column=1, padx=10, pady=10)

        self.label_hash_to_verify = tk.Label(root, text="Hash to Verify:")
        self.label_hash_to_verify.grid(row=4, column=0, padx=10, pady=10)
        self.text_hash_to_verify = tk.Text(root, height=2, width=50)
        self.text_hash_to_verify.grid(row=5, column=0, padx=10, pady=10)

        self.enc_aes_btn = tk.Button(root, text="Encrypt (AES)", command=self.encrypt_text_aes)
        self.enc_aes_btn.grid(row=6, column=0, padx=10, pady=10)

        self.dec_aes_btn = tk.Button(root, text="Decrypt (AES)", command=self.decrypt_text_aes)
        self.dec_aes_btn.grid(row=6, column=1, padx=10, pady=10)

        self.enc_rsa_btn = tk.Button(root, text="Encrypt (RSA)", command=self.encrypt_text_rsa)
        self.enc_rsa_btn.grid(row=7, column=0, padx=10, pady=10)

        self.dec_rsa_btn = tk.Button(root, text="Decrypt (RSA)", command=self.decrypt_text_rsa)
        self.dec_rsa_btn.grid(row=7, column=1, padx=10, pady=10)

        self.hash_btn = tk.Button(root, text="Generate Hash (SHA-256)", command=self.generate_hash)
        self.hash_btn.grid(row=8, column=0, padx=10, pady=10)

        self.verify_btn = tk.Button(root, text="Verify Hash (SHA-256)", command=self.verify_hash)
        self.verify_btn.grid(row=8, column=1, padx=10, pady=10)

        self.key = generate_aes_key()
        self.private_key, self.public_key = generate_rsa_keys()

    def encrypt_text_aes(self):
        text = self.text_plaintext.get("1.0", tk.END).strip()
        if text:
            encrypted_text = encrypt_aes(text, self.key)
            self.text_encrypted.delete("1.0", tk.END)
            self.text_encrypted.insert(tk.END, encrypted_text)
        else:
            messagebox.showerror("Error", "No text provided!")

    def decrypt_text_aes(self):
        enc_text = self.text_encrypted.get("1.0", tk.END).strip()
        if enc_text:
            try:
                decrypted_text = decrypt_aes(enc_text, self.key)
                self.text_decrypted.delete("1.0", tk.END)
                self.text_decrypted.insert(tk.END, decrypted_text)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        else:
            messagebox.showerror("Error", "No text provided!")

    def encrypt_text_rsa(self):
        text = self.text_plaintext.get("1.0", tk.END).strip()
        if text:
            encrypted_text = encrypt_rsa(text, self.public_key)
            self.text_encrypted.delete("1.0", tk.END)
            self.text_encrypted.insert(tk.END, encrypted_text)
        else:
            messagebox.showerror("Error", "No text provided!")

    def decrypt_text_rsa(self):
        enc_text = self.text_encrypted.get("1.0", tk.END).strip()
        if enc_text:
            try:
                decrypted_text = decrypt_rsa(enc_text, self.private_key)
                self.text_decrypted.delete("1.0", tk.END)
                self.text_decrypted.insert(tk.END, decrypted_text)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        else:
            messagebox.showerror("Error", "No text provided!")

    def generate_hash(self):
        text = self.text_plaintext.get("1.0", tk.END).strip()
        if text:
            hash_value = generate_sha256_hash(text)
            self.text_hash.delete("1.0", tk.END)
            self.text_hash.insert(tk.END, hash_value)
        else:
            messagebox.showerror("Error", "No text provided!")

    def verify_hash(self):
        text = self.text_plaintext.get("1.0", tk.END).strip()
        hash_value = self.text_hash_to_verify.get("1.0", tk.END).strip()
        if text and hash_value:
            if verify_sha256_hash(text, hash_value):
                messagebox.showinfo("Success", "Hash verification succeeded!")
            else:
                messagebox.showerror("Error", "Hash verification failed!")
        else:
            messagebox.showerror("Error", "No text or hash value provided!")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptextApp(root)
    root.mainloop()
