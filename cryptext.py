import tkinter as tk
from tkinter import simpledialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import hashlib

class CryptextApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptext")

        self.content_frame = tk.Frame(root, padx=20, pady=20)
        self.content_frame.pack()

        self.label_plaintext = tk.Label(self.content_frame, text="Plaintext:")
        self.label_plaintext.grid(row=0, column=0, padx=10, pady=10)
        self.text_plaintext = tk.Text(self.content_frame, height=5, width=50)
        self.text_plaintext.grid(row=1, column=0, padx=10, pady=10)

        self.label_encrypted = tk.Label(self.content_frame, text="Encrypted Text:")
        self.label_encrypted.grid(row=0, column=1, padx=10, pady=10)
        self.text_encrypted = tk.Text(self.content_frame, height=5, width=50)
        self.text_encrypted.grid(row=1, column=1, padx=10, pady=10)

        self.label_decrypted = tk.Label(self.content_frame, text="Decrypted Text:")
        self.label_decrypted.grid(row=2, column=0, padx=10, pady=10)
        self.text_decrypted = tk.Text(self.content_frame, height=5, width=50)
        self.text_decrypted.grid(row=3, column=0, padx=10, pady=10)

        self.label_hash = tk.Label(self.content_frame, text="Hash:")
        self.label_hash.grid(row=2, column=1, padx=10, pady=10)
        self.text_hash = tk.Text(self.content_frame, height=5, width=50)
        self.text_hash.grid(row=3, column=1, padx=10, pady=10)

        self.label_hash_to_verify = tk.Label(self.content_frame, text="Hash to Verify:")
        self.label_hash_to_verify.grid(row=4, column=0, padx=10, pady=10)
        self.text_hash_to_verify = tk.Text(self.content_frame, height=5, width=50)
        self.text_hash_to_verify.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        self.frame_aes_keys = tk.LabelFrame(self.content_frame, text="AES Key and IV", padx=10, pady=10)
        self.frame_aes_keys.grid(row=6, column=0, padx=10, pady=10, sticky="ew")

        self.label_aes_key = tk.Label(self.frame_aes_keys, text="AES Key:")
        self.label_aes_key.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_aes_key = tk.Entry(self.frame_aes_keys, width=50)
        self.entry_aes_key.grid(row=0, column=1, padx=5, pady=5)

        self.label_aes_iv = tk.Label(self.frame_aes_keys, text="AES IV:")
        self.label_aes_iv.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.entry_aes_iv = tk.Entry(self.frame_aes_keys, width=50)
        self.entry_aes_iv.grid(row=1, column=1, padx=5, pady=5)

        self.frame_rsa_keys = tk.LabelFrame(self.content_frame, text="RSA Keys", padx=10, pady=10)
        self.frame_rsa_keys.grid(row=6, column=1, padx=10, pady=10, sticky="ew")

        self.label_rsa_public_key = tk.Label(self.frame_rsa_keys, text="RSA Public Key:")
        self.label_rsa_public_key.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_rsa_public_key = tk.Entry(self.frame_rsa_keys, width=50)
        self.entry_rsa_public_key.grid(row=0, column=1, padx=5, pady=5)

        self.label_rsa_private_key = tk.Label(self.frame_rsa_keys, text="RSA Private Key:")
        self.label_rsa_private_key.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.entry_rsa_private_key = tk.Entry(self.frame_rsa_keys, width=50)
        self.entry_rsa_private_key.grid(row=1, column=1, padx=5, pady=5)

        self.enc_aes_btn = tk.Button(self.content_frame, text="Encrypt (AES)", command=self.encrypt_text_aes)
        self.enc_aes_btn.grid(row=7, column=0, padx=10, pady=10)

        self.dec_aes_btn = tk.Button(self.content_frame, text="Decrypt (AES)", command=self.decrypt_text_aes)
        self.dec_aes_btn.grid(row=7, column=1, padx=10, pady=10)

        self.enc_rsa_btn = tk.Button(self.content_frame, text="Encrypt (RSA)", command=self.encrypt_text_rsa)
        self.enc_rsa_btn.grid(row=8, column=0, padx=10, pady=10)

        self.dec_rsa_btn = tk.Button(self.content_frame, text="Decrypt (RSA)", command=self.decrypt_text_rsa)
        self.dec_rsa_btn.grid(row=8, column=1, padx=10, pady=10)

        self.hash_btn = tk.Button(self.content_frame, text="Generate Hash (SHA-256)", command=self.generate_hash)
        self.hash_btn.grid(row=9, column=0, padx=10, pady=10)

        self.verify_btn = tk.Button(self.content_frame, text="Verify Hash (SHA-256)", command=self.verify_hash)
        self.verify_btn.grid(row=9, column=1, padx=10, pady=10)

        self.clean_btn = tk.Button(self.content_frame, text="Clean", command=self.clean_text_fields)
        self.clean_btn.grid(row=10, column=0, padx=10, pady=10)

        self.regenerate_btn = tk.Button(self.content_frame, text="Regenerate Keys & IV", command=self.regenerate_keys)
        self.regenerate_btn.grid(row=10, column=1, padx=10, pady=10)

        self.status_bar = tk.Label(self.content_frame, text="", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=11, column=0, columnspan=2, sticky="we")

        self.key = None
        self.iv = None
        self.private_key = None
        self.public_key = None
        self.generate_keys()

        self.text_plaintext.focus_set()

    def generate_keys(self):
        self.key = get_random_bytes(32)
        self.iv = get_random_bytes(16)
        key_pair = RSA.generate(2048)
        self.private_key = key_pair.export_key()
        self.public_key = key_pair.publickey().export_key()

        self.update_aes_keys()
        self.update_rsa_keys()
        self.set_message("Initial keys generated.")

    def update_aes_keys(self):
        if self.key:
            self.entry_aes_key.delete(0, tk.END)
            self.entry_aes_key.insert(0, self.key.hex())
        if self.iv:
            self.entry_aes_iv.delete(0, tk.END)
            self.entry_aes_iv.insert(0, self.iv.hex())

    def update_rsa_keys(self):
        if self.public_key:
            self.entry_rsa_public_key.delete(0, tk.END)
            self.entry_rsa_public_key.insert(0, self.public_key.decode("utf-8"))
        if self.private_key:
            self.entry_rsa_private_key.delete(0, tk.END)
            self.entry_rsa_private_key.insert(0, self.private_key.decode("utf-8"))

    def save_to_variables(self):
        try:
            self.key = bytes.fromhex(self.entry_aes_key.get().strip())
            self.iv = bytes.fromhex(self.entry_aes_iv.get().strip())
            self.public_key = self.entry_rsa_public_key.get().encode("utf-8")
            self.private_key = self.entry_rsa_private_key.get().encode("utf-8")
            self.set_message("Variables updated with current keys and IV.")
        except ValueError:
            self.set_message("Error: Invalid hexadecimal input for AES key or IV.", is_error=True)

    def encrypt_text_aes(self):
        self.save_to_variables()
        text = self.text_plaintext.get("1.0", tk.END).strip()
        if text:
            try:
                encrypted_text = encrypt_aes(text, self.key, self.iv)
                self.text_encrypted.delete("1.0", tk.END)
                self.text_encrypted.insert(tk.END, encrypted_text)
                self.set_message("Text encrypted successfully.")
            except Exception as e:
                self.set_message(f"Encryption failed: {e}", is_error=True)
        else:
            self.set_message("Error: No text provided!", is_error=True)

    def decrypt_text_aes(self):
        self.save_to_variables()
        enc_text = self.text_encrypted.get("1.0", tk.END).strip()
        if enc_text:
            try:
                decrypted_text = decrypt_aes(enc_text, self.key, self.iv)
                if decrypted_text:
                    self.text_decrypted.delete("1.0", tk.END)
                    self.text_decrypted.insert(tk.END, decrypted_text)
                    self.set_message("Text decrypted successfully.")
                else:
                    self.set_message("Decryption failed: Incorrect key or IV.", is_error=True)
            except Exception as e:
                self.set_message(f"Decryption failed: {e}", is_error=True)
        else:
            self.set_message("Error: No encrypted text provided!", is_error=True)

    def encrypt_text_rsa(self):
        self.save_to_variables()
        text = self.text_plaintext.get("1.0", tk.END).strip()
        if text:
            try:
                encrypted_text = encrypt_rsa(text, self.public_key)
                self.text_encrypted.delete("1.0", tk.END)
                self.text_encrypted.insert(tk.END, encrypted_text)
                self.set_message("Text encrypted with RSA successfully.")
            except Exception as e:
                self.set_message(f"RSA encryption failed: {e}", is_error=True)
        else:
            self.set_message("Error: No text provided!", is_error=True)

    def decrypt_text_rsa(self):
        self.save_to_variables()
        enc_text = self.text_encrypted.get("1.0", tk.END).strip()
        if enc_text:
            try:
                decrypted_text = decrypt_rsa(enc_text, self.private_key)
                self.text_decrypted.delete("1.0", tk.END)
                self.text_decrypted.insert(tk.END, decrypted_text)
                self.set_message("Text decrypted with RSA successfully.")
            except Exception as e:
                self.set_message(f"RSA decryption failed: {e}", is_error=True)
        else:
            self.set_message("Error: No encrypted text provided!", is_error=True)

    def generate_hash(self):
        text = self.text_plaintext.get("1.0", tk.END).strip()
        if text:
            try:
                hashed_text = hash_text(text)
                self.text_hash.delete("1.0", tk.END)
                self.text_hash.insert(tk.END, hashed_text)
                self.set_message("Hash generated successfully.")
            except Exception as e:
                self.set_message(f"Hash generation failed: {e}", is_error=True)
        else:
            self.set_message("Error: No text provided!", is_error=True)

    def verify_hash(self):
        text = self.text_plaintext.get("1.0", tk.END).strip()
        hash_to_verify = self.text_hash_to_verify.get("1.0", tk.END).strip()
        if text and hash_to_verify:
            try:
                is_verified = verify_hash(text, hash_to_verify)
                if is_verified:
                    self.set_message("Hash verified successfully.")
                else:
                    self.set_message("Hash verification failed.", is_error=True)
            except Exception as e:
                self.set_message(f"Hash verification failed: {e}", is_error=True)
        else:
            self.set_message("Error: Missing text or hash to verify!", is_error=True)

    def clean_text_fields(self):
        self.text_plaintext.delete("1.0", tk.END)
        self.text_encrypted.delete("1.0", tk.END)
        self.text_decrypted.delete("1.0", tk.END)
        self.text_hash.delete("1.0", tk.END)
        self.text_hash_to_verify.delete("1.0", tk.END)
        self.set_message("Text fields cleaned.")

    def regenerate_keys(self):
        self.generate_keys()
        self.update_aes_keys()
        self.update_rsa_keys()

    def set_message(self, message, is_error=False):
        if is_error:
            self.status_bar.config(text=f"Error: {message}", fg="red")
        else:
            self.status_bar.config(text=message, fg="black")

def encrypt_aes(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext).encode())
    return b64encode(ciphertext).decode()

def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(b64decode(ciphertext))).decode()
    return decrypted

def encrypt_rsa(plaintext, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_text = cipher_rsa.encrypt(plaintext.encode())
    return b64encode(encrypted_text).decode()

def decrypt_rsa(ciphertext, private_key):
    private_key_obj = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    decrypted_text = cipher_rsa.decrypt(b64decode(ciphertext))
    return decrypted_text.decode()

def hash_text(text):
    hashed = hashlib.sha256(text.encode()).hexdigest()
    return hashed

def verify_hash(text, hash_to_verify):
    return hash_text(text) == hash_to_verify

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptextApp(root)
    root.mainloop()
