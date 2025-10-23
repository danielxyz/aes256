import tkinter as tk 
from tkinter import messagebox 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import padding 
from cryptography.hazmat.backends import default_backend 
import os 
import base64 
 
def generate_key(): 
    """Generate a random 256-bit key.""" 
    return os.urandom(32) 
 
def pad(data): 
    """Pad the data to be multiple of block size.""" 
    padder = padding.PKCS7(algorithms.AES.block_size).padder() 
    padded_data = padder.update(data) + padder.finalize() 
    return padded_data 
 
def unpad(padded_data): 
    """Unpad the data.""" 
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder() 
    data = unpadder.update(padded_data) + unpadder.finalize() 
    return data 
 
def encrypt(text, key): 
    """Encrypt the text using AES-256-CBC.""" 
    try: 
        iv = os.urandom(16)  # Initialization Vector 
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) 
        encryptor = cipher.encryptor() 
        padded_text = pad(text.encode('utf-8')) 
        ct = encryptor.update(padded_text) + encryptor.finalize() 
        # Combine IV and ciphertext, then base64 encode for easy display 
        return base64.urlsafe_b64encode(iv + ct).decode('utf-8') 
    except Exception as e: 
        return str(e) 
 
def decrypt(ciphertext, key): 
    """Decrypt the ciphertext using AES-256-CBC.""" 
    try: 
        data = base64.urlsafe_b64decode(ciphertext) 
        iv = data[:16] 
        ct = data[16:] 
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) 
        decryptor = cipher.decryptor() 
        padded_text = decryptor.update(ct) + decryptor.finalize() 
        return unpad(padded_text).decode('utf-8') 
    except Exception as e: 
        return str(e) 
 
# GUI Setup 
root = tk.Tk() 
root.title("AES-256 Encrypt/Decrypt") 
root.geometry("500x400") 
 
# Key Section 
key_label = tk.Label(root, text="Key (32 bytes, base64 encoded):") 
key_label.pack(pady=5) 
key_entry = tk.Entry(root, width=50) 
key_entry.pack() 
 
def generate_key_btn(): 
    key = generate_key() 
    key_b64 = base64.urlsafe_b64encode(key).decode('utf-8') 
    key_entry.delete(0, tk.END) 
    key_entry.insert(0, key_b64) 
    messagebox.showinfo("Key Generated", "Key telah digenerate dan dimasukkan ke field.") 
 
gen_key_button = tk.Button(root, text="Generate Key", command=generate_key_btn) 
gen_key_button.pack(pady=5) 
 
# Input Text 
input_label = tk.Label(root, text="Input Text:") 
input_label.pack(pady=5) 
input_text = tk.Text(root, height=5, width=50) 
input_text.pack() 
 
# Output Text 
output_label = tk.Label(root, text="Output:") 
output_label.pack(pady=5) 
output_text = tk.Text(root, height=5, width=50) 
output_text.pack() 
 
def encrypt_btn(): 
    text = input_text.get("1.0", tk.END).strip() 
    key_b64 = key_entry.get().strip() 
    if not text or not key_b64: 
        messagebox.showerror("Error", "Masukkan text dan key!") 
        return 
    try: 
        key = base64.urlsafe_b64decode(key_b64) 
        if len(key) != 32: 
            raise ValueError("Key harus 32 bytes!") 
        encrypted = encrypt(text, key) 
        output_text.delete("1.0", tk.END) 
        output_text.insert(tk.END, encrypted) 
    except Exception as e: 
        messagebox.showerror("Error", str(e)) 
 
def decrypt_btn(): 
    ciphertext = input_text.get("1.0", tk.END).strip() 
    key_b64 = key_entry.get().strip() 
    if not ciphertext or not key_b64: 
        messagebox.showerror("Error", "Masukkan ciphertext dan key!") 
        return 
    try: 
        key = base64.urlsafe_b64decode(key_b64) 
        if len(key) != 32: 
            raise ValueError("Key harus 32 bytes!") 
        decrypted = decrypt(ciphertext, key) 
        output_text.delete("1.0", tk.END) 
        output_text.insert(tk.END, decrypted) 
    except Exception as e: 
        messagebox.showerror("Error", str(e)) 
 
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_btn) 
encrypt_button.pack(side=tk.LEFT, padx=10, pady=10) 
 
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_btn) 
decrypt_button.pack(side=tk.RIGHT, padx=10, pady=10) 
 
root.mainloop() 