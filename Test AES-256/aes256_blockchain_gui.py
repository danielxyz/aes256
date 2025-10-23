"""
Aplikasi Enkripsi AES-256 dengan GUI Modern Blockchain-Style
Enhanced dengan CustomTkinter, Animated Blocks, dan Transaction History
Author: Decky - Advanced Crypto Security Tool
"""

import customtkinter as ctk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
import base64
from datetime import datetime
import hashlib

# Set appearance mode and color theme
ctk.set_appearance_mode("dark")  # Modes: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"

class BlockchainStyleEncryption(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window configuration
        self.title("🔐 AES-256 Blockchain Encryption Suite")
        self.geometry("1200x800")

        # Encryption keys
        self.encryption_key = None
        self.mac_key = None

        # Transaction history (blockchain-style)
        self.transaction_history = []

        # Configure grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Create sidebar
        self.create_sidebar()

        # Create main content area
        self.create_main_content()

        # Create blockchain transaction panel
        self.create_blockchain_panel()

    def create_sidebar(self):
        """Create blockchain-style sidebar with controls"""
        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color="#1a1a2e")
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        # Logo/Title
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="⛓️ BLOCKCHAIN\nENCRYPTION", 
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#00d4ff"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Subtitle
        self.subtitle = ctk.CTkLabel(
            self.sidebar_frame, 
            text="AES-256-CBC + HMAC-SHA256", 
            font=ctk.CTkFont(size=12),
            text_color="#7f8c8d"
        )
        self.subtitle.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Key Management Section
        self.key_section_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🔑 Key Management",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.key_section_label.grid(row=2, column=0, padx=20, pady=(10, 5))

        # Generate Key Button
        self.generate_key_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🎲 Generate Master Key",
            command=self.generate_keys,
            fg_color="#00d4ff",
            hover_color="#0099cc",
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.generate_key_btn.grid(row=3, column=0, padx=20, pady=10)

        # Key Display
        self.key_textbox = ctk.CTkTextbox(
            self.sidebar_frame,
            height=80,
            font=ctk.CTkFont(family="Courier", size=10)
        )
        self.key_textbox.grid(row=4, column=0, padx=20, pady=5, sticky="ew")
        self.key_textbox.insert("1.0", "No key generated yet...")
        self.key_textbox.configure(state="disabled")

        # Action Buttons
        self.encrypt_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🔒 ENCRYPT",
            command=self.encrypt_action,
            fg_color="#2ecc71",
            hover_color="#27ae60",
            height=45,
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.encrypt_btn.grid(row=5, column=0, padx=20, pady=(20, 10))

        self.decrypt_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🔓 DECRYPT",
            command=self.decrypt_action,
            fg_color="#e74c3c",
            hover_color="#c0392b",
            height=45,
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.decrypt_btn.grid(row=6, column=0, padx=20, pady=10)

        self.clear_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🗑️ Clear All",
            command=self.clear_all,
            fg_color="#95a5a6",
            hover_color="#7f8c8d",
            height=35
        )
        self.clear_btn.grid(row=7, column=0, padx=20, pady=10)

        # Stats at bottom
        self.stats_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Transactions: 0\nBlocks Mined: 0",
            font=ctk.CTkFont(size=11),
            text_color="#7f8c8d"
        )
        self.stats_label.grid(row=9, column=0, padx=20, pady=(0, 20))

    def create_main_content(self):
        """Create main content area with input/output"""
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#16213e")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(3, weight=1)

        # Input Section
        self.input_label = ctk.CTkLabel(
            self.main_frame,
            text="📝 Input Data",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.input_label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")

        self.input_textbox = ctk.CTkTextbox(
            self.main_frame,
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="word"
        )
        self.input_textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

        # Output Section
        self.output_label = ctk.CTkLabel(
            self.main_frame,
            text="📤 Output / Encrypted Data",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.output_label.grid(row=2, column=0, padx=20, pady=(10, 5), sticky="w")

        self.output_textbox = ctk.CTkTextbox(
            self.main_frame,
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="word",
            fg_color="#0f3460"
        )
        self.output_textbox.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")

    def create_blockchain_panel(self):
        """Create blockchain transaction history panel"""
        self.blockchain_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1a2e")
        self.blockchain_frame.grid(row=1, column=1, padx=20, pady=(0, 20), sticky="nsew")
        self.blockchain_frame.grid_columnconfigure(0, weight=1)
        self.blockchain_frame.grid_rowconfigure(1, weight=1)

        # Header
        self.blockchain_label = ctk.CTkLabel(
            self.blockchain_frame,
            text="⛓️ Blockchain Transaction Log",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#00d4ff"
        )
        self.blockchain_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        # Transaction list
        self.transaction_textbox = ctk.CTkTextbox(
            self.blockchain_frame,
            font=ctk.CTkFont(family="Courier", size=11),
            height=180,
            fg_color="#0f0f1e"
        )
        self.transaction_textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.transaction_textbox.insert("1.0", "💎 No transactions yet. Start by generating a key!\n")

    def generate_keys(self):
        """Generate master encryption and MAC keys"""
        master_key = os.urandom(64)
        self.encryption_key = master_key[:32]
        self.mac_key = master_key[32:]

        key_b64 = base64.urlsafe_b64encode(master_key).decode('utf-8')

        # Update key display
        self.key_textbox.configure(state="normal")
        self.key_textbox.delete("1.0", "end")
        self.key_textbox.insert("1.0", f"Master Key (64 bytes):\n{key_b64[:50]}...\n{key_b64[50:]}")
        self.key_textbox.configure(state="disabled")

        # Add to blockchain log
        self.add_transaction("KEY_GENERATION", "Master key generated (64 bytes = 512 bits)")

        messagebox.showinfo(
            "✅ Key Generated", 
            "Master key successfully generated!\n\n"
            "🔐 Encryption: 32 bytes (AES-256)\n"
            "🔏 MAC: 32 bytes (HMAC-SHA256)"
        )

    def pad(self, data):
        """PKCS7 padding"""
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        return padder.update(data) + padder.finalize()

    def unpad(self, padded_data):
        """Remove PKCS7 padding"""
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def encrypt(self, text):
        """Encrypt with AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)"""
        # Generate IV
        iv = os.urandom(16)

        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        padded_text = self.pad(text.encode('utf-8'))
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()

        # Compute HMAC
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        mac = h.finalize()

        # Combine
        combined = iv + ciphertext + mac
        return base64.urlsafe_b64encode(combined).decode('utf-8')

    def decrypt(self, encrypted_data):
        """Decrypt and verify HMAC"""
        # Decode
        data = base64.urlsafe_b64decode(encrypted_data)

        if len(data) < 48:
            raise ValueError("Data too short")

        iv = data[:16]
        mac_received = data[-32:]
        ciphertext = data[16:-32]

        # Verify HMAC
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        try:
            h.verify(mac_received)
        except Exception:
            raise ValueError("⚠️ HMAC verification failed! Data may be tampered!")

        # Decrypt
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_text = decryptor.update(ciphertext) + decryptor.finalize()

        return self.unpad(padded_text).decode('utf-8')

    def encrypt_action(self):
        """Handle encrypt button"""
        if not self.encryption_key or not self.mac_key:
            messagebox.showerror("❌ Error", "Please generate a master key first!")
            return

        text = self.input_textbox.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showerror("❌ Error", "Please enter text to encrypt!")
            return

        try:
            encrypted = self.encrypt(text)
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("1.0", encrypted)

            # Add to blockchain
            data_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
            self.add_transaction(
                "ENCRYPT",
                f"Data encrypted | Hash: {data_hash} | Size: {len(encrypted)} chars"
            )

            messagebox.showinfo("✅ Success", "Data encrypted successfully with HMAC protection!")
        except Exception as e:
            messagebox.showerror("❌ Error", f"Encryption failed: {str(e)}")

    def decrypt_action(self):
        """Handle decrypt button"""
        if not self.encryption_key or not self.mac_key:
            messagebox.showerror("❌ Error", "Please generate a master key first!")
            return

        ciphertext = self.input_textbox.get("1.0", "end-1c").strip()
        if not ciphertext:
            messagebox.showerror("❌ Error", "Please enter ciphertext to decrypt!")
            return

        try:
            decrypted = self.decrypt(ciphertext)
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("1.0", decrypted)

            # Add to blockchain
            self.add_transaction(
                "DECRYPT",
                f"Data decrypted | HMAC verified ✓ | Size: {len(decrypted)} chars"
            )

            messagebox.showinfo("✅ Success", "Data decrypted successfully! HMAC verified ✓")
        except Exception as e:
            messagebox.showerror("❌ Error", f"Decryption failed: {str(e)}")

    def add_transaction(self, tx_type, details):
        """Add transaction to blockchain log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        block_num = len(self.transaction_history) + 1

        tx = {
            "block": block_num,
            "type": tx_type,
            "details": details,
            "timestamp": timestamp
        }

        self.transaction_history.append(tx)

        # Update display
        if tx_type == "KEY_GENERATION":
            icon = "🔑"
            color = "cyan"
        elif tx_type == "ENCRYPT":
            icon = "🔒"
            color = "green"
        elif tx_type == "DECRYPT":
            icon = "🔓"
            color = "red"
        else:
            icon = "📦"
            color = "white"

        tx_text = f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        tx_text += f"Block #{block_num:03d} | {timestamp}\n"
        tx_text += f"{icon} {tx_type}\n"
        tx_text += f"└─ {details}\n"

        self.transaction_textbox.insert("end", tx_text)
        self.transaction_textbox.see("end")

        # Update stats
        self.stats_label.configure(
            text=f"Transactions: {len(self.transaction_history)}\nBlocks Mined: {block_num}"
        )

    def clear_all(self):
        """Clear all fields"""
        self.input_textbox.delete("1.0", "end")
        self.output_textbox.delete("1.0", "end")
        messagebox.showinfo("🗑️ Cleared", "All fields have been cleared!")

def main():
    app = BlockchainStyleEncryption()
    app.mainloop()

if __name__ == "__main__":
    main()
