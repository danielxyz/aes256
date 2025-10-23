"""
AES-256 Blockchain Crypto Suite - All-in-One Super Features (FIXED)
Author: Decky (+ Perplexity AI)
Req: pip install customtkinter cryptography qrcode pillow pandas
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
import os, base64, json, random, hashlib
from datetime import datetime
import pandas as pd
import qrcode
from PIL import Image, ImageTk

### -------- APP CONFIG -------- ###
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# === UTILITY ===
def base64_clean(s): return base64.urlsafe_b64encode(s).decode("utf-8")
def base64_restore(s): return base64.urlsafe_b64decode(s)
def random_bytes(n=32): return os.urandom(n)
def sha256hex(data: bytes): return hashlib.sha256(data).hexdigest()
def gen_profile_id(): return "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", k=8))

### -------- DATA MODELS -------- ###
class KeyProfile:
    def __init__(self, name, master_key64, profile_id=None):
        self.profile_id = profile_id or gen_profile_id()
        self.name = name
        self.master_key64 = master_key64
    def get_keys(self):
        raw = base64_restore(self.master_key64)
        return raw[:32], raw[32:]

### --------- APP MAIN --------- ###
class BlockchainAES(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔒 AES-256 Blockchain Suite")
        self.geometry("1400x850")

        # DATA
        self.active_key = None
        self.key_profiles = []
        self.cur_profile = None
        self.blockchain = []

        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure((0,1), weight=1)

        # Build UI
        self.sidebar()
        self.main_panel()
        self.block_panel()
        self.update_stats()

        # Default profile
        self.profile_add("Default")
        self.switch_profile(self.key_profiles[0].profile_id)

    # ==== SIDEBAR ====
    def sidebar(self):
        sb = ctk.CTkFrame(self, width=320, corner_radius=0, fg_color="#141626")
        sb.grid(row=0, column=0, rowspan=3, sticky="nsew")
        sb.grid_rowconfigure(12, weight=1)

        # Title
        ctk.CTkLabel(sb, text="⛓️ BLOCKCHAIN\nCRYPTO SUITE", 
                     font=ctk.CTkFont(size=22,weight="bold"),
                     text_color="#03eaff").grid(row=0, column=0, pady=(20,5))

        ctk.CTkLabel(sb,text="AES-256-CBC + HMAC-SHA256",
                    font=ctk.CTkFont(size=11),text_color="#b4c2d7").grid(row=1, column=0)

        self.stat_label = ctk.CTkLabel(sb,font=ctk.CTkFont(size=11),text_color="#66ff99")
        self.stat_label.grid(row=2, column=0, pady=5)

        # --- Key Profiles ---
        ctk.CTkLabel(sb,text="🔑 Profile Management",
                    font=ctk.CTkFont(size=14,weight="bold")).grid(row=3, column=0, pady=(15,5))

        self.profile_listbox = ctk.CTkOptionMenu(sb, values=["Default"], width=260,
                                                 command=self.switch_profile)
        self.profile_listbox.grid(row=4, column=0, padx=20, pady=5)

        # Profile buttons
        pf = ctk.CTkFrame(sb, fg_color="transparent")
        pf.grid(row=5, column=0, pady=5)
        ctk.CTkButton(pf,text="New",width=60,command=self.ui_profile_add,
                     fg_color="#2ecc71").grid(row=0,column=0,padx=2)
        ctk.CTkButton(pf,text="Del",width=50,command=self.ui_profile_del,
                     fg_color="#e74c3c").grid(row=0,column=1,padx=2)
        ctk.CTkButton(pf,text="QR",width=50,command=self.export_key_qr,
                     fg_color="#03eaff").grid(row=0,column=2,padx=2)

        # Key management buttons
        kf = ctk.CTkFrame(sb, fg_color="transparent")
        kf.grid(row=6, column=0, pady=5)
        ctk.CTkButton(kf,text="Import Key",width=120,command=self.import_key_file,
                     fg_color="#9b59b6").grid(row=0,column=0,padx=3)
        ctk.CTkButton(kf,text="Export Key",width=120,command=self.export_key_file,
                     fg_color="#34495e").grid(row=0,column=1,padx=3)

        # QR Display
        self.qr_canvas = ctk.CTkLabel(sb, text="")
        self.qr_canvas.grid(row=7, column=0, pady=10)

        # Generate Key
        ctk.CTkButton(sb,text="🎲 Generate New Key",command=self.key_generate,
                     fg_color="#03eaff",hover_color="#02a0b5",
                     font=ctk.CTkFont(size=13,weight="bold"),
                     height=40).grid(row=8, column=0, padx=20, pady=10, sticky="ew")

        # --- Export/Import Log ---
        ctk.CTkLabel(sb,text="📊 Transaction Log",
                    font=ctk.CTkFont(size=14,weight="bold")).grid(row=9, column=0, pady=(15,5))

        lf = ctk.CTkFrame(sb, fg_color="transparent")
        lf.grid(row=10, column=0, pady=5)
        ctk.CTkButton(lf,text="Export CSV",width=85,command=self.export_csv,
                     fg_color="#8d8dc2").grid(row=0,column=0,padx=2)
        ctk.CTkButton(lf,text="Export JSON",width=85,command=self.export_json,
                     fg_color="#2bbc8a").grid(row=0,column=1,padx=2)

        ctk.CTkButton(sb,text="🗑️ Clear Log",command=self.clear_blockchain,
                     fg_color="#c0392b",width=180).grid(row=11, column=0, pady=5)

    # ==== MAIN PANEL ====
    def main_panel(self):
        mp = ctk.CTkFrame(self, fg_color="#1e1e2e", corner_radius=10)
        mp.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")
        mp.grid_columnconfigure(0, weight=1)
        mp.grid_rowconfigure(4, weight=1)

        # Title
        ctk.CTkLabel(mp,text="🔐 AES-256 Encrypt/Decrypt Suite",
                    font=ctk.CTkFont(size=19,weight="bold")).grid(row=0, column=0, pady=10)

        # Input section
        ctk.CTkLabel(mp,text="📝 Input Data / File",
                    font=ctk.CTkFont(size=14,weight="bold"),
                    anchor="w").grid(row=1, column=0, padx=20, sticky="w")

        inputfr = ctk.CTkFrame(mp, fg_color="#2d2e41")
        inputfr.grid(row=2, column=0, padx=20, pady=5, sticky="ew")
        inputfr.grid_columnconfigure(0, weight=1)

        self.input_textbox = ctk.CTkTextbox(inputfr,font=("Consolas",12),height=80)
        self.input_textbox.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        btnfr = ctk.CTkFrame(inputfr, fg_color="transparent")
        btnfr.grid(row=0, column=1, padx=5)
        ctk.CTkButton(btnfr,text="📋",width=30,command=lambda:self.clip_copy(
            self.input_textbox.get("1.0","end-1c"))).grid(row=0,column=0,pady=2)
        ctk.CTkButton(btnfr,text="📁",width=30,command=self.select_file).grid(row=1,column=0,pady=2)

        self.file_status = ctk.CTkLabel(inputfr,text="",text_color="#4ad1ef",
                                       font=ctk.CTkFont(size=10))
        self.file_status.grid(row=1, column=0, padx=5, sticky="w")

        # Output section
        ctk.CTkLabel(mp,text="📤 Output / Result",
                    font=ctk.CTkFont(size=14,weight="bold"),
                    anchor="w").grid(row=3, column=0, padx=20, pady=(10,0), sticky="w")

        outf = ctk.CTkFrame(mp, fg_color="#232341")
        outf.grid(row=4, column=0, padx=20, pady=5, sticky="nsew")
        outf.grid_columnconfigure(0, weight=1)
        outf.grid_rowconfigure(0, weight=1)

        self.output_textbox = ctk.CTkTextbox(outf,height=80,font=("Consolas",12))
        self.output_textbox.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        outbtn = ctk.CTkFrame(outf, fg_color="transparent")
        outbtn.grid(row=0, column=1, padx=5)
        ctk.CTkButton(outbtn,text="📋",width=30,command=lambda:self.clip_copy(
            self.output_textbox.get("1.0","end-1c"))).grid(row=0,column=0,pady=2)
        ctk.CTkButton(outbtn,text="💾",width=30,command=self.save_output).grid(row=1,column=0,pady=2)

        # Action buttons
        btnf = ctk.CTkFrame(mp, fg_color="transparent")
        btnf.grid(row=5, column=0, pady=15)

        ctk.CTkButton(btnf,text="🔒 ENCRYPT",fg_color="#27ae60",
                     font=ctk.CTkFont(size=14,weight="bold"),
                     width=160,height=40,command=self.encrypt_action).grid(row=0,column=0,padx=8)

        ctk.CTkButton(btnf,text="🔓 DECRYPT",fg_color="#3498db",
                     font=ctk.CTkFont(size=14,weight="bold"),
                     width=160,height=40,command=self.decrypt_action).grid(row=0,column=1,padx=8)

        ctk.CTkButton(btnf,text="🗑️ Clear",command=self.clear_io,
                     fg_color="#95a5a6",width=80,height=40).grid(row=0,column=2,padx=8)

        self.status_lbl = ctk.CTkLabel(btnf,text="Ready",text_color="#2ecc71",
                                       font=("Consolas",11))
        self.status_lbl.grid(row=0,column=3,padx=15)

    # ==== BLOCKCHAIN PANEL ====
    def block_panel(self):
        pan = ctk.CTkFrame(self, fg_color="#181828", corner_radius=10)
        pan.grid(row=1, column=1, padx=15, pady=(0,15), sticky="nsew")
        pan.grid_columnconfigure(0, weight=1)
        pan.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(pan,text="⛓️ Blockchain Transaction Log",
                    font=ctk.CTkFont(size=16,weight="bold"),
                    text_color="#03eaff").grid(row=0, column=0, pady=10)

        # Transaction log
        self.tx_log = ctk.CTkTextbox(pan,height=200,font=("Courier",10),fg_color="#212230")
        self.tx_log.grid(row=1, column=0, padx=15, pady=(0,10), sticky="nsew")

        ctk.CTkButton(pan,text="📋 Copy Entire Log",
                     command=lambda:self.clip_copy(self.tx_log.get("1.0","end-1c")),
                     fg_color="#34495e").grid(row=2, column=0, pady=10)

    # ==== LOGIC ====
    def key_generate(self):
        master = random_bytes(64)
        name = f"Profile-{len(self.key_profiles)+1}"
        self.profile_add(name,base64_clean(master))
        self.switch_profile(self.key_profiles[-1].profile_id)
        self.status("✅ New master key generated!")

    def profile_add(self,name,masterkey64=None):
        mk = masterkey64 or base64_clean(random_bytes(64))
        profile = KeyProfile(name, mk)
        self.key_profiles.append(profile)
        self.update_profilelist()

    def switch_profile(self, profile_id):
        for prof in self.key_profiles:
            if prof.profile_id==profile_id or prof.name==profile_id:
                self.cur_profile = prof
                self.active_key = prof.get_keys()
                self.profile_listbox.set(prof.name)
                self.update_stats()
                self.show_qr(prof.master_key64)
                self.status(f"✅ Switched to: {prof.name}")
                return

    def ui_profile_add(self):
        dialog = ctk.CTkInputDialog(text="Enter profile name:", title="New Profile")
        name = dialog.get_input()
        if name:
            self.profile_add(name)
            self.switch_profile(self.key_profiles[-1].profile_id)

    def ui_profile_del(self):
        if len(self.key_profiles)<=1:
            messagebox.showerror("Error","Cannot delete last profile!")
            return
        cur_idx = self.key_profiles.index(self.cur_profile)
        del self.key_profiles[cur_idx]
        self.update_profilelist()
        self.switch_profile(self.key_profiles[0].profile_id)
        self.status("Profile deleted")

    def update_profilelist(self):
        self.profile_listbox.configure(values=[p.name for p in self.key_profiles])
        if self.cur_profile: self.profile_listbox.set(self.cur_profile.name)

    def show_qr(self, masterkey64):
        try:
            qimg = qrcode.make(masterkey64)
            img = qimg.resize((110,110))
            img = ImageTk.PhotoImage(img)
            self.qr_canvas.configure(image=img)
            self.qr_canvas.image = img
        except: pass

    def export_key_qr(self):
        if not self.cur_profile: return
        fpath = filedialog.asksaveasfilename(defaultextension=".png",
                                            filetypes=[("PNG","*.png")])
        if fpath:
            img = qrcode.make(self.cur_profile.master_key64)
            img.save(fpath)
            self.status("✅ QR code exported!")

    def import_key_file(self):
        fpath = filedialog.askopenfilename(filetypes=[("Key Files","*.txt;*.key")])
        if not fpath: return
        try:
            with open(fpath,"r") as fin:
                key = fin.read().strip()
            if len(base64_restore(key))==64:
                self.profile_add(f"Imported-{gen_profile_id()[:4]}", key)
                self.switch_profile(self.key_profiles[-1].profile_id)
                self.status("✅ Key imported!")
            else:
                messagebox.showerror("Error","Invalid key file!")
        except Exception as e:
            messagebox.showerror("Error",f"Import failed: {e}")

    def export_key_file(self):
        if not self.cur_profile: return
        fpath = filedialog.asksaveasfilename(defaultextension=".key",
                                            filetypes=[("Key File","*.key"),("Text","*.txt")])
        if fpath:
            with open(fpath,"w") as fout: 
                fout.write(self.cur_profile.master_key64)
            self.status("✅ Key exported!")

    # ==== CRYPTO ====
    def encrypt(self, data: bytes) -> str:
        enc_key, mac_key = self.active_key
        iv = random_bytes(16)
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data)+padder.finalize()
        ctext = encryptor.update(padded) + encryptor.finalize()
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(iv+ctext)
        mac = h.finalize()
        return base64_clean(iv+ctext+mac)

    def decrypt(self, enc_b64: str) -> bytes:
        enc_key, mac_key = self.active_key
        blob = base64_restore(enc_b64)
        if len(blob)<48: raise ValueError("Data too short")
        iv, ctext, mac = blob[:16], blob[16:-32], blob[-32:]
        # Verify HMAC
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(iv+ctext)
        h.verify(mac)
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ctext)+dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded)+unpadder.finalize()
        return data

    # ==== ACTIONS ====
    def encrypt_action(self):
        if not self.active_key:
            messagebox.showerror("Error","Generate/select a key first!")
            return

        self.status("⏳ Encrypting...")
        self.update()

        try:
            # Check if file loaded
            if hasattr(self, 'file_data'):
                enc = self.encrypt(self.file_data)
                saveto = filedialog.asksaveasfilename(defaultextension=".enc",
                                                     filetypes=[("Encrypted","*.enc")])
                if saveto:
                    with open(saveto,"w") as fout: 
                        fout.write(enc)
                    fname = getattr(self,"file_path","file")
                    self.tx_add("ENCRYPT","File",os.path.basename(fname),
                               len(self.file_data),len(enc))
                    self.status(f"✅ File encrypted → {os.path.basename(saveto)}")
                    del self.file_data
                    self.file_status.configure(text="")
            else:
                text = self.input_textbox.get("1.0","end-1c").strip()
                if not text:
                    messagebox.showerror("Error","Enter text or load file!")
                    return
                enc = self.encrypt(text.encode("utf-8"))
                self.output_textbox.delete("1.0","end")
                self.output_textbox.insert("1.0",enc)
                self.tx_add("ENCRYPT","Text",text[:25]+"...",len(text),len(enc))
                self.status("✅ Text encrypted!")
        except Exception as e:
            messagebox.showerror("Error",f"Encryption failed: {e}")
            self.status("❌ Encryption failed")

    def decrypt_action(self):
        if not self.active_key:
            messagebox.showerror("Error","Generate/select a key first!")
            return

        self.status("⏳ Decrypting & verifying HMAC...")
        self.update()

        try:
            if hasattr(self, 'file_data'):
                dec = self.decrypt(self.file_data.decode())
                saveto = filedialog.asksaveasfilename(defaultextension=".dec")
                if saveto:
                    with open(saveto,"wb") as fout: 
                        fout.write(dec)
                    self.tx_add("DECRYPT","File",os.path.basename(self.file_path),
                               len(self.file_data),len(dec))
                    self.status(f"✅ File decrypted → {os.path.basename(saveto)}")
                    del self.file_data
                    self.file_status.configure(text="")
            else:
                enc = self.input_textbox.get("1.0","end-1c").strip()
                if not enc:
                    messagebox.showerror("Error","Enter ciphertext or load file!")
                    return
                dec = self.decrypt(enc)
                self.output_textbox.delete("1.0","end")
                self.output_textbox.insert("1.0",dec.decode())
                self.tx_add("DECRYPT","Text",enc[:25]+"...",len(enc),len(dec))
                self.status("✅ Text decrypted! HMAC verified ✓")
        except Exception as e:
            messagebox.showerror("Error",f"Decryption failed: {e}")
            self.status("❌ Decryption failed!")

    def clip_copy(self,txt):
        self.clipboard_clear()
        self.clipboard_append(txt)
        self.status("📋 Copied to clipboard!")

    def select_file(self):
        fpath = filedialog.askopenfilename()
        if fpath:
            with open(fpath,"rb") as fin: 
                self.file_data = fin.read()
            self.file_path = fpath
            self.file_status.configure(text=f"📁 {os.path.basename(fpath)} ({len(self.file_data)} bytes)")
            self.status("File loaded! Click encrypt/decrypt.")

    def save_output(self):
        txt = self.output_textbox.get("1.0","end-1c")
        if not txt.strip():
            messagebox.showinfo("Info","Output is empty!")
            return
        saveto = filedialog.asksaveasfilename(defaultextension=".txt")
        if saveto:
            with open(saveto,"w") as fout: 
                fout.write(txt)
            self.status(f"✅ Saved to {os.path.basename(saveto)}")

    def clear_io(self):
        self.input_textbox.delete("1.0","end")
        self.output_textbox.delete("1.0","end")
        self.file_status.configure(text="")
        if hasattr(self,'file_data'): del self.file_data
        self.status("🗑️ Cleared")

    # ==== BLOCKCHAIN ====
    def tx_add(self, ttype, mode, val, siz_in, siz_out):
        txid = sha256hex(f"{ttype}{mode}{siz_in}{siz_out}{random_bytes(4)}".encode())[:12]
        tx = {
            "block":len(self.blockchain)+1,
            "time":datetime.now().strftime("%H:%M:%S"),
            "type":ttype,
            "mode":mode,
            "val":val,
            "in_size":siz_in,
            "out_size":siz_out,
            "txid":txid
        }
        self.blockchain.append(tx)

        icon = "🔒" if ttype=="ENCRYPT" else "🔓"
        self.tx_log.insert("end",
            f"\n{'═'*50}\n"
            f"Block #{tx['block']:03d} | {tx['time']} | {icon} {tx['type']} {tx['mode']}\n"
            f"TxID: {txid}\n"
            f"Data: {tx['val']}\n"
            f"Size: {tx['in_size']} → {tx['out_size']} bytes\n")
        self.tx_log.see("end")
        self.update_stats()

    def clear_blockchain(self):
        if messagebox.askyesno("Confirm","Clear all transaction logs?"):
            self.blockchain.clear()
            self.tx_log.delete("1.0","end")
            self.status("🗑️ Blockchain log cleared!")
            self.update_stats()

    def export_csv(self):
        if not self.blockchain:
            messagebox.showinfo("Info","No transactions to export!")
            return
        fpath = filedialog.asksaveasfilename(defaultextension=".csv")
        if fpath:
            pd.DataFrame(self.blockchain).to_csv(fpath,index=False)
            self.status("✅ Exported to CSV!")

    def export_json(self):
        if not self.blockchain:
            messagebox.showinfo("Info","No transactions to export!")
            return
        fpath = filedialog.asksaveasfilename(defaultextension=".json")
        if fpath:
            with open(fpath,"w") as fout: 
                json.dump(self.blockchain,fout,indent=2)
            self.status("✅ Exported to JSON!")

    def update_stats(self):
        n_block = len(self.blockchain)
        n_prof = len(self.key_profiles)
        cur = self.cur_profile.name if self.cur_profile else "-"
        self.stat_label.configure(text=f"Blocks: {n_block} | Profiles: {n_prof}\nActive: {cur}")

    def status(self,msg):
        colors = {"✅":"#2ecc71","❌":"#e74c3c","⏳":"#f39c12","📋":"#3498db","🗑️":"#95a5a6"}
        color = "#ecf0f1"
        for k,v in colors.items():
            if k in msg: color=v; break
        self.status_lbl.configure(text=msg,text_color=color)


if __name__ == "__main__":
    app = BlockchainAES()
    app.mainloop()
