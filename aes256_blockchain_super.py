"""
AES-256 Blockchain Crypto Suite - All-in-One Super Features
Author: Decky (+ Perplexity AI)
Req: pip install customtkinter cryptography qrcode pillow pandas tkinterdnd2
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
import os, base64, json, csv, random, hashlib, io
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
        self.geometry("1390x850")
        self.resizable(width=False, height=True)
        self.configure(bg="#101020")
        # DATA
        self.active_key = None
        self.key_profiles = []
        self.cur_profile = None
        self.blockchain = []
        self.network_line = []
        # WIDGETS
        self.sidebar()
        self.main_panel()
        self.block_panel()
        self.update_stats()
        # default
        self.profile_add("Default")
        self.switch_profile(self.key_profiles[0].profile_id)

    # ==== SIDEBAR ====
    def sidebar(self):
        sb = ctk.CTkFrame(self, width=330, fg_color="#141626")
        sb.place(x=0,y=0,relheight=1)
        # Title + stats
        ctk.CTkLabel(sb, text="⛓️ BLOCKCHAIN SUITE", font=ctk.CTkFont(size=23,weight="bold"),text_color="#03eaff").pack(pady=(20,0))
        ctk.CTkLabel(sb,text="AES-256-CBC & Encrypted Log",
            font=ctk.CTkFont(size=12),text_color="#b4c2d7").pack()
        self.stat_label = ctk.CTkLabel(sb,font=ctk.CTkFont(size=12),text_color="#66ff99")
        self.stat_label.pack(pady=(2,7))

        # --- Key Profiles ---
        ctk.CTkLabel(sb,text="Profile Management",font=ctk.CTkFont(size=15,weight="bold")).pack(pady=(18,0))
        pf = ctk.CTkFrame(sb,fg_color="#181828",corner_radius=8)
        pf.pack(padx=18,fill="x")
        self.profile_listbox = ctk.CTkOptionMenu(pf, values=[], width=180, command=self.switch_profile)
        self.profile_listbox.pack(side="left",padx=4,pady=4)
        ctk.CTkButton(pf,text="New +",width=12,command=self.ui_profile_add).pack(side="left",padx=2)
        ctk.CTkButton(pf,text="Del", width=8,command=self.ui_profile_del).pack(side="left",padx=2)
        ctk.CTkButton(pf,text="QR",width=7,command=self.export_key_qr,fg_color="#03eaff",hover_color="#02b0c2").pack(side="left",padx=2)
        ctk.CTkButton(pf,text="Imp",width=9,command=self.import_key_file,fg_color="#009122",hover_color="#026212").pack(side="left",padx=2)
        ctk.CTkButton(pf,text="Exp",width=9,command=self.export_key_file,fg_color="#555599",hover_color="#393969").pack(side="left",padx=2)

        # QR Canvas
        self.qr_canvas = ctk.CTkLabel(sb,text="")
        self.qr_canvas.pack(pady=(5,8))

        # Generate Key
        ctk.CTkButton(sb,text="🎲 Generate Key",command=self.key_generate,fg_color="#03eaff",font=ctk.CTkFont(size=13,weight="bold")).pack(padx=15,fill="x",pady=(3,4))

        # --- Export/Import Log ---
        ctk.CTkLabel(sb,text="Transaction Log Export",font=ctk.CTkFont(size=15,weight="bold")).pack(pady=(14,1))
        lf = ctk.CTkFrame(sb,fg_color="#181828",corner_radius=8)
        lf.pack(padx=18)
        ctk.CTkButton(lf,text="Export CSV",width=80,command=self.export_csv,fg_color="#8d8dc2").pack(side="left",padx=2,pady=2)
        ctk.CTkButton(lf,text="Export JSON",width=80,command=self.export_json,fg_color="#2bbc8a").pack(side="left",padx=2,pady=2)
        ctk.CTkButton(lf,text="Clear Log",width=70,command=self.clear_blockchain, fg_color="#e63d48").pack(side="left",padx=3,pady=2)
        # Filler
        ctk.CTkLabel(sb,text=" " * 12).pack(expand=True)

    # ==== MAIN PANEL ====
    def main_panel(self):
        mp = ctk.CTkFrame(self,height=400,fg_color="#202030")
        mp.place(x=340,y=19,width=1022,height=280)
        ctk.CTkLabel(mp,text="AES-256 🔐 Encrypt/Decrypt Suite",font=ctk.CTkFont(size=20,weight="bold")).pack(pady=(4,1))
        # File/text input
        inputfr = ctk.CTkFrame(mp,fg_color="#2d2e41")
        inputfr.pack(pady=6,padx=4,fill="x")
        self.input_textbox = ctk.CTkTextbox(inputfr,font=("Consolas",13),height=70,width=480)
        self.input_textbox.pack(side="left",padx=4)
        ctk.CTkButton(inputfr,text="📋",width=25,command=lambda:self.clip_copy(self.input_textbox.get("1.0","end-1c"))).pack(side="left",padx=2)
        self.file_btn = ctk.CTkButton(inputfr,text="File...",command=self.select_file)
        self.file_btn.pack(side="left",padx=2)
        self.file_status = ctk.CTkLabel(inputfr,text="",text_color="#4ad1ef",font=ctk.CTkFont(size=11))
        self.file_status.pack(side="left")

        # Output box
        outf = ctk.CTkFrame(mp,fg_color="#232341")
        outf.pack(pady=2,padx=4,fill="x")
        self.output_textbox = ctk.CTkTextbox(outf,height=70,font=("Consolas",13))
        self.output_textbox.pack(side="left",padx=4)
        ctk.CTkButton(outf, text="📋", width=25, command=lambda:self.clip_copy(self.output_textbox.get("1.0","end-1c"))).pack(side="left",padx=2)
        self.save_btn = ctk.CTkButton(outf,text="Save",command=self.save_output)
        self.save_btn.pack(side="left")

        # Encrypt/Decrypt buttons + status
        btnf = ctk.CTkFrame(mp,fg_color="#202840")
        btnf.pack(pady=5)
        self.enc_btn = ctk.CTkButton(btnf,text="🔒 ENCRYPT DATA",fg_color="#23e640", font=ctk.CTkFont(size=14,weight="bold"),width=170,command=self.encrypt_action)
        self.enc_btn.pack(side="left",padx=8)
        self.dec_btn = ctk.CTkButton(btnf,text="🔓 DECRYPT DATA",fg_color="#4ac7e7",font=ctk.CTkFont(size=14,weight="bold"),width=170,command=self.decrypt_action)
        self.dec_btn.pack(side="left",padx=8)
        ctk.CTkButton(btnf,text="🗑️ Clear",command=self.clear_io,fg_color="#b2b2b2",width=50).pack(side="left",padx=8)
        self.status_lbl = ctk.CTkLabel(btnf,text="",text_color="#ffd369",font=("Consolas",11))
        self.status_lbl.pack(side="left",padx=18)

        # DnD: Drag & drop
        self.dnd_init(mp)

    def dnd_init(self,frame):
        # TkinterDnD2: perlu window._root().tk sebagai root DnD
        frame.drop_target_register(DND_FILES)
        frame.dnd_bind("<<Drop>>", self.handle_drop)

    # ==== BLOCKCHAIN PANEL ====
    def block_panel(self):
        pan = ctk.CTkFrame(self,fg_color="#181828")
        pan.place(x=340,y=305,width=1022,height=455)
        ctk.CTkLabel(pan,text="⛓️ Blockchain Transaction Log",font=ctk.CTkFont(size=16,weight="bold"),text_color="#03eaff").pack(pady=(10,0))
        # Block visual/network
        self.net_canvas = ctk.CTkCanvas(pan, width=900, height=80, bg="#192029", highlightthickness=0)
        self.net_canvas.pack(pady=(5,0))
        # Block details (log)
        self.tx_log = ctk.CTkTextbox(pan,height=285,font=("Courier",11),fg_color="#212230")
        self.tx_log.pack(fill="both",expand=True,padx=15,pady=10)
        ctk.CTkButton(pan,text="📋 Copy Log",command=lambda:self.clip_copy(self.tx_log.get("1.0","end-1c"))).pack()

    # ==== MAIN LOGIC ====
    def key_generate(self):
        master = random_bytes(64)
        name = f"Profile-{len(self.key_profiles)+1}"
        self.profile_add(name,base64_clean(master))
        self.switch_profile(self.key_profiles[-1].profile_id)
        self.status("Generated new master key.")

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
                self.status(f"Switched to profile: {prof.name}")
                return
        self.status(f"Profile not found!", err=True)

    def ui_profile_add(self):
        name = ctk.CTkInputDialog(title="Add Profile Name", text="Profile name? (eg. App1|Dev2)").get_input()
        if not name: return
        self.profile_add(name)
        self.switch_profile(self.key_profiles[-1].profile_id)

    def ui_profile_del(self):
        if len(self.key_profiles)<=1:
            self.status("Cannot delete last profile!",err=True)
            return
        cur_idx = self.key_profiles.index(self.cur_profile)
        del self.key_profiles[cur_idx]
        self.update_profilelist()
        self.switch_profile(self.key_profiles[0].profile_id)

    def update_profilelist(self):
        self.profile_listbox.configure(values=[p.name for p in self.key_profiles])
        if self.cur_profile: self.profile_listbox.set(self.cur_profile.name)

    # --- QR CODE FUNCTIONS ---
    def show_qr(self, masterkey64):
        qimg = qrcode.make(masterkey64)
        img = qimg.resize((120,120))
        img = ImageTk.PhotoImage(img)
        self.qr_canvas.configure(image=img)
        self.qr_canvas.image = img  # Save ref

    def export_key_qr(self):
        if not self.cur_profile: return
        qdata = self.cur_profile.master_key64
        fpath = filedialog.asksaveasfilename(defaultextension=".png",filetypes=[("PNG","*.png")])
        if not fpath: return
        img = qrcode.make(qdata)
        img.save(fpath)
        self.status("QR code exported.")

    def import_key_file(self):
        fpath = filedialog.askopenfilename(filetypes=[("Key & QR Files","*.txt;*.png")])
        if not fpath: return
        if fpath.endswith(".png"):
            img = Image.open(fpath)
            import pyzbar.pyzbar as pyzbar
            d = pyzbar.decode(img)
            if not d: self.status("QR decode failed!",err=True); return
            key = d[0].data.decode()
        else:
            with open(fpath,"r") as fin:
                key = fin.read().strip()
        if len(base64_restore(key))==64:
            self.profile_add(f"Imported-{gen_profile_id()}", key)
            self.switch_profile(self.key_profiles[-1].profile_id)
            self.status("Key profile imported.")
        else:
            self.status("Invalid key file/QR!", err=True)

    def export_key_file(self):
        if not self.cur_profile: return
        fpath = filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("TXT","*.txt")])
        if fpath:
            with open(fpath,"w") as fout: fout.write(self.cur_profile.master_key64)
            self.status("Exported profile key.")

    # ==== ENCRYPTION LOGIC ====
    def encrypt(self, data: bytes) -> str:
        enc_key, mac_key = self.active_key
        iv = random_bytes(16)
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder(); padded = padder.update(data)+padder.finalize()
        ctext = encryptor.update(padded) + encryptor.finalize()
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(iv+ctext)
        mac = h.finalize()
        return base64_clean(iv+ctext+mac)
    
    def decrypt(self, enc_b64: str) -> bytes:
        enc_key, mac_key = self.active_key
        blob = base64_restore(enc_b64)
        iv, ctext, mac = blob[:16], blob[16:-32], blob[-32:]
        # Verify MAC
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(iv+ctext)
        h.verify(mac)
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor(); padded = dec.update(ctext)+dec.finalize()
        unpadder = padding.PKCS7(128).unpadder(); data = unpadder.update(padded)+unpadder.finalize()
        return data

    # ==== UI ACTIONS ==== 
    def encrypt_action(self):
        self.status_lbl.configure(text="Encrypting...",text_color="#fab905")
        self.update_idletasks()
        if not self.active_key: return self.status("Select/generate key!",err=True)
        try:
            text = self.input_textbox.get("1.0","end-1c")
            filebuf = getattr(self, "file_data", None)
            if filebuf: # File mode
                enc = self.encrypt(filebuf)
                saveto = filedialog.asksaveasfilename(defaultextension=".bin",filetypes=[("Encrypted","*.bin")])
                if saveto:
                    with open(saveto,"wb") as fout: fout.write(enc.encode())
                fname = self.file_path if hasattr(self,"file_path") else "file"
                self.tx_add("ENCRYPT","File",fname, len(filebuf), len(enc))
                self.status(f"File encrypted ➡ {os.path.basename(saveto)}"); del self.file_data
                self.file_status.configure(text="")
            else: # Text mode
                enc = self.encrypt(text.encode("utf-8"))
                self.output_textbox.delete("1.0","end"); self.output_textbox.insert("1.0",enc)
                self.tx_add("ENCRYPT","Text", text[:20]+"...", len(text.encode()), len(enc))
                self.status("Text encrypted!")
        except Exception as e:
            self.status(f"Error: {e}", err=True)
        self.status_lbl.configure(text="",text_color="#ffd369")

    def decrypt_action(self):
        self.status_lbl.configure(text="Decrypting...",text_color="#fab905")
        self.update_idletasks()
        if not self.active_key: return self.status("Select/generate key!",err=True)
        try:
            filebuf = getattr(self, "file_data", None)
            if filebuf:
                dec = self.decrypt(filebuf.decode())
                saveto = filedialog.asksaveasfilename(defaultextension=".decrypted",filetypes=[("Decrypted","*.decrypted")])
                if saveto:
                    with open(saveto,"wb") as fout: fout.write(dec)
                self.tx_add("DECRYPT","File",self.file_path,len(filebuf),len(dec))
                self.status(f"File decrypted ➡ {os.path.basename(saveto)}"); del self.file_data
                self.file_status.configure(text="")
            else:
                enc = self.input_textbox.get("1.0","end-1c")
                dec = self.decrypt(enc)
                self.output_textbox.delete("1.0","end"); self.output_textbox.insert("1.0",dec.decode())
                self.tx_add("DECRYPT","Text",enc[:20]+"...", len(enc), len(dec))
                self.status("Text decrypted.")
        except Exception as e:
            self.status(f"Error: {e}",err=True)
        self.status_lbl.configure(text="",text_color="#ffd369")

    def clip_copy(self,txt):
        self.clipboard_clear(); self.clipboard_append(txt)
        self.status("Copied to clipboard.")

    # -- Drag & Drop/File
    def handle_drop(self, event):
        # For drag&drop file
        filepath = event.data.strip()
        if os.path.isfile(filepath):
            with open(filepath,"rb") as fin:
                self.file_data = fin.read()
            self.file_status.configure(text=f"Loaded File: {os.path.basename(filepath)} ({len(self.file_data)} bytes)",text_color="#44feee")
            self.file_path = filepath
            self.status("File loaded for encrypt/decrypt. Click button to proceed.")

    def select_file(self):
        fpath = filedialog.askopenfilename(); 
        if fpath:
            with open(fpath,"rb") as fin: self.file_data = fin.read()
            self.file_status.configure(text=f"Loaded File: {os.path.basename(fpath)} ({len(self.file_data)} bytes)",text_color="#44feee")
            self.file_path = fpath
            self.status("File loaded for encrypt/decrypt. Click button.")

    def save_output(self):
        txt = self.output_textbox.get("1.0","end-1c")
        saveto = filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("Text","*.txt")])
        if saveto: 
            with open(saveto,"w") as fout: fout.write(txt)
            self.status(f"Output saved.")

    def clear_io(self):
        self.input_textbox.delete("1.0","end")
        self.output_textbox.delete("1.0","end")
        self.file_status.configure(text="")
        self.status("Input & output cleared.")

    # --- Blockchain Logging ---
    def tx_add(self, ttype, mode, val, siz_in, siz_out):
        txid = sha256hex(f"{ttype}{mode}{siz_in}{siz_out}{random_bytes(6)}".encode())[:10]
        tx = dict(block=len(self.blockchain)+1, time=datetime.now().strftime("%H:%M:%S"), type=ttype, mode=mode, val=val, in_size=siz_in, out_size=siz_out, txid=txid)
        self.blockchain.append(tx)
        self.tx_log.insert("end",f"\n{'━'*42}\nBlock {tx['block']:03d} | {tx['time']} | {tx['type']} {tx['mode']}\nID: {txid}\n{tx['val']}\nData Size: {tx['in_size']} ➡ {tx['out_size']} bytes\n")
        self.update_stats(); self.draw_network()

    def clear_blockchain(self):
        self.blockchain.clear(); self.tx_log.delete("1.0","end")
        self.status("Blockchain log cleared!"); self.update_stats(); self.draw_network()

    def export_csv(self):
        if not self.blockchain: return self.status("Log empty.",err=True)
        fpath = filedialog.asksaveasfilename(defaultextension=".csv")
        if not fpath: return
        pd.DataFrame(self.blockchain).to_csv(fpath,index=False)
        self.status("Transaction log exported CSV.")

    def export_json(self):
        if not self.blockchain: return self.status("Log empty.",err=True)
        fpath = filedialog.asksaveasfilename(defaultextension=".json")
        if not fpath: return
        with open(fpath,"w") as fout: json.dump(self.blockchain,fout,indent=2)
        self.status("Transaction log exported JSON.")

    # --- Visualisasi blockchain network (simple)
    def draw_network(self):
        c = self.net_canvas
        c.delete("all")
        block_count = len(self.blockchain)
        if block_count == 0: return
        x0,y0,dx = 60, 38, 110
        for i in range(block_count):
            x = x0+dx*i
            c.create_rectangle(x-28,y0-28,x+28,y0+28, fill="#3a47bd",outline="#00d4ff",width=3)
            c.create_text(x,y0-8,text=f"B{i+1}",fill="white",font=("Arial",15,"bold"))
            c.create_text(x,y0+14,text=self.blockchain[i]['type'],fill="#fff",font=("Arial",11,"italic"))
            if i>0: # network line
                c.create_line(x0+dx*(i-1)+28,y0,x-28,y0,fill="#00d4ff",width=6,arrow="last")
        c.update()

    def update_stats(self):
        n_block = len(self.blockchain)
        n_prof = len(self.key_profiles)
        cur = self.cur_profile.name if self.cur_profile else "-"
        self.stat_label.configure(text=f"Blocks: {n_block} | Profiles: {n_prof}\nActive: {cur}")

    def status(self,msg,err=False):
        self.status_lbl.configure(text=msg,text_color="#f22222" if err else "#ffd369")


if __name__ == "__main__":
    app = BlockchainAES()
    app.mainloop()
