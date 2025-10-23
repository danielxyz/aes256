import base64
from Crypto.Cipher import AES

input_data = "nOBSZYhDC4om0Kz5KtB5JbUVBLXIxxQq2pJCIWAOb769Oj-SR7uZuTWIQFN4I1ha-NG5YhTNfFNIaEqkPZCNZw=="
master_key_64 = "1ZSsTudxHFc5IWcSdUK0n7nx8x5i1rUrDiBKQ_nFCm-p4E17ii...knVgbTqjg5wJ6C5wQVw4v2wtOyCVoW9FMe2A=="

master_key_clean = master_key_64.replace("...", "")
key_bytes = base64.urlsafe_b64decode(master_key_clean)
key = key_bytes[:32]

ciphertext = base64.urlsafe_b64decode(input_data)
iv = ciphertext[:16]
ciphertext_actual = ciphertext[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext_actual)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

try:
    plaintext = unpad(decrypted)
    plaintext_decoded = plaintext.decode('utf-8', errors='replace')
except Exception as e:
    plaintext_decoded = f"ERROR: {str(e)}"

print(plaintext_decoded)
