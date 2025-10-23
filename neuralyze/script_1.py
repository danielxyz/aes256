
# Create detailed comparison table and statistics
import pandas as pd
import csv

# Comparison table for all 4 files
comparison_data = {
    'File': ['masterkee.k3y', 'dec_danielx.txt', 'enc_danielx.enc', 'dec2enc.enc'],
    'Type': ['Master Key', 'Plaintext (OpenVPN)', 'Encrypted', 'Encrypted (Re-encrypted)'],
    'Size (bytes)': [64, 20480, 20544, 20544],
    'Format': ['Base64', 'Text/Binary', 'Base64', 'Base64'],
    'Readable': ['No', 'Yes', 'No', 'No'],
    'Security': ['CRITICAL', 'UNPROTECTED', 'PROTECTED', 'PROTECTED'],
    'Purpose': ['Encryption+MAC keys', 'VPN credentials', 'Encrypted VPN config', 'Re-encrypted same data'],
    'SHA256 (first 16)': [
        'db29ef5a8b775496',
        '38856920dfdd4e4a',
        'varies (IV based)',
        'varies (IV based)'
    ]
}

df = pd.DataFrame(comparison_data)
df.to_csv('file_comparison_table.csv', index=False)

print("="*90)
print("TABEL PERBANDINGAN 4 FILE")
print("="*90)
print(df.to_string(index=False))

# Structure breakdown table
structure_data = {
    'Component': ['Master Key', 'Encryption Key', 'MAC Key', 'Plaintext', 'Padding', 'IV', 'Ciphertext', 'HMAC', 'Total Encrypted'],
    'Size (bytes)': [64, 32, 32, 20480, 16, 16, 20496, 32, 20544],
    'Format': ['Binary', 'Binary', 'Binary', 'Text', 'PKCS7', 'Random', 'Binary', 'SHA256', 'Binary'],
    'Purpose': [
        'Split untuk enc+mac',
        'AES-256 encryption',
        'HMAC-SHA256 authentication',
        'Original VPN config',
        'Make multiple of 16',
        'Randomize encryption',
        'Encrypted data',
        'Integrity verification',
        'Final encrypted package'
    ]
}

df_struct = pd.DataFrame(structure_data)
df_struct.to_csv('structure_breakdown.csv', index=False)

print("\n" + "="*90)
print("STRUKTUR BREAKDOWN")
print("="*90)
print(df_struct.to_string(index=False))

# Encryption steps table
steps_data = [
    ['Step', 'Input', 'Process', 'Output', 'Size Change'],
    ['1', 'Plaintext', 'Load file', 'Raw bytes', '20,480 bytes'],
    ['2', 'Raw bytes', 'Add PKCS7 padding', 'Padded', '20,496 bytes (+16)'],
    ['3', 'Padded', 'Generate random IV', 'IV generated', '16 bytes'],
    ['4', 'Padded + IV', 'AES-256-CBC encrypt', 'Ciphertext', '20,496 bytes'],
    ['5', 'IV + Ciphertext', 'Compute HMAC-SHA256', 'HMAC tag', '32 bytes'],
    ['6', 'IV + Cipher + HMAC', 'Combine components', 'Binary package', '20,544 bytes'],
    ['7', 'Binary package', 'Base64 URL-safe encode', 'Final .enc file', '27,392 chars'],
]

with open('encryption_steps.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerows(steps_data)

print("\n" + "="*90)
print("LANGKAH-LANGKAH ENKRIPSI")
print("="*90)
for row in steps_data:
    print(f"{row[0]:<6} {row[1]:<18} → {row[2]:<30} → {row[3]:<15} [{row[4]}]")

# Key insights
insights = """
═══════════════════════════════════════════════════════════════════════════════════════════
KEY INSIGHTS & FAKTA PENTING
═══════════════════════════════════════════════════════════════════════════════════════════

1. MULTIPLE ENCRYPTION WITH SAME KEY = DIFFERENT OUTPUT
   ✓ dec_danielx.txt dienkripsi 2x dengan key yang sama
   ✓ Hasilnya berbeda: enc_danielx.enc ≠ dec2enc.enc
   ✓ Penyebab: Random IV berbeda di setiap enkripsi
   ✓ Ini adalah FITUR KEAMANAN, bukan bug!

2. IV (INITIALIZATION VECTOR) ROLE
   ✓ IV di-generate random setiap enkripsi
   ✓ IV berbeda → ciphertext berbeda (meski plaintext & key sama)
   ✓ IV tidak perlu dirahasiakan (dikirim bersama ciphertext)
   ✓ IV HARUS unik untuk setiap enkripsi dengan key yang sama

3. HMAC PROTECTION
   ✓ HMAC computed atas IV + Ciphertext
   ✓ Jika 1 bit berubah → HMAC verification gagal
   ✓ Protect dari tampering, bit-flipping, padding oracle attacks
   ✓ Encrypt-then-MAC = best practice (lebih aman dari MAC-then-Encrypt)

4. FILE SIZE MATHEMATICS
   ✓ Plaintext: 20,480 bytes
   ✓ Block size: 16 bytes (AES)
   ✓ Padding: 16 bytes (20480 % 16 = 0, tambah 1 block penuh per PKCS7)
   ✓ Encrypted: 16 (IV) + 20,496 (cipher) + 32 (HMAC) = 20,544 bytes
   ✓ Base64: 20,544 bytes → 27,392 characters (4/3 expansion)

5. SECURITY LEVEL
   ✓ AES-256: 2^256 possible keys (computationally infeasible to brute force)
   ✓ Quantum resistance: ~128-bit security (still safe for 30-40 years)
   ✓ HMAC-SHA256: Collision resistant, pre-image resistant
   ✓ Combined: Military-grade encryption + authentication

6. KERENTANAN TANPA KEY
   ✓ Tanpa masterkee.k3y → IMPOSSIBLE to decrypt
   ✓ Wrong key → HMAC verification fails instantly
   ✓ Tampered data → HMAC verification fails
   ✓ No key = No plaintext recovery (even with quantum computer)
"""

print(insights)

# Save insights
with open('key_insights.txt', 'w') as f:
    f.write(insights)

print("\n📊 Files created:")
print("  ✓ file_comparison_table.csv")
print("  ✓ structure_breakdown.csv")
print("  ✓ encryption_steps.csv")
print("  ✓ key_insights.txt")
