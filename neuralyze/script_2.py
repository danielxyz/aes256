
# Create comprehensive bash scripts for manual encryption/decryption

bash_encrypt_script = '''#!/bin/bash
################################################################################
# AES-256-CBC Encryption Script with HMAC-SHA256 (Encrypt-then-MAC)
# Manual implementation menggunakan OpenSSL
# Author: Decky
# Date: 2025-10-24
################################################################################

set -e  # Exit on error

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  AES-256-CBC + HMAC-SHA256 Encryption Script (Encrypt-then-MAC)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

# Function to display usage
usage() {
    echo -e "${YELLOW}Usage: $0 <plaintext_file> <master_key_file> <output_file>${NC}"
    echo ""
    echo "Example:"
    echo "  $0 dec_danielx.txt masterkee.k3y enc_danielx.enc"
    echo ""
    echo "Master key file should contain 64-byte key in base64 format"
    exit 1
}

# Check arguments
if [ $# -ne 3 ]; then
    usage
fi

PLAINTEXT_FILE="$1"
KEY_FILE="$2"
OUTPUT_FILE="$3"

# Verify files exist
if [ ! -f "$PLAINTEXT_FILE" ]; then
    echo -e "${RED}Error: Plaintext file not found: $PLAINTEXT_FILE${NC}"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo -e "${RED}Error: Key file not found: $KEY_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Input file: $PLAINTEXT_FILE${NC}"
echo -e "${GREEN}✓ Key file: $KEY_FILE${NC}"
echo -e "${GREEN}✓ Output file: $OUTPUT_FILE${NC}"
echo ""

# Read and decode master key (64 bytes)
echo -e "${BLUE}[1/7] Reading master key...${NC}"
MASTER_KEY=$(cat "$KEY_FILE" | tr -d '\\n')
MASTER_KEY_HEX=$(echo "$MASTER_KEY" | base64 -d | xxd -p -c 1000)

# Split master key: first 32 bytes for encryption, last 32 for MAC
ENC_KEY_HEX="${MASTER_KEY_HEX:0:64}"
MAC_KEY_HEX="${MASTER_KEY_HEX:64:64}"

echo -e "${GREEN}  ✓ Encryption key (32 bytes): ${ENC_KEY_HEX:0:40}...${NC}"
echo -e "${GREEN}  ✓ MAC key (32 bytes): ${MAC_KEY_HEX:0:40}...${NC}"

# Generate random IV (16 bytes)
echo -e "${BLUE}[2/7] Generating random IV (16 bytes)...${NC}"
IV=$(openssl rand -hex 16)
echo -e "${GREEN}  ✓ IV: $IV${NC}"

# Encrypt with AES-256-CBC
echo -e "${BLUE}[3/7] Encrypting with AES-256-CBC...${NC}"
CIPHERTEXT_HEX=$(openssl enc -aes-256-cbc -K "$ENC_KEY_HEX" -iv "$IV" -in "$PLAINTEXT_FILE" | xxd -p -c 1000)
CIPHER_SIZE=$((${#CIPHERTEXT_HEX}/2))
echo -e "${GREEN}  ✓ Ciphertext size: $CIPHER_SIZE bytes${NC}"

# Combine IV + Ciphertext for HMAC computation
echo -e "${BLUE}[4/7] Combining IV + Ciphertext...${NC}"
IV_CIPHER="${IV}${CIPHERTEXT_HEX}"

# Compute HMAC-SHA256 over IV + Ciphertext
echo -e "${BLUE}[5/7] Computing HMAC-SHA256...${NC}"
HMAC=$(echo -n "$IV_CIPHER" | xxd -r -p | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$MAC_KEY_HEX" | cut -d' ' -f2)
echo -e "${GREEN}  ✓ HMAC: $HMAC${NC}"

# Combine IV + Ciphertext + HMAC
echo -e "${BLUE}[6/7] Combining IV + Ciphertext + HMAC...${NC}"
FINAL_HEX="${IV}${CIPHERTEXT_HEX}${HMAC}"
FINAL_SIZE=$((${#FINAL_HEX}/2))
echo -e "${GREEN}  ✓ Total size: $FINAL_SIZE bytes${NC}"

# Encode to Base64 and save
echo -e "${BLUE}[7/7] Encoding to Base64 and saving...${NC}"
echo -n "$FINAL_HEX" | xxd -r -p | base64 | tr -d '\\n' > "$OUTPUT_FILE"

# Get file sizes
PLAINTEXT_SIZE=$(wc -c < "$PLAINTEXT_FILE")
OUTPUT_SIZE=$(wc -c < "$OUTPUT_FILE")

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ ENCRYPTION SUCCESSFUL!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Input size: $PLAINTEXT_SIZE bytes${NC}"
echo -e "${GREEN}  Output size: $OUTPUT_SIZE characters (base64)${NC}"
echo -e "${GREEN}  Encrypted file: $OUTPUT_FILE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}⚠️  Keep your master key safe! Without it, decryption is impossible.${NC}"
'''

bash_decrypt_script = '''#!/bin/bash
################################################################################
# AES-256-CBC Decryption Script with HMAC-SHA256 Verification
# Manual implementation menggunakan OpenSSL
# Author: Decky
# Date: 2025-10-24
################################################################################

set -e  # Exit on error

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  AES-256-CBC + HMAC-SHA256 Decryption Script${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

# Function to display usage
usage() {
    echo -e "${YELLOW}Usage: $0 <encrypted_file> <master_key_file> <output_file>${NC}"
    echo ""
    echo "Example:"
    echo "  $0 enc_danielx.enc masterkee.k3y decrypted_output.txt"
    exit 1
}

# Check arguments
if [ $# -ne 3 ]; then
    usage
fi

ENCRYPTED_FILE="$1"
KEY_FILE="$2"
OUTPUT_FILE="$3"

# Verify files
if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo -e "${RED}Error: Encrypted file not found: $ENCRYPTED_FILE${NC}"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo -e "${RED}Error: Key file not found: $KEY_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Encrypted file: $ENCRYPTED_FILE${NC}"
echo -e "${GREEN}✓ Key file: $KEY_FILE${NC}"
echo -e "${GREEN}✓ Output file: $OUTPUT_FILE${NC}"
echo ""

# Read master key
echo -e "${BLUE}[1/8] Reading master key...${NC}"
MASTER_KEY=$(cat "$KEY_FILE" | tr -d '\\n')
MASTER_KEY_HEX=$(echo "$MASTER_KEY" | base64 -d | xxd -p -c 1000)

# Split keys
ENC_KEY_HEX="${MASTER_KEY_HEX:0:64}"
MAC_KEY_HEX="${MASTER_KEY_HEX:64:64}"
echo -e "${GREEN}  ✓ Keys loaded${NC}"

# Decode base64 encrypted data
echo -e "${BLUE}[2/8] Decoding base64...${NC}"
ENCRYPTED_HEX=$(cat "$ENCRYPTED_FILE" | base64 -d | xxd -p -c 1000)
ENCRYPTED_SIZE=$((${#ENCRYPTED_HEX}/2))
echo -e "${GREEN}  ✓ Decoded size: $ENCRYPTED_SIZE bytes${NC}"

# Extract IV (first 16 bytes = 32 hex chars)
echo -e "${BLUE}[3/8] Extracting IV...${NC}"
IV="${ENCRYPTED_HEX:0:32}"
echo -e "${GREEN}  ✓ IV: $IV${NC}"

# Extract HMAC (last 32 bytes = 64 hex chars)
echo -e "${BLUE}[4/8] Extracting HMAC...${NC}"
HMAC_RECEIVED="${ENCRYPTED_HEX: -64}"
echo -e "${GREEN}  ✓ HMAC received: ${HMAC_RECEIVED:0:40}...${NC}"

# Extract ciphertext (middle part)
CIPHERTEXT_HEX="${ENCRYPTED_HEX:32:-64}"
CIPHER_SIZE=$((${#CIPHERTEXT_HEX}/2))
echo -e "${GREEN}  ✓ Ciphertext size: $CIPHER_SIZE bytes${NC}"

# Verify HMAC
echo -e "${BLUE}[5/8] Verifying HMAC-SHA256...${NC}"
IV_CIPHER="${IV}${CIPHERTEXT_HEX}"
HMAC_COMPUTED=$(echo -n "$IV_CIPHER" | xxd -r -p | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$MAC_KEY_HEX" | cut -d' ' -f2)

if [ "$HMAC_RECEIVED" != "$HMAC_COMPUTED" ]; then
    echo -e "${RED}  ❌ HMAC VERIFICATION FAILED!${NC}"
    echo -e "${RED}  Data may have been tampered or wrong key!${NC}"
    echo -e "${RED}  Expected: ${HMAC_COMPUTED}${NC}"
    echo -e "${RED}  Received: ${HMAC_RECEIVED}${NC}"
    exit 1
fi

echo -e "${GREEN}  ✅ HMAC verified successfully!${NC}"

# Decrypt
echo -e "${BLUE}[6/8] Decrypting with AES-256-CBC...${NC}"
echo -n "$CIPHERTEXT_HEX" | xxd -r -p | openssl enc -d -aes-256-cbc -K "$ENC_KEY_HEX" -iv "$IV" > "$OUTPUT_FILE"

# Verify output
if [ ! -f "$OUTPUT_FILE" ]; then
    echo -e "${RED}  ❌ Decryption failed!${NC}"
    exit 1
fi

OUTPUT_SIZE=$(wc -c < "$OUTPUT_FILE")
echo -e "${GREEN}  ✓ Decrypted size: $OUTPUT_SIZE bytes${NC}"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ DECRYPTION SUCCESSFUL!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Input: $ENCRYPTED_FILE${NC}"
echo -e "${GREEN}  Output: $OUTPUT_FILE ($OUTPUT_SIZE bytes)${NC}"
echo -e "${GREEN}  HMAC verification: PASSED ✓${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
'''

# Save bash scripts
with open('aes_encrypt.sh', 'w') as f:
    f.write(bash_encrypt_script)

with open('aes_decrypt.sh', 'w') as f:
    f.write(bash_decrypt_script)

print("="*90)
print("✅ BASH SCRIPTS CREATED!")
print("="*90)
print("\n📝 Files generated:")
print("  1. aes_encrypt.sh - Script untuk enkripsi manual")
print("  2. aes_decrypt.sh - Script untuk dekripsi manual")

print("\n🚀 CARA MENGGUNAKAN:")
print("\n1. ENKRIPSI:")
print("   chmod +x aes_encrypt.sh")
print("   ./aes_encrypt.sh dec_danielx.txt masterkee.k3y output.enc")
print("\n2. DEKRIPSI:")
print("   chmod +x aes_decrypt.sh")
print("   ./aes_decrypt.sh enc_danielx.enc masterkee.k3y decrypted.txt")

print("\n📋 REQUIREMENTS:")
print("  - OpenSSL installed (openssl command)")
print("  - Bash shell (Linux/Mac/WSL)")
print("  - xxd utility (usually pre-installed)")

print("\n⚠️  CATATAN PENTING:")
print("  • Scripts ini menggunakan OpenSSL command-line")
print("  • Master key harus 64 bytes dalam format base64")
print("  • HMAC verification otomatis dilakukan saat decrypt")
print("  • Jika HMAC fail, dekripsi akan dibatalkan")
