#!/bin/bash
################################################################################
# AES-256-CBC Encryption Script with HMAC-SHA256 (Encrypt-then-MAC)
# Manual implementation menggunakan OpenSSL
# Author: Decky
# Date: 2025-10-24
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
MASTER_KEY=$(cat "$KEY_FILE" | tr -d '\n')
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
echo -n "$FINAL_HEX" | xxd -r -p | base64 | tr -d '\n' > "$OUTPUT_FILE"

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
