#!/bin/bash
################################################################################
# AES-256-CBC Decryption Script with HMAC-SHA256 Verification
# Manual implementation menggunakan OpenSSL
# Author: Decky
# Date: 2025-10-24
################################################################################

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
MASTER_KEY=$(cat "$KEY_FILE" | tr -d '\n')
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
