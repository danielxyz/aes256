
# Script untuk mendeteksi semua non-printable characters dalam file

diagnostic_script = '''import sys

def diagnose_file(filepath):
    """Scan file untuk non-printable characters dan tampilkan lokasinya."""
    
    print(f"Scanning file: {filepath}\\n")
    
    with open(filepath, 'rb') as f:
        content = f.read()
    
    issues = []
    line_num = 1
    col_num = 1
    
    for i, byte in enumerate(content):
        char = chr(byte)
        
        # Check untuk non-printable characters
        if byte == 0xC2:  # UTF-8 non-breaking space prefix
            if i + 1 < len(content) and content[i + 1] == 0xA0:
                issues.append({
                    'line': line_num,
                    'col': col_num,
                    'char': 'NON-BREAKING SPACE (U+00A0)',
                    'hex': f'0x{byte:02X} 0x{content[i+1]:02X}'
                })
        elif byte == 0xA0:  # Direct non-breaking space
            issues.append({
                'line': line_num,
                'col': col_num,
                'char': 'NON-BREAKING SPACE (0xA0)',
                'hex': f'0x{byte:02X}'
            })
        elif not char.isprintable() and char not in ('\\n', '\\r', '\\t'):
            issues.append({
                'line': line_num,
                'col': col_num,
                'char': f'NON-PRINTABLE (U+{ord(char):04X})',
                'hex': f'0x{byte:02X}'
            })
        
        # Update line and column counters
        if char == '\\n':
            line_num += 1
            col_num = 1
        else:
            col_num += 1
    
    # Display results
    if issues:
        print(f"❌ Found {len(issues)} non-printable character(s):\\n")
        for issue in issues[:20]:  # Show first 20
            print(f"  Line {issue['line']}, Col {issue['col']}: {issue['char']} [{issue['hex']}]")
        
        if len(issues) > 20:
            print(f"\\n  ... and {len(issues) - 20} more issues")
    else:
        print("✓ No non-printable characters found!")
    
    return len(issues)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python diagnose_python.py <file_to_scan>")
        print("Example: python diagnose_python.py aes256_app_decky.py")
    else:
        filepath = sys.argv[1]
        diagnose_file(filepath)
'''

with open('diagnose_python.py', 'w', encoding='utf-8') as f:
    f.write(diagnostic_script)

print("✓ Script diagnostic telah dibuat: diagnose_python.py")
print("\n=== CARA DIAGNOSE FILE ===")
print("python diagnose_python.py aes256_app_decky.py")
print("\nScript ini akan menampilkan:")
print("- Lokasi (line & column) dari setiap non-printable character")
print("- Jenis karakter bermasalah")
print("- Hex code untuk debugging")
