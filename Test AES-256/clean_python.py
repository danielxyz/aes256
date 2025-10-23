import sys

def clean_python_file(input_file, output_file=None):
    """
    Membersihkan non-printable characters dari file Python.

    Args:
        input_file: Path ke file yang akan dibersihkan
        output_file: Path output (optional, default: overwrite input)
    """
    if output_file is None:
        output_file = input_file

    # Baca file dengan encoding UTF-8
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Replace non-breaking spaces (U+00A0) dengan regular spaces
    content = content.replace('\u00a0', ' ')
    content = content.replace('\xa0', ' ')

    # Hapus karakter non-printable lainnya kecuali newline dan tab
    cleaned = ''
    for char in content:
        if char.isprintable() or char in ('\n', '\r', '\t'):
            cleaned += char
        elif char == '\xa0':  # non-breaking space
            cleaned += ' '

    # Tulis kembali file yang sudah dibersihkan
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(cleaned)

    print(f"✓ File berhasil dibersihkan: {output_file}")
    print(f"  Karakter non-printable telah dihapus")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python clean_python.py <file_to_clean> [output_file]")
        print("Example: python clean_python.py aes256_app_decky.py")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        clean_python_file(input_file, output_file)
