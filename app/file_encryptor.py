from app import aes
import sys
import os
from hashlib import pbkdf2_hmac

def read_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

def write_file(file_path, data):
    with open(file_path, 'wb') as f:
        f.write(data)

def encrypt_file(input_file, output_file, password):
    data = read_file(input_file)
    ciphertext = aes.encrypt(password.encode('utf-8'), data)  # ✅ correct order
    write_file(output_file, ciphertext)

def decrypt_file(input_file, output_file, password):
    data = read_file(input_file)
    plaintext = aes.decrypt(password.encode('utf-8'), data)  # ✅ correct order
    write_file(output_file, plaintext)


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: python file_encryptor.py [encrypt|decrypt] input_file output_file password")
        sys.exit(1)

    mode, infile, outfile, password = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    if mode == 'encrypt':
        encrypt_file(infile, outfile, password)
    elif mode == 'decrypt':
        decrypt_file(infile, outfile, password)
    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")
