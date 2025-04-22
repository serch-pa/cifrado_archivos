import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# Constants
AES_BLOCK_SIZE = 16
IV_SIZE = 16

# Functions

def encrypt_file(file_path, public_key_path, private_key_path, output_path):
    try:
        # Read RSA keys
        with open(public_key_path, 'rb') as f:
            public_key = RSA.import_key(f.read())
        with open(private_key_path, 'rb') as f:
            private_key = RSA.import_key(f.read())

        # Generate AES key and IV
        aes_key = os.urandom(16)  # AES-128
        iv = os.urandom(IV_SIZE)

        # Read plaintext from file
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        # Encrypt plaintext with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(pad(plaintext, AES_BLOCK_SIZE))

        # Encrypt AES key with RSA public key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Sign the ciphertext using RSA private key
        hasher = SHA256.new(ciphertext)
        signature = pkcs1_15.new(private_key).sign(hasher)

        # Write encrypted data to output file
        with open(output_path, 'wb') as f:
            f.write(iv + encrypted_aes_key + signature + ciphertext)

        messagebox.showinfo("Success", "File encrypted and signed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def decrypt_file(file_path, private_key_path, public_key_path, output_path):
    try:
        # Read RSA keys
        with open(private_key_path, 'rb') as f:
            private_key = RSA.import_key(f.read())
        with open(public_key_path, 'rb') as f:
            public_key = RSA.import_key(f.read())

        # Read encrypted file
        with open(file_path, 'rb') as f:
            data = f.read()

        # Extract IV, encrypted AES key, signature, and ciphertext
        iv = data[:IV_SIZE]
        encrypted_aes_key = data[IV_SIZE:IV_SIZE + public_key.size_in_bytes()]
        signature = data[IV_SIZE + public_key.size_in_bytes():IV_SIZE + public_key.size_in_bytes() + 256]
        ciphertext = data[IV_SIZE + public_key.size_in_bytes() + 256:]

        # Decrypt AES key with RSA private key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Verify signature using RSA public key
        hasher = SHA256.new(ciphertext)
        try:
            pkcs1_15.new(public_key).verify(hasher, signature)
        except (ValueError, TypeError):
            messagebox.showerror("Error", "Signature verification failed. Integrity or authentication error.")
            return

        # Decrypt ciphertext
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher_aes.decrypt(ciphertext), AES_BLOCK_SIZE)

        # Write decrypted data to output file
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("Success", "File decrypted and signature verified successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# GUI

def select_file(entry):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)

def encrypt_action():
    input_path = input_file_entry.get()
    public_key_path = public_key_entry.get()
    private_key_path = private_key_entry.get()
    output_path = output_file_entry.get()
    if input_path and public_key_path and private_key_path and output_path:
        encrypt_file(input_path, public_key_path, private_key_path, output_path)
    else:
        messagebox.showerror("Error", "Please fill in all fields.")

def decrypt_action():
    input_path = input_file_entry.get()
    private_key_path = private_key_entry.get()
    public_key_path = public_key_entry.get()
    output_path = output_file_entry.get()
    if input_path and private_key_path and public_key_path and output_path:
        decrypt_file(input_path, private_key_path, public_key_path, output_path)
    else:
        messagebox.showerror("Error", "Please fill in all fields.")

# Main Window
root = tk.Tk()
root.title("AES Encryption with RSA Signing")

# Input File
input_file_label = tk.Label(root, text="Input File:")
input_file_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
input_file_entry = tk.Entry(root, width=50)
input_file_entry.grid(row=0, column=1, padx=5, pady=5)
input_file_button = tk.Button(root, text="Browse", command=lambda: select_file(input_file_entry))
input_file_button.grid(row=0, column=2, padx=5, pady=5)

# Public Key File
public_key_label = tk.Label(root, text="Public Key File:")
public_key_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
public_key_entry = tk.Entry(root, width=50)
public_key_entry.grid(row=1, column=1, padx=5, pady=5)
public_key_button = tk.Button(root, text="Browse", command=lambda: select_file(public_key_entry))
public_key_button.grid(row=1, column=2, padx=5, pady=5)

# Private Key File
private_key_label = tk.Label(root, text="Private Key File:")
private_key_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
private_key_entry = tk.Entry(root, width=50)
private_key_entry.grid(row=2, column=1, padx=5, pady=5)
private_key_button = tk.Button(root, text="Browse", command=lambda: select_file(private_key_entry))
private_key_button.grid(row=2, column=2, padx=5, pady=5)

# Output File
output_file_label = tk.Label(root, text="Output File:")
output_file_label.grid(row=3, column=0, padx=5, pady=5, sticky="e")
output_file_entry = tk.Entry(root, width=50)
output_file_entry.grid(row=3, column=1, padx=5, pady=5)
output_file_button = tk.Button(root, text="Browse", command=lambda: select_file(output_file_entry))
output_file_button.grid(row=3, column=2, padx=5, pady=5)

# Buttons
encrypt_button = tk.Button(root, text="Encrypt and Sign", command=encrypt_action)
encrypt_button.grid(row=4, column=0, columnspan=2, pady=10)
decrypt_button = tk.Button(root, text="Decrypt and Verify", command=decrypt_action)
decrypt_button.grid(row=4, column=1, columnspan=2, pady=10)

# Run the application
root.mainloop()
