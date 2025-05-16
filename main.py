import os
import base64
from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Derive a key from password using PBKDF2 and SHA-256
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt File
def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Enter a password to encrypt.")
        return

    try:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)

        with open(file_path, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        encrypted_file_path = file_path + ".encrypted"
        with open(encrypted_file_path, 'wb') as enc_file:
            enc_file.write(salt + encrypted)  # prepend salt

        messagebox.showinfo("Success", f"File encrypted successfully:\n{encrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

# Decrypt File
def decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.encrypted")])
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Enter the password used for encryption.")
        return

    try:
        with open(file_path, 'rb') as enc_file:
            data = enc_file.read()
            salt = data[:16]
            encrypted = data[16:]

        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)

        original_file_path = file_path.replace(".encrypted", "_decrypted")
        with open(original_file_path, 'wb') as dec_file:
            dec_file.write(decrypted)

        messagebox.showinfo("Success", f"File decrypted successfully:\n{original_file_path}")
    except Exception as e:
        messagebox.showerror("Decryption Error", "Failed to decrypt file.\n" + str(e))

# GUI Setup
root = Tk()
root.title("🔐 File Encryption/Decryption Tool")
root.geometry("450x300")
root.config(bg="#1c1c1c")

Label(root, text="🔐 File Encryption Tool", font=("Helvetica", 18), fg="white", bg="#1c1c1c").pack(pady=20)
Label(root, text="Enter password (used for encryption/decryption):", font=("Helvetica", 10), fg="lightgray", bg="#1c1c1c").pack()
password_entry = Entry(root, show='*', width=40)
password_entry.pack(pady=5)

Button(root, text="Encrypt File", command=encrypt_file, bg="#27ae60", fg="white", width=20).pack(pady=10)
Button(root, text="Decrypt File", command=decrypt_file, bg="#2980b9", fg="white", width=20).pack(pady=10)

root.mainloop()
