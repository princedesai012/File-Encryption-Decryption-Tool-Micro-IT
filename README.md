# File-Encryption-Decryption-Tool-Micro-IT
## 🔐 File Encryption/Decryption Tool

This is a simple yet secure **Python GUI application** built using `Tkinter` and `cryptography` that allows users to **encrypt** and **decrypt** files using a password. It ensures privacy and security by using **PBKDF2HMAC with SHA-256** for key derivation and **Fernet encryption** for secure file handling.

---

### 🚀 Features

* 🔐 Password-based encryption
* 🔑 Secure key derivation using PBKDF2 and SHA-256
* 🧂 Random salt generation and secure storage
* 💡 User-friendly GUI with error handling
* 🪄 Simple decrypt button to recover files
* 🌙 Dark-themed interface

---

### 🛠️ Technologies Used

* **Python 3**
* **Tkinter** – for GUI
* **cryptography** – for encryption and decryption (Fernet, PBKDF2)

---

### 🧪 How It Works

* When encrypting:

  * You select a file.
  * Enter a password (used to generate a secure key).
  * A random salt is generated and prepended to the encrypted file.
* When decrypting:

  * You select the `.encrypted` file.
  * Enter the original password.
  * The salt is extracted, the key is derived, and the file is decrypted.

> ⚠️ Make sure to **remember the password**. Without it, decryption is impossible.

---

### 📁 File Structure

```
file-encryption-tool/
│
├── main.py      # Main application file
├── screenshot.png          # Optional UI screenshot
└── README.md               # Project README
```

---

### 💡 Future Improvements

* Dark/Light Mode toggle
* Multiple file encryption
* Drag-and-drop file support
* Cloud upload for encrypted files
  
### 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
