🔐 Secure Password Manager
A secure, locally hosted password manager built with Python. It features a full desktop GUI for managing credentials and a lightweight, read-only web server for accessing your passwords on mobile devices via your local network.

✨ Features
🖥️ Desktop Application (password_manager.py)
Strong Encryption: Uses Fernet (AES) symmetric encryption. Data is secured using a master password derived via PBKDF2HMAC-SHA256.


CRUD Operations: Add, Edit, Delete, and Search your password database.


Password Generator: Built-in tool to generate secure, random passwords with customizable length and symbols.


Clipboard Integration: Quick-copy context menu and buttons for usernames and passwords.


Auto-Locking: "Lock" feature to secure the interface without exiting.

📱 Mobile Companion (mobile_server.py)

Read-Only Access: Safely view your credentials on your phone without risk of database corruption.


Mobile-Optimized UI: A responsive web interface that works in any mobile browser.


Smart Network Detection: Automatically detects Local IP and suggests Tailscale IP addresses for remote access.


Secure Handling: Decrypts data in memory only; requires the Master Password to access the web interface.

🛠️ Prerequisites
Python 3.x

Required Python packages:

cryptography

pyperclip

tkinter (usually included with Python)

📦 Installation
Clone the repository:

Bash

git clone https://github.com/dannylombardo/password_manager.git
cd password-manager
Install dependencies:

Bash

pip install cryptography pyperclip
🚀 Usage
1. Using the Desktop App
The desktop application is the primary tool for creating and editing your passwords.

Run the application:

Bash

python password_manager.py
First Run: You will be prompted to create a Master Password. This will generate salt.key and passwords.enc in the application directory.

Warning: Do not lose your master password. Data cannot be recovered without it.

Use the Add button to store new credentials.

Right-click any entry to copy the username or password.

2. Using the Mobile Server
The mobile server allows you to view your passwords on your smartphone. It requires the passwords.enc and salt.key files created by the desktop app.

Start the server:

Bash

python mobile_server.py [port]

(Default port is 8080 if unspecified).

The console will display the access URLs, for example:

Plaintext

📍 Access URLs:
   Local: http://localhost:8080
   Network: http://192.168.1.15:8080
   Tailscale: http://100.x.x.x:8080
Open the Network URL on your mobile device's browser.

Enter your Master Password to decrypt and view your vault.

🏗️ Building the Executable
A PyInstaller specification file (PasswordManager.spec) is included to compile the desktop application into a standalone executable.

Install PyInstaller:

Bash

pip install pyinstaller
Build the application:

Bash

pyinstaller PasswordManager.spec
The compiled application will be available in the dist/ folder.

🔒 Security Details

Encryption: Data is encrypted using the cryptography library's Fernet implementation.


Key Derivation: The encryption key is derived from your Master Password using PBKDF2HMAC with SHA256 hashing, a 32-byte salt, and 100,000 iterations.

Storage: Credentials are stored in passwords.enc. The random salt is stored in salt.key. Both files are required to decrypt the database.


Mobile Safety: The mobile server does not store the password or decrypted data on the disk; it exists only in memory during your session.

📄 License
Distributed under the MIT License. See LICENSE for more information.

Disclaimer: This software is provided for educational and personal use. Always maintain backups of your data.
