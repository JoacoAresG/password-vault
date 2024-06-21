# Password Vault

Password Vault is a secure and user-friendly password manager application that uses two-factor authentication (2FA) to ensure the safety of your passwords. This application is built using Python and Tkinter for the GUI, and it supports dark mode for a better user experience.

## Features

- **Two-Factor Authentication (2FA)**: Secure your application using TOTP.
- **Password Management**: Add, search, export, import, and view passwords.
- **Dark Mode**: Switch between light and dark themes.
- **Encryption**: Store your passwords securely with encryption.

## Installation

### Requirements

- Python 3.6 or higher
- Tkinter
- Pillow
- pyotp
- qrcode
- cryptography

### Steps

1. **Clone the repository**:
   ```sh
   git clone https://github.com/JoacoAresG/password-vault.git
   cd password-vault
   ```
   
2. **Install the required packages**:
   ```sh
   pip install -r requirements.txt
   ```
3. **Run the application**:
   ```sh
   python main.py
   ```
## Usage

# Authenticator

1. When you run the application for the first time, a QR code will be displayed.
2. Scan the QR code using any authenticator app (like Google Authenticator or Authy).
3. Enter the TOTP generated by your authenticator app to log in.

# Password Manager
- Add Password: Click on the "Add Password" button to add a new password.
- Search Passwords: Click on the "Search Passwords" button to search for passwords.
- Export Passwords: Click on the "Export Passwords" button to export your passwords to a JSON file.
- Import Passwords: Click on the "Import Passwords" button to import passwords from a JSON file.
- Copy Password: Select a password from the list and click on the "Copy Password" button to copy it to the clipboard.
- Toggle Dark Mode: Click on the "Toggle Dark Mode" button to switch between light and dark themes.
 






