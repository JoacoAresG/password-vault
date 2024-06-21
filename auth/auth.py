import tkinter as tk
from tkinter import messagebox
import pyotp
import qrcode
from PIL import Image, ImageTk
import os
import base64
import binascii
import secrets

class Authenticator:
    def __init__(self, master):
        self.master = master
        self.window = tk.Toplevel(master)
        self.window.title("Authenticator")
        self.window.geometry("400x500")  # Ajustar tamaño para mostrar el QR
        self.secret = self.load_or_create_secret()
        self.totp = pyotp.TOTP(self.secret)
        self.create_widgets()
        self.authenticated = False  # Añade un atributo para almacenar el estado de autenticación
        self.auth_token = None

    def load_or_create_secret(self):
        # Define the path for the secret key inside the data directory
        data_dir = 'data'
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        secret_file = os.path.join(data_dir, 'secret.key')
        
        if not os.path.exists(secret_file):
            secret = pyotp.random_base32()
            with open(secret_file, 'w') as file:
                file.write(secret)
            # Display QR code if the secret is created for the first time
            self.display_qr_code(secret)
            return secret
        else:
            with open(secret_file, 'r') as file:
                secret = file.read().strip()
            if self.is_valid_base32(secret):
                return secret
            else:
                messagebox.showerror("Error", "Invalid secret key found. Regenerating a new one.")
                secret = pyotp.random_base32()
                with open(secret_file, 'w') as file:
                    file.write(secret)
                self.display_qr_code(secret)
                return secret

    def is_valid_base32(self, secret):
        try:
            base64.b32decode(secret, casefold=True)
            return True
        except binascii.Error:
            return False

    def create_widgets(self):
        tk.Label(self.window, text="Enter TOTP from your authenticator app:").pack(pady=10)
        self.totp_entry = tk.Entry(self.window)
        self.totp_entry.pack(pady=5)
        tk.Button(self.window, text="Login", command=self.verify_totp).pack(pady=10)

    def display_qr_code(self, secret):
        uri = pyotp.TOTP(secret).provisioning_uri(name="user@example.com", issuer_name="YourApp")
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
        img = img.resize((300, 300), Image.LANCZOS)  # Ajustar el tamaño de la imagen
        qr_photo = ImageTk.PhotoImage(img)
        qr_label = tk.Label(self.window, image=qr_photo)
        qr_label.image = qr_photo  # Keep a reference!
        qr_label.pack(pady=10)

    def verify_totp(self):
        user_code = self.totp_entry.get()
        if self.totp.verify(user_code):
            messagebox.showinfo("Login Successful", "You are now logged in.")
            self.authenticated = True  # Actualizar el estado de autenticación
            self.auth_token = secrets.token_hex(16)  # Generar un token de autenticación
            self.window.destroy()
        else:
            messagebox.showerror("Login Failed", "The TOTP you entered is incorrect.")
            self.authenticated = False  # Asegurarse de actualizar el estado en caso de fallo

    def run(self):
        self.window.grab_set()  # Hacer la ventana modal
        self.master.wait_window(self.window)  # Esperar a que la ventana se cierre
        return self.authenticated, self.auth_token  # Devolver el estado de autenticación y el token
