import tkinter as tk
from auth.auth import Authenticator
from password_manager.ui import PasswordManagerUI

def main():
    root = tk.Tk()
    root.withdraw()  # Ocultar la ventana raíz

    try:
        auth = Authenticator(root)
        authenticated, auth_token = auth.run()  # Obtener el estado de autenticación y el token
        if authenticated:
            app = PasswordManagerUI(root, auth_token)  # Pasar el token al Password Manager
            app.run()  # Lanzar el Password Manager solo si la autenticación es exitosa
        else:
            print("Authentication failed or token is missing.")
    except KeyboardInterrupt:
        print("Programa interrumpido por el usuario.")
    finally:
        root.destroy()  # Destruir el objeto root para cerrar todas las ventanas
    
    root.mainloop()

if __name__ == "__main__":
    main()
