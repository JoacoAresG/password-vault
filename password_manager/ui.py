import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import json
from .password_manager import initialize_vault, add_password, load_passwords, save_passwords
from .utils import generate_password

class PasswordManagerUI:
    def __init__(self, master, auth_token):
        self.master = master
        self.auth_token = auth_token
        self.window = tk.Toplevel(master)
        self.window.title("Password Manager")
        self.window.geometry('800x600')  # Tamaño ajustado según necesidad
        self.setup_styles()

        if not self.verify_auth_token():
            messagebox.showerror("Authentication Error", "Invalid authentication token.")
            self.window.destroy()
            return

        self.encryption_key, self.passwords = initialize_vault()
        self.create_widgets()

    def verify_auth_token(self):
        # Verifica que el token pasado sea correcto
        return self.auth_token is not None and len(self.auth_token) == 32

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("default")
    
        # Modo claro
        self.style.configure("TButton", padding=6, relief="flat", background="#eee", foreground="#000")
        self.style.configure("TFrame", background="#fff")
        self.style.configure("TLabel", background="#fff", padding=6, foreground="#000")
        self.style.configure("TEntry", background="#fff", foreground="#000")

    def configure_styles(self, light=True):
        if light:
            background = "#f5f5dc"  # crema para el fondo en modo claro
            foreground = "#000000"  # negro para texto en modo claro
            button_background = "#dddddd"  # un gris claro para botones en modo claro
            entry_background = "#ffffff"  # blanco para entradas en modo claro
            entry_foreground = "#000000"  # texto negro en entradas en modo claro
        else:
            background = "#003366"  # azul oscuro para el fondo en modo oscuro
            foreground = "#ffffff"  # blanco para texto en modo oscuro
            button_background = "#004080"  # un azul más claro para botones en modo oscuro
            entry_background = "#222222"  # un gris muy oscuro para entradas en modo oscuro
            entry_foreground = "#ffffff"  # texto blanco en entradas en modo oscuro

        self.style.configure("TFrame", background=background)
        self.style.configure("TLabel", background=background, foreground=foreground)
        self.style.configure("TButton", background=button_background, foreground=foreground, borderwidth=1)
        self.style.configure("TEntry", background=entry_background, foreground=entry_foreground)

        # Actualizar los widgets existentes con los nuevos colores
        for widget in self.window.winfo_children():
            self.apply_widget_theme(widget, background, foreground, button_background, entry_background, entry_foreground)

    def create_widgets(self):
        frame = ttk.Frame(self.window)
        frame.pack(fill=tk.BOTH, expand=True)

        # Añadir botones y widgets aquí...
        ttk.Button(frame, text="Add Password", command=self.add_password_ui).pack(fill=tk.X)
        ttk.Button(frame, text="Search Passwords", command=self.search_passwords).pack(fill=tk.X)
        ttk.Button(frame, text="Export Passwords", command=self.export_passwords).pack(fill=tk.X)
        ttk.Button(frame, text="Import Passwords", command=self.import_passwords).pack(fill=tk.X)
        ttk.Button(frame, text="Toggle Dark Mode", command=self.toggle_dark_mode).pack(fill=tk.X)
        ttk.Button(frame, text="Copy Password", command=self.copy_password).pack(fill=tk.X)
        ttk.Button(frame, text="Close", command=self.close_password_manager).pack(fill=tk.X)

        self.password_list = tk.Listbox(frame, height=15)
        self.password_list.pack(fill=tk.BOTH, expand=True, pady=10)
        self.password_list.bind('<Double-1>', self.view_password_details)

        self.update_password_list()

    def add_password_ui(self):
        title = simpledialog.askstring("Title", "Enter the title:")
        username = simpledialog.askstring("Username", "Enter the username:")
        category = simpledialog.askstring("Category", "Enter the category:")

        choice = messagebox.askquestion("Password", "Would you like to generate a password?")
        if choice == 'yes':
            password = generate_password()
        else:
            password = simpledialog.askstring("Password", "Enter the password:")

        description = simpledialog.askstring("Description", "Enter a description:")

        if title and username and password:
            add_password(self.passwords, title, username, password, description, category, self.encryption_key)
            self.update_password_list()
        else:
            messagebox.showerror("Error", "All fields must be filled out")

    def export_passwords(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                json.dump(self.passwords, file)
            messagebox.showinfo("Export Successful", "Passwords exported successfully")

    def import_passwords(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'r') as file:
                self.passwords = json.load(file)
            self.update_password_list()
            messagebox.showinfo("Import Successful", "Passwords imported successfully")

    def search_passwords(self):
        query = simpledialog.askstring("Search", "Enter search query:")
        if query:
            results = [p for p in self.passwords if query.lower() in p['title'].lower() or query.lower() in p['username'].lower() or query.lower() in p['description'].lower() or query.lower() in p['category'].lower()]
            if results:
                self.display_search_results(results)
            else:
                messagebox.showinfo("No Results", "No passwords found matching the search query.")

    def display_search_results(self, results):
        result_window = tk.Toplevel()
        result_window.title("Search Results")
        listbox = tk.Listbox(result_window, height=15, width=50)
        listbox.pack(pady=5)
        for result in results:
            listbox.insert(tk.END, f"{result['title']} ({result['username']})")
        listbox.bind('<Double-1>', lambda e: self.view_password_details(e, results))

    def toggle_dark_mode(self):
        current_theme = self.style.theme_use()
        if current_theme == "default":
            self.style.theme_use("clam")  # Cambiar a un tema oscuro
            self.style.configure("TButton", background="#333", foreground="#fff")
            self.style.configure("TFrame", background="#222")
            self.style.configure("TLabel", background="#222", foreground="#fff")
            self.style.configure("TEntry", background="#444", foreground="#fff")
        else:
            self.style.theme_use("default")  # Cambiar a un tema claro
            self.style.configure("TButton", background="#eee", foreground="#000")
            self.style.configure("TFrame", background="#fff")
            self.style.configure("TLabel", background="#fff", foreground="#000")
            self.style.configure("TEntry", background="#fff", foreground="#000")


    def update_password_list(self):
        self.password_list.delete(0, tk.END)
        for password in self.passwords:
            self.password_list.insert(tk.END, f"{password['title']} ({password['username']})")

    def view_password_details(self, event, search_results=None):
        selected_idx = event.widget.curselection()
        if selected_idx:
            if search_results:
                selected_password = search_results[selected_idx[0]]
            else:
                selected_password = self.passwords[selected_idx[0]]
            details = f"Title: {selected_password['title']}\nUsername: {selected_password['username']}\nPassword: {selected_password['password']}\nDescription: {selected_password['description']}\nCategory: {selected_password['category']}"
            messagebox.showinfo("Password Details", details)

    def close_password_manager(self):
        self.window.destroy()

    def copy_password(self):
        selected_idx = self.password_list.curselection()
        if selected_idx:
            selected_password = self.passwords[selected_idx[0]]
            self.master.clipboard_clear()
            self.master.clipboard_append(selected_password['password'])
            messagebox.showinfo("Copied", "Password copied to clipboard")

    def run(self):
        self.master.wait_window(self.window)