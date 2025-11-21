import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import pyperclip
from datetime import datetime

class PasswordManager:
    def __init__(self):
        self.master_password = None
        self.cipher_suite = None
        self.passwords_file = "passwords.enc"
        self.salt_file = "salt.key"
        self.passwords = {}
        
    def generate_key_from_password(self, password, salt):
        """Generate encryption key from master password"""
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def setup_encryption(self, master_password):
        """Setup encryption with master password"""
        self.master_password = master_password
        
        # Load or create salt
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
        
        key = self.generate_key_from_password(master_password, salt)
        self.cipher_suite = Fernet(key)
    
    def verify_master_password(self, password):
        """Verify master password by attempting to decrypt existing data"""
        if not os.path.exists(self.passwords_file) or not os.path.exists(self.salt_file):
            return True  # No existing data, any password is valid for setup
        
        try:
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            
            key = self.generate_key_from_password(password, salt)
            test_cipher = Fernet(key)
            
            with open(self.passwords_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = test_cipher.decrypt(encrypted_data)
            json.loads(decrypted_data.decode())
            return True
        except:
            return False
    
    def save_passwords(self):
        """Encrypt and save passwords to file"""
        if not self.cipher_suite:
            return False
        
        try:
            # Add metadata
            data = {
                'passwords': self.passwords,
                'last_modified': datetime.now().isoformat()
            }
            
            json_data = json.dumps(data, indent=2)
            encrypted_data = self.cipher_suite.encrypt(json_data.encode())
            
            with open(self.passwords_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {str(e)}")
            return False
    
    def load_passwords(self):
        """Load and decrypt passwords from file"""
        if not os.path.exists(self.passwords_file) or not self.cipher_suite:
            return True
        
        try:
            with open(self.passwords_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            data = json.loads(decrypted_data.decode())
            
            # Handle both old format (just passwords) and new format (with metadata)
            if 'passwords' in data:
                self.passwords = data['passwords']
            else:
                self.passwords = data
            
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load passwords: {str(e)}")
            return False
    
    def add_password(self, service, username, password, notes=""):
        """Add a new password entry"""
        self.passwords[service] = {
            'username': username,
            'password': password,
            'notes': notes,
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }
        return self.save_passwords()
    
    def update_password(self, service, username, password, notes=""):
        """Update existing password entry"""
        if service in self.passwords:
            self.passwords[service].update({
                'username': username,
                'password': password,
                'notes': notes,
                'modified': datetime.now().isoformat()
            })
            return self.save_passwords()
        return False
    
    def delete_password(self, service):
        """Delete a password entry"""
        if service in self.passwords:
            del self.passwords[service]
            return self.save_passwords()
        return False
    
    def generate_secure_password(self, length=16, include_symbols=True):
        """Generate a secure random password"""
        import string
        
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += "!@#$%^&*"
        
        return ''.join(secrets.choice(chars) for _ in range(length))

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.pm = PasswordManager()
        self.authenticated = False
        
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.setup_login_ui()
    
    def setup_login_ui(self):
        """Setup the login interface"""
        self.clear_window()
        
        # Center frame
        login_frame = ttk.Frame(self.root)
        login_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        ttk.Label(login_frame, text="Password Manager", font=('Arial', 16, 'bold')).pack(pady=20)
        
        ttk.Label(login_frame, text="Master Password:").pack(pady=5)
        self.master_password_entry = ttk.Entry(login_frame, show="*", width=30)
        self.master_password_entry.pack(pady=5)
        self.master_password_entry.bind('<Return>', lambda e: self.authenticate())
        
        button_frame = ttk.Frame(login_frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Login", command=self.authenticate).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Exit", command=self.root.quit).pack(side=tk.LEFT, padx=5)
        
        self.master_password_entry.focus()
    
    def authenticate(self):
        """Authenticate user with master password"""
        master_password = self.master_password_entry.get()
        
        if not master_password:
            messagebox.showerror("Error", "Please enter master password")
            return
        
        if not self.pm.verify_master_password(master_password):
            messagebox.showerror("Error", "Invalid master password")
            self.master_password_entry.delete(0, tk.END)
            return
        
        self.pm.setup_encryption(master_password)
        
        if self.pm.load_passwords():
            self.authenticated = True
            self.setup_main_ui()
        else:
            messagebox.showerror("Error", "Failed to load password database")
    
    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def setup_main_ui(self):
        """Setup the main application interface"""
        self.clear_window()
        
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Lock", command=self.lock_application)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Generate Password", command=self.show_password_generator)
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 10))
        search_entry.bind('<KeyRelease>', self.filter_passwords)
        
        # Buttons frame
        button_frame = ttk.Frame(search_frame)
        button_frame.pack(side=tk.RIGHT)
        
        ttk.Button(button_frame, text="Add", command=self.add_password_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Edit", command=self.edit_password_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Delete", command=self.delete_password_dialog).pack(side=tk.LEFT, padx=2)
        
        # Password list frame
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for password list
        columns = ('Service', 'Username', 'Modified')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        self.tree.heading('Service', text='Service')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Modified', text='Last Modified')
        
        self.tree.column('Service', width=200)
        self.tree.column('Username', width=200)
        self.tree.column('Modified', width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy Username", command=self.copy_username)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Edit", command=self.edit_password_dialog)
        self.context_menu.add_command(label="Delete", command=self.delete_password_dialog)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.copy_password)
        
        self.refresh_password_list()
    
    def show_context_menu(self, event):
        """Show context menu on right click"""
        if self.tree.selection():
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_username(self):
        """Copy username to clipboard"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            service = item['values'][0]
            if service in self.pm.passwords:
                pyperclip.copy(self.pm.passwords[service]['username'])
                messagebox.showinfo("Copied", "Username copied to clipboard")
    
    def copy_password(self, event=None):
        """Copy password to clipboard"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            service = item['values'][0]
            if service in self.pm.passwords:
                pyperclip.copy(self.pm.passwords[service]['password'])
                messagebox.showinfo("Copied", "Password copied to clipboard")
    
    def filter_passwords(self, event=None):
        """Filter password list based on search"""
        self.refresh_password_list()
    
    def refresh_password_list(self):
        """Refresh the password list display"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        search_term = self.search_var.get().lower()
        
        # Add filtered passwords
        for service, data in self.pm.passwords.items():
            if (search_term in service.lower() or 
                search_term in data['username'].lower()):
                
                modified = data.get('modified', 'Unknown')
                if modified != 'Unknown':
                    try:
                        modified_dt = datetime.fromisoformat(modified.replace('Z', '+00:00'))
                        modified = modified_dt.strftime('%Y-%m-%d %H:%M')
                    except:
                        pass
                
                self.tree.insert('', tk.END, values=(service, data['username'], modified))
    
    def add_password_dialog(self):
        """Show add password dialog"""
        self.show_password_dialog("Add Password")
    
    def edit_password_dialog(self):
        """Show edit password dialog"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to edit")
            return
        
        item = self.tree.item(selection[0])
        service = item['values'][0]
        self.show_password_dialog("Edit Password", service)
    
    def show_password_dialog(self, title, service=None):
        """Show password add/edit dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Form fields
        ttk.Label(dialog, text="Service/Website:").pack(anchor=tk.W, padx=10, pady=(10,0))
        service_var = tk.StringVar(value=service or "")
        service_entry = ttk.Entry(dialog, textvariable=service_var)
        service_entry.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(dialog, text="Username/Email:").pack(anchor=tk.W, padx=10)
        username_var = tk.StringVar()
        username_entry = ttk.Entry(dialog, textvariable=username_var)
        username_entry.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(dialog, text="Password:").pack(anchor=tk.W, padx=10)
        password_frame = ttk.Frame(dialog)
        password_frame.pack(fill=tk.X, padx=10, pady=5)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=password_var, show="*")
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(password_frame, text="Generate", 
                  command=lambda: self.generate_password_for_dialog(password_var)).pack(side=tk.RIGHT, padx=(5,0))
        
        ttk.Label(dialog, text="Notes (optional):").pack(anchor=tk.W, padx=10)
        notes_text = tk.Text(dialog, height=4)
        notes_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Load existing data for editing
        if service and service in self.pm.passwords:
            data = self.pm.passwords[service]
            username_var.set(data['username'])
            password_var.set(data['password'])
            notes_text.insert(tk.END, data.get('notes', ''))
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def save_password():
            service_name = service_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()
            notes = notes_text.get(1.0, tk.END).strip()
            
            if not service_name or not username or not password:
                messagebox.showerror("Error", "Please fill in all required fields")
                return
            
            if service:  # Editing
                if self.pm.update_password(service_name, username, password, notes):
                    messagebox.showinfo("Success", "Password updated successfully")
                    dialog.destroy()
                    self.refresh_password_list()
            else:  # Adding
                if service_name in self.pm.passwords:
                    if not messagebox.askyesno("Confirm", "Service already exists. Overwrite?"):
                        return
                
                if self.pm.add_password(service_name, username, password, notes):
                    messagebox.showinfo("Success", "Password added successfully")
                    dialog.destroy()
                    self.refresh_password_list()
        
        ttk.Button(button_frame, text="Save", command=save_password).pack(side=tk.RIGHT, padx=(5,0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        service_entry.focus()
    
    def generate_password_for_dialog(self, password_var):
        """Generate password for dialog"""
        password = self.pm.generate_secure_password()
        password_var.set(password)
    
    def delete_password_dialog(self):
        """Delete selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to delete")
            return
        
        item = self.tree.item(selection[0])
        service = item['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Delete password for '{service}'?"):
            if self.pm.delete_password(service):
                messagebox.showinfo("Success", "Password deleted successfully")
                self.refresh_password_list()
    
    def show_password_generator(self):
        """Show password generator dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Password Generator")
        dialog.geometry("350x250")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        ttk.Label(dialog, text="Password Length:").pack(anchor=tk.W, padx=10, pady=(10,0))
        length_var = tk.IntVar(value=16)
        length_spin = ttk.Spinbox(dialog, from_=8, to=64, textvariable=length_var)
        length_spin.pack(fill=tk.X, padx=10, pady=5)
        
        symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Include symbols (!@#$%^&*)", variable=symbols_var).pack(anchor=tk.W, padx=10)
        
        ttk.Label(dialog, text="Generated Password:").pack(anchor=tk.W, padx=10, pady=(10,0))
        password_var = tk.StringVar()
        password_entry = ttk.Entry(dialog, textvariable=password_var, state='readonly')
        password_entry.pack(fill=tk.X, padx=10, pady=5)
        
        def generate():
            password = self.pm.generate_secure_password(length_var.get(), symbols_var.get())
            password_var.set(password)
        
        def copy_generated():
            if password_var.get():
                pyperclip.copy(password_var.get())
                messagebox.showinfo("Copied", "Password copied to clipboard")
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Generate", command=generate).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(button_frame, text="Copy", command=copy_generated).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Generate initial password
        generate()
    
    def lock_application(self):
        """Lock the application"""
        self.authenticated = False
        self.pm.master_password = None
        self.pm.cipher_suite = None
        self.setup_login_ui()

def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()