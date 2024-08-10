import tkinter as tk
from tkinter import ttk, messagebox
import mysql.connector
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import os

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root001',
    'database': 'CreditVault'
}

KEY_FILE = 'encryption.key'

def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        return key

ENCRYPTION_KEY = load_or_generate_key()
fernet = Fernet(ENCRYPTION_KEY)

class CreditCardVault:
    def __init__(self, root):
        self.root = root
        self.root.title("CreditCard Vault")
        self.root.geometry("800x600")
        self.current_user = None
        self.current_role = None
        self.create_widgets()
        self.create_database()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.login_frame = ttk.Frame(self.notebook)
        self.card_frame = ttk.Frame(self.notebook)
        self.admin_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.login_frame, text="Login")
        self.notebook.add(self.card_frame, text="Credit Cards")
        self.notebook.add(self.admin_frame, text="Admin Dashboard")

        self.create_login_widgets()
        self.create_card_widgets()
        self.create_admin_widgets()

    def create_login_widgets(self):
        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        ttk.Button(self.login_frame, text="Login", command=self.login).grid(row=2, column=1, padx=10, pady=10)

    def create_card_widgets(self):
        ttk.Label(self.card_frame, text="Cardholder Name:").grid(row=0, column=0, padx=10, pady=10)
        self.cardholder_entry = ttk.Entry(self.card_frame)
        self.cardholder_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.card_frame, text="Card Number:").grid(row=1, column=0, padx=10, pady=10)
        self.card_number_entry = ttk.Entry(self.card_frame)
        self.card_number_entry.grid(row=1, column=1, padx=10, pady=10)

        ttk.Label(self.card_frame, text="Expiration Date:").grid(row=2, column=0, padx=10, pady=10)
        self.expiration_entry = ttk.Entry(self.card_frame)
        self.expiration_entry.grid(row=2, column=1, padx=10, pady=10)

        ttk.Label(self.card_frame, text="CVV:").grid(row=3, column=0, padx=10, pady=10)
        self.cvv_entry = ttk.Entry(self.card_frame, show="*")
        self.cvv_entry.grid(row=3, column=1, padx=10, pady=10)

        ttk.Button(self.card_frame, text="Add Card", command=self.add_card).grid(row=4, column=1, padx=10, pady=10)
        ttk.Button(self.card_frame, text="View Cards", command=self.view_cards).grid(row=5, column=1, padx=10, pady=10)

    def create_admin_widgets(self):
        ttk.Label(self.admin_frame, text="Admin Dashboard").grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(self.admin_frame, text="View All Users", command=self.view_all_users).grid(row=1, column=0, padx=10, pady=10)
        ttk.Button(self.admin_frame, text="View All Cards", command=self.view_all_cards).grid(row=2, column=0, padx=10, pady=10)

        ttk.Label(self.admin_frame, text="Username:").grid(row=3, column=0, padx=10, pady=10)
        self.new_username_entry = ttk.Entry(self.admin_frame)
        self.new_username_entry.grid(row=3, column=1, padx=10, pady=10)

        ttk.Label(self.admin_frame, text="Password:").grid(row=4, column=0, padx=10, pady=10)
        self.new_password_entry = ttk.Entry(self.admin_frame, show="*")
        self.new_password_entry.grid(row=4, column=1, padx=10, pady=10)

        ttk.Label(self.admin_frame, text="Role:").grid(row=5, column=0, padx=10, pady=10)
        self.role_var = tk.StringVar()
        self.role_combobox = ttk.Combobox(self.admin_frame, textvariable=self.role_var)
        self.role_combobox['values'] = ('admin', 'merchant', 'customer')
        self.role_combobox.grid(row=5, column=1, padx=10, pady=10)

        ttk.Button(self.admin_frame, text="Add User", command=self.add_user).grid(row=6, column=1, padx=10, pady=10)

    def create_database(self):
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
         # Create Users table
       # cursor.execute("""
        #CREATE TABLE IF NOT EXISTS Users (
         #   user_id INT AUTO_INCREMENT PRIMARY KEY,
         #   username VARCHAR(50) UNIQUE,
         #   password_hash VARCHAR(64),
         #   role ENUM('admin', 'merchant', 'customer')
        #)
        #""")

        # Create CreditCards table
        #cursor.execute("""
        #CREATE TABLE IF NOT EXISTS CreditCards (
          #  card_id INT AUTO_INCREMENT PRIMARY KEY,
          #  user_id INT,
          #  cardholder_name VARCHAR(100),
          #  card_number VARCHAR(255),
           # expiration_date VARCHAR(255),
          #  cvv VARCHAR(255),
          #  FOREIGN KEY (user_id) REFERENCES Users(user_id)
       # )
        #""")

        # Create default admin user if not exists
       # admin_password = hashlib.sha256("admin123".encode()).hexdigest()
        #cursor.execute("INSERT IGNORE INTO Users (username, password_hash, role) VALUES (%s, %s, %s)", 
        #               ("admin", admin_password, "admin"))

        conn.commit()
        conn.close()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("SELECT user_id, role FROM Users WHERE username = %s AND password_hash = %s", 
                       (username, password_hash))
        user = cursor.fetchone()

        if user:
            self.current_user = user[0]
            self.current_role = user[1]
            messagebox.showinfo("Success", f"Logged in as {self.current_role}")
            self.notebook.select(1)  # Switch to Credit Cards tab
        else:
            messagebox.showerror("Error", "Invalid credentials")

        conn.close()

    def add_card(self):
        if not self.current_user:
            messagebox.showerror("Error", "Please login first")
            return

        cardholder = self.cardholder_entry.get()
        card_number = self.card_number_entry.get()
        expiration = self.expiration_entry.get()
        cvv = self.cvv_entry.get()

        # Encrypt sensitive data
        encrypted_card_number = fernet.encrypt(card_number.encode()).decode()
        encrypted_cvv = fernet.encrypt(cvv.encode()).decode()

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO CreditCards (user_id, cardholder_name, card_number, expiration_date, cvv)
        VALUES (%s, %s, %s, %s, %s)
        """, (self.current_user, cardholder, encrypted_card_number, expiration, encrypted_cvv))

        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Card added successfully")
        self.clear_card_entries()

    def view_cards(self):
        if not self.current_user:
            messagebox.showerror("Error", "Please login first")
            return

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM CreditCards WHERE user_id = %s", (self.current_user,))
        cards = cursor.fetchall()

        conn.close()

        if cards:
            card_window = tk.Toplevel(self.root)
            card_window.title("Your Credit Cards")
            
            for i, card in enumerate(cards):
                try:
                    decrypted_number = fernet.decrypt(card[3].encode()).decode()
                    masked_number = f"**** **** **** {decrypted_number[-4:]}"
                    ttk.Label(card_window, text=f"Card {i+1}: {card[2]} - {masked_number}").pack(padx=10, pady=5)
                except InvalidToken:
                    messagebox.showerror("Error", "Decryption failed. Invalid key or corrupted data.")
        else:
            messagebox.showinfo("Info", "No cards found")

    def view_all_users(self):
        if self.current_role != 'admin':
            messagebox.showerror("Error", "Admin access required")
            return

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("SELECT user_id, username, role FROM Users")
        users = cursor.fetchall()

        conn.close()

        user_window = tk.Toplevel(self.root)
        user_window.title("All Users")
        
        for user in users:
            ttk.Label(user_window, text=f"ID: {user[0]}, Username: {user[1]}, Role: {user[2]}").pack(padx=10, pady=5)

    def view_all_cards(self):
        if self.current_role != 'admin':
            messagebox.showerror("Error", "Admin access required")
            return

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
        SELECT c.card_id, u.username, c.cardholder_name, c.card_number, c.expiration_date
        FROM CreditCards c
        JOIN Users u ON c.user_id = u.user_id
        """)
        cards = cursor.fetchall()

        conn.close()

        card_window = tk.Toplevel(self.root)
        card_window.title("All Credit Cards")
        
        for card in cards:
            try:
                decrypted_number = fernet.decrypt(card[3].encode()).decode()
                masked_number = f"**** **** **** {decrypted_number[-4:]}"
                ttk.Label(card_window, text=f"ID: {card[0]}, User: {card[1]}, Name: {card[2]}, Number: {masked_number}, Exp: {card[4]}").pack(padx=10, pady=5)
            except InvalidToken:
                messagebox.showerror("Error", "Decryption failed. Invalid key or corrupted data.")

    def add_user(self):
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()
        role = self.role_var.get()

        if not username or not password or not role:
            messagebox.showerror("Error", "All fields are required")
            return

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO Users (username, password_hash, role) VALUES (%s, %s, %s)", 
                           (username, password_hash, role))
            conn.commit()
            messagebox.showinfo("Success", f"User '{username}' added successfully")
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Error: {err}")

        conn.close()
        self.clear_admin_entries()

    def clear_admin_entries(self):
        self.new_username_entry.delete(0, tk.END)
        self.new_password_entry.delete(0, tk.END)
        self.role_combobox.set('')

    def clear_card_entries(self):
        self.cardholder_entry.delete(0, tk.END)
        self.card_number_entry.delete(0, tk.END)
        self.expiration_entry.delete(0, tk.END)
        self.cvv_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = CreditCardVault(root)
    root.mainloop()
