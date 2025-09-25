import mysql.connector
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import bcrypt
import tkinter as tk
from tkinter import messagebox
import os

# ---------------- Database Connection ---------------- #
class DatabaseConnection:
    def __init__(self):
        self.myconn = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd="6324",
            database="jeevan1"
        )
        self.cur = self.myconn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS notepad_USERS (
                id INT AUTO_INCREMENT PRIMARY KEY,
                FULLNAME VARCHAR(255),
                USER_NAME VARCHAR(255) UNIQUE,
                DOB DATE,
                AGE INT,
                GENDER VARCHAR(10),
                pkey BLOB
            )
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS notepad_CONTENTS (
                id INT AUTO_INCREMENT PRIMARY KEY,
                USER_NAME VARCHAR(255),
                FILE_NAME VARCHAR(255),
                CONTENTS TEXT,
                IV BLOB,
                UNIQUE (USER_NAME, FILE_NAME)
            )
        """)
        self.myconn.commit()

    def execute(self, sql, params=None):
        try:
            self.cur.execute(sql, params)
        except mysql.connector.errors.InternalError as e:
            if 'Unread result found' in str(e):
                self.cur.fetchall()
                self.cur.execute(sql, params)
            else:
                raise e

    def fetchone(self):
        return self.cur.fetchone()

    def fetchall(self):
        return self.cur.fetchall()

    def commit(self):
        self.myconn.commit()

# ---------------- User Management ---------------- #
class User(DatabaseConnection):
    def __init__(self, fullname=None, username=None, dob=None, age=None, gender=None, password=None):
        super().__init__()
        self.fullname = fullname
        self.username = username
        self.dob = dob
        self.age = age
        self.gender = gender
        self.password = password

    def signup(self):
        hashed_password = bcrypt.hashpw(self.password.encode(), bcrypt.gensalt())
        sql = "INSERT INTO notepad_USERS (FULLNAME, USER_NAME, DOB, AGE, GENDER, pkey) VALUES (%s, %s, %s, %s, %s, %s)"
        self.execute(sql, (self.fullname, self.username, self.dob, self.age, self.gender, hashed_password))
        self.commit()

    @staticmethod
    def signin(db, username, password):
        sql = "SELECT pkey, fullname FROM notepad_USERS WHERE USER_NAME = %s"
        db.execute(sql, (username,))
        result = db.fetchone()
        if result and bcrypt.checkpw(password.encode(), result[0]):
            return True, result[1]
        return False, None

# ---------------- Secured Notepad ---------------- #
class SecuredNotepad(DatabaseConnection):
    def __init__(self, username):
        super().__init__()
        self.username = username

    def _derive_key(self):
        # Generate a 16-byte AES key using username as password and random salt
        salt = b'secure_salt_1234'
        key = bcrypt.kdf(password=self.username.encode(), salt=salt, desired_key_bytes=16, rounds=100)
        return key

    def write_content(self, content, file_name):
        key = self._derive_key()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(content.encode(), AES.block_size))
        encoded_ciphertext = base64.b64encode(ciphertext).decode()
        sql = "INSERT INTO notepad_CONTENTS (USER_NAME, FILE_NAME, CONTENTS, IV) VALUES (%s, %s, %s, %s)"
        self.execute(sql, (self.username, file_name, encoded_ciphertext, iv))
        self.commit()

    def read_content(self, file_name):
        key = self._derive_key()
        sql = "SELECT CONTENTS, IV FROM notepad_CONTENTS WHERE USER_NAME=%s AND FILE_NAME=%s"
        self.execute(sql, (self.username, file_name))
        result = self.fetchone()
        if result:
            encoded_ciphertext, iv = result
            ciphertext = base64.b64decode(encoded_ciphertext)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode()
        return None

    def delete_content(self, file_name):
        sql = "DELETE FROM notepad_CONTENTS WHERE USER_NAME=%s AND FILE_NAME=%s"
        self.execute(sql, (self.username, file_name))
        self.commit()

    def edit_content(self, content, file_name):
        key = self._derive_key()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(content.encode(), AES.block_size))
        encoded_ciphertext = base64.b64encode(ciphertext).decode()
        sql = "UPDATE notepad_CONTENTS SET CONTENTS=%s, IV=%s WHERE USER_NAME=%s AND FILE_NAME=%s"
        self.execute(sql, (encoded_ciphertext, iv, self.username, file_name))
        self.commit()

    def get_saved_files(self):
        sql = "SELECT FILE_NAME FROM notepad_CONTENTS WHERE USER_NAME=%s"
        self.execute(sql, (self.username,))
        return [f[0] for f in self.fetchall()]

# ---------------- GUI Application ---------------- #
class NotepadApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secured Notepad")
        self.db = DatabaseConnection()
        self.username = None
        self.notepad = None
        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=20)
        self.show_login()

    # ---------- GUI screens ---------- #
    def show_login(self):
        for w in self.frame.winfo_children(): w.destroy()
        tk.Label(self.frame, text="Secured Notepad", font=("Arial", 20)).pack(pady=10)
        tk.Label(self.frame, text="Username:").pack()
        self.username_entry = tk.Entry(self.frame)
        self.username_entry.pack()
        tk.Label(self.frame, text="Password:").pack()
        self.password_entry = tk.Entry(self.frame, show='*')
        self.password_entry.pack()
        tk.Button(self.frame, text="Sign In", command=self.sign_in).pack(pady=5)
        tk.Button(self.frame, text="Sign Up", command=self.show_signup).pack(pady=5)

    def show_signup(self):
        for w in self.frame.winfo_children(): w.destroy()
        tk.Label(self.frame, text="Sign Up", font=("Arial", 20)).pack(pady=10)
        tk.Label(self.frame, text="Fullname:").pack()
        self.fullname_entry = tk.Entry(self.frame)
        self.fullname_entry.pack()
        tk.Label(self.frame, text="Username:").pack()
        self.username_entry = tk.Entry(self.frame)
        self.username_entry.pack()
        tk.Label(self.frame, text="Password:").pack()
        self.password_entry = tk.Entry(self.frame, show='*')
        self.password_entry.pack()
        tk.Label(self.frame, text="DOB (YYYY-MM-DD):").pack()
        self.dob_entry = tk.Entry(self.frame)
        self.dob_entry.pack()
        tk.Label(self.frame, text="Age:").pack()
        self.age_entry = tk.Entry(self.frame)
        self.age_entry.pack()
        tk.Label(self.frame, text="Gender:").pack()
        self.gender_entry = tk.Entry(self.frame)
        self.gender_entry.pack()
        tk.Button(self.frame, text="Sign Up", command=self.sign_up).pack(pady=5)
        tk.Button(self.frame, text="Back to Login", command=self.show_login).pack(pady=5)

    # ---------- User actions ---------- #
    def sign_up(self):
        user = User(
            fullname=self.fullname_entry.get(),
            username=self.username_entry.get(),
            password=self.password_entry.get(),
            dob=self.dob_entry.get(),
            age=self.age_entry.get(),
            gender=self.gender_entry.get()
        )
        try:
            user.signup()
            messagebox.showinfo("Success", "Sign up successful!")
            self.show_login()
        except mysql.connector.IntegrityError:
            messagebox.showerror("Error", "Username already exists.")

    def sign_in(self):
        success, fullname = User.signin(self.db, self.username_entry.get(), self.password_entry.get())
        if success:
            self.username = self.username_entry.get()
            self.notepad = SecuredNotepad(self.username)
            self.show_notepad()
        else:
            messagebox.showerror("Error", "Invalid credentials.")

    # ---------- Notepad screen ---------- #
    def show_notepad(self):
        for w in self.frame.winfo_children(): w.destroy()
        tk.Label(self.frame, text="Secured Notepad", font=("Arial", 20)).pack(pady=10)
        tk.Label(self.frame, text="File Name:").pack()
        self.file_name_entry = tk.Entry(self.frame)
        self.file_name_entry.pack()
        self.content_text = tk.Text(self.frame, width=40, height=10)
        self.content_text.pack()
        tk.Button(self.frame, text="Save", command=self.save_content).pack(pady=2)
        tk.Button(self.frame, text="Load", command=self.load_content).pack(pady=2)
        tk.Button(self.frame, text="Edit", command=self.edit_content).pack(pady=2)
        tk.Button(self.frame, text="Delete", command=self.delete_content).pack(pady=2)
        tk.Button(self.frame, text="Show Files", command=self.show_saved_files).pack(pady=2)
        tk.Button(self.frame, text="Logout", command=self.logout).pack(pady=5)

    # ---------- Notepad actions ---------- #
    def save_content(self):
        fn, content = self.file_name_entry.get(), self.content_text.get("1.0", tk.END).strip()
        if fn and content:
            self.notepad.write_content(content, fn)
            messagebox.showinfo("Success", "Content saved successfully!")
            self.content_text.delete("1.0", tk.END)
            self.file_name_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "Enter file name and content.")

    def load_content(self):
        fn = self.file_name_entry.get()
        if fn:
            content = self.notepad.read_content(fn)
            if content:
                self.content_text.delete("1.0", tk.END)
                self.content_text.insert(tk.END, content)
            else:
                messagebox.showwarning("Warning", "No such file found.")
        else:
            messagebox.showwarning("Warning", "Enter a file name.")

    def edit_content(self):
        fn, content = self.file_name_entry.get(), self.content_text.get("1.0", tk.END).strip()
        if fn and content:
            self.notepad.edit_content(content, fn)
            messagebox.showinfo("Success", "Content edited successfully!")
            self.content_text.delete("1.0", tk.END)
            self.file_name_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "Enter file name and content.")

    def delete_content(self):
        fn = self.file_name_entry.get()
        if fn:
            self.notepad.delete_content(fn)
            messagebox.showinfo("Success", "File deleted successfully!")
            self.content_text.delete("1.0", tk.END)
            self.file_name_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "Enter a file name.")

    def show_saved_files(self):
        files = self.notepad.get_saved_files()
        messagebox.showinfo("Saved Files", "\n".join(files) if files else "No files found.")

    def logout(self):
        self.username = None
        self.notepad = None
        self.show_login()

# ---------------- Run Application ---------------- #
if __name__ == "__main__":
    root = tk.Tk()
    app = NotepadApp(root)
    root.mainloop()
