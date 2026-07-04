import base64
import os
import secrets
import sqlite3
import string
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Optional

import customtkinter as ctk
import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class DatabaseManager:
    """Obsługuje połączenia z bazą SQLite, ustawienia oraz wpisy haseł."""

    def __init__(self, db_path: str = "passwords.db"):
        self.db_path = db_path
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cursor = self.connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                master_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                notes TEXT DEFAULT '',
                modified_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        self.connection.commit()

    def create_user(self, master_hash: str, salt: str):
        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM users")
        cursor.execute(
            "INSERT INTO users (master_hash, salt) VALUES (?, ?)",
            (master_hash, salt),
        )
        self.connection.commit()

    def update_user(self, master_hash: str, salt: str):
        # Tabela users zawsze ma dokładnie jeden wiersz (create_user usuwa
        # poprzednie rekordy przed wstawieniem nowego), więc nie trzeba
        # polegać na konkretnym, zahardkodowanym id.
        cursor = self.connection.cursor()
        cursor.execute("UPDATE users SET master_hash = ?, salt = ?", (master_hash, salt))
        self.connection.commit()

    def get_user(self):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users LIMIT 1")
        return cursor.fetchone()

    def add_password(self, website: str, username: str, encrypted_password: bytes, notes: str = "", modified_at: Optional[str] = None):
        cursor = self.connection.cursor()
        if modified_at is None:
            modified_at = datetime.now().strftime("%Y-%m-%d %H:%M")
        cursor.execute(
            "INSERT INTO passwords (website, username, encrypted_password, notes, modified_at) VALUES (?, ?, ?, ?, ?)",
            (website, username, encrypted_password, notes, modified_at),
        )
        self.connection.commit()

    def update_password(self, password_id: int, website: str, username: str, encrypted_password: bytes, notes: str = "", modified_at: Optional[str] = None):
        cursor = self.connection.cursor()
        if modified_at is None:
            modified_at = datetime.now().strftime("%Y-%m-%d %H:%M")
        cursor.execute(
            "UPDATE passwords SET website = ?, username = ?, encrypted_password = ?, notes = ?, modified_at = ? WHERE id = ?",
            (website, username, encrypted_password, notes, modified_at, password_id),
        )
        self.connection.commit()

    def delete_password(self, password_id: int):
        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
        self.connection.commit()

    def get_passwords(self):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM passwords ORDER BY website COLLATE NOCASE")
        return cursor.fetchall()

    def get_setting(self, key: str, default: str = "") -> str:
        cursor = self.connection.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str):
        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.connection.commit()

    def close(self):
        self.connection.close()


class CryptoManager:
    """Umożliwia haszowanie hasła głównego i szyfrowanie/odszyfrowanie haseł użytkownika."""

    def __init__(self, master_password: str, salt: bytes):
        self.master_password = master_password.encode("utf-8")
        self.salt = salt
        self.fernet = self._create_fernet()

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        return os.urandom(length)

    @staticmethod
    def _derive_key(password: bytes, salt: bytes, iterations: int = 200_000) -> bytes:
        """Wyprowadza klucz symetryczny z hasła głównego przy użyciu PBKDF2HMAC z SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password))

    def _create_fernet(self) -> Fernet:
        key = self._derive_key(self.master_password, self.salt)
        return Fernet(key)

    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:
        """Hashuje hasło główne do przechowywania w bazie danych."""
        password_bytes = password.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password_bytes)).decode("utf-8")

    @classmethod
    def verify_password(cls, password: str, salt: bytes, expected_hash: str) -> bool:
        """Weryfikuje podane hasło główne względem zapisanego hasha."""
        try:
            return cls.hash_password(password, salt) == expected_hash
        except Exception:
            return False

    def encrypt(self, plaintext: str) -> bytes:
        """Szyfruje hasło użytkownika."""
        return self.fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, token: bytes) -> str:
        """Odszyfrowuje hasło użytkownika."""
        return self.fernet.decrypt(token).decode("utf-8")


class PasswordManagerApp(ctk.CTk):
    """Główna aplikacja menedżera haseł z obsługą ustawień, edycji i bezpieczeństwa."""

    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.title("Menedżer Haseł")
        self.geometry("1000x700")
        self.resizable(False, False)

        self.current_db_path = "passwords.db"
        self.db = DatabaseManager(self.current_db_path)
        self.crypto_manager = None
        self.current_passwords = []
        self.inactivity_timer_id = None
        self.font_size = 14
        self.clipboard_timeout = 20
        self.inactivity_timeout_minutes = 5
        self.theme_mode = "System"
        self.db_path_var = tk.StringVar(value=self.current_db_path)

        self._load_settings()
        self._apply_settings()
        self._initialize_gui()
        self._bind_activity_events()
        self._load_login_screen()

    def _initialize_gui(self):
        self.login_frame = ctk.CTkFrame(self, corner_radius=12, width=520, height=420)
        self.login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        self.main_frame = ctk.CTkFrame(self, corner_radius=12, width=920, height=650)
        self.main_frame.place_forget()

    def _clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def _apply_font(self, widget, size=None, weight="normal"):
        try:
            widget.configure(font=ctk.CTkFont(size=size or self.font_size, weight=weight))
        except Exception:
            pass

    def _apply_tree_font(self):
        if not hasattr(self, "tree"):
            return
        try:
            style = ttk.Style()
            style.configure("Treeview", font=("Segoe UI", self.font_size), rowheight=max(24, self.font_size + 8))
            style.configure("Treeview.Heading", font=("Segoe UI", self.font_size, "bold"))
            self.tree.configure(style="Treeview")
        except Exception:
            pass

    def _load_settings(self):
        """Wczytuje ustawienia z aktualnie otwartej bazy danych.

        Uwaga: dawniej metoda ta próbowała też odczytać zapisaną ścieżkę do
        bazy ("db_path") i automatycznie się na nią przełączyć. Był to
        martwy i ryzykowny mechanizm (mógł np. wywalić aplikację przy
        starcie, jeśli zapisany katalog przestał istnieć), więc został
        usunięty.
        """
        self.theme_mode = self.db.get_setting("theme", "System")
        font_value = self.db.get_setting("font_size", self.db.get_setting("font_scale", "14"))
        try:
            self.font_size = max(10, min(18, int(float(font_value))))
        except Exception:
            self.font_size = 14
        try:
            self.clipboard_timeout = max(5, int(self.db.get_setting("clipboard_timeout", "20")))
        except Exception:
            self.clipboard_timeout = 20
        try:
            self.inactivity_timeout_minutes = max(1, int(self.db.get_setting("inactivity_timeout", "5")))
        except Exception:
            self.inactivity_timeout_minutes = 5

    def _apply_settings(self):
        ctk.set_appearance_mode(self.theme_mode)

    def _bind_activity_events(self):
        # <Motion> celowo pominięte - odpalałoby się na każde drgnięcie
        # myszy i bez potrzeby przeplanowywało timer bezczynności.
        self.bind_all("<KeyPress>", self._reset_inactivity_timer)
        self.bind_all("<Button-1>", self._reset_inactivity_timer)

    def _reset_inactivity_timer(self, *_args):
        if self.crypto_manager is None:
            return
        if self.inactivity_timer_id is not None:
            self.after_cancel(self.inactivity_timer_id)
        timeout_ms = max(self.inactivity_timeout_minutes, 1) * 60_000
        self.inactivity_timer_id = self.after(timeout_ms, self._lock_app_for_inactivity)

    def _lock_app_for_inactivity(self):
        messagebox.showinfo("Blokada", "Zostałeś wylogowany z powodu bezczynności.")
        self._logout()

    def _load_login_screen(self):
        self.main_frame.place_forget()
        self.login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self._clear_frame(self.login_frame)
        if self.inactivity_timer_id is not None:
            self.after_cancel(self.inactivity_timer_id)
            self.inactivity_timer_id = None

        login_frame = ctk.CTkFrame(self.login_frame, corner_radius=10)
        login_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(login_frame, text="Baza haseł", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(12, 6))
        path_row = ctk.CTkFrame(login_frame)
        path_row.pack(fill="x", padx=20, pady=(0, 8))
        path_entry = ctk.CTkEntry(path_row, textvariable=self.db_path_var, width=300)
        path_entry.pack(side="left", fill="x", expand=True)
        self._apply_font(path_entry)
        ctk.CTkButton(path_row, text="Wybierz", command=self._choose_existing_database).pack(side="left", padx=(8, 0))
        ctk.CTkButton(login_frame, text="Utwórz nową bazę", command=self._create_new_database).pack(pady=(0, 8))

        user = self.db.get_user()
        if user is None:
            self._show_registration_form(login_frame)
        else:
            self._show_login_form(user, login_frame)

    def _show_registration_form(self, parent):
        label = ctk.CTkLabel(parent, text="Konfiguracja hasła głównego", font=ctk.CTkFont(size=20, weight="bold"))
        label.pack(pady=(10, 10))
        self._apply_font(label, weight="bold")
        self.master_entry = ctk.CTkEntry(parent, show="*", placeholder_text="Wprowadź nowe hasło główne")
        self.master_entry.pack(pady=10, padx=40, fill="x")
        self._apply_font(self.master_entry)
        self.confirm_entry = ctk.CTkEntry(parent, show="*", placeholder_text="Powtórz hasło główne")
        self.confirm_entry.pack(pady=10, padx=40, fill="x")
        self._apply_font(self.confirm_entry)
        button = ctk.CTkButton(parent, text="Zarejestruj", command=self._register_master_password)
        button.pack(pady=20)
        self._apply_font(button)

    def _show_login_form(self, user_record, parent):
        label = ctk.CTkLabel(parent, text="Zaloguj się", font=ctk.CTkFont(size=20, weight="bold"))
        label.pack(pady=(10, 10))
        self._apply_font(label, weight="bold")
        self.master_entry = ctk.CTkEntry(parent, show="*", placeholder_text="Hasło główne")
        self.master_entry.pack(pady=10, padx=40, fill="x")
        self._apply_font(self.master_entry)
        button = ctk.CTkButton(parent, text="Zaloguj", command=lambda: self._login_master_password(user_record))
        button.pack(pady=20)
        self._apply_font(button)

    def _register_master_password(self):
        password = self.master_entry.get()
        password2 = self.confirm_entry.get()
        if not password or not password2:
            messagebox.showwarning("Błąd", "Wypełnij wszystkie pola.")
            return
        if password != password2:
            messagebox.showerror("Błąd", "Hasła nie są takie same.")
            return
        salt = CryptoManager.generate_salt()
        master_hash = CryptoManager.hash_password(password, salt)
        self.db.create_user(master_hash, base64.urlsafe_b64encode(salt).decode("utf-8"))
        messagebox.showinfo("Sukces", "Hasło główne zostało utworzone.")
        self._load_login_screen()

    def _login_master_password(self, user_record):
        password = self.master_entry.get()
        if not password:
            messagebox.showwarning("Błąd", "Wprowadź hasło główne.")
            return
        salt = base64.urlsafe_b64decode(user_record["salt"].encode("utf-8"))
        if not CryptoManager.verify_password(password, salt, user_record["master_hash"]):
            messagebox.showerror("Błąd", "Nieprawidłowe hasło główne.")
            return
        self.crypto_manager = CryptoManager(password, salt)
        self._reset_inactivity_timer()
        self._load_main_screen()

    def _load_main_screen(self):
        self.login_frame.place_forget()
        self.main_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self._clear_frame(self.main_frame)

        header = ctk.CTkLabel(self.main_frame, text="Menedżer haseł", font=ctk.CTkFont(size=22, weight="bold"))
        header.pack(pady=(15, 5))

        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(padx=15, pady=10, fill="both", expand=True)
        self.tabview.add("Konta")
        self.tabview.add("Ustawienia")
        self.tabview.set("Konta")

        self._build_accounts_tab()
        self._build_settings_tab()
        self._refresh_password_list()

    def _build_accounts_tab(self):
        tab = self.tabview.tab("Konta")
        search_frame = ctk.CTkFrame(tab, corner_radius=8)
        search_frame.pack(pady=(10, 8), padx=10, fill="x")
        label = ctk.CTkLabel(search_frame, text="Szukaj serwisu:")
        label.pack(side="left", padx=(12, 6), pady=8)
        self._apply_font(label)
        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(search_frame, textvariable=self.search_var, placeholder_text="Filtruj po serwisie...")
        search_entry.pack(side="left", padx=(0, 10), fill="x", expand=True, pady=6)
        self._apply_font(search_entry)
        self.search_var.trace_add("write", lambda *_: self._refresh_password_list())

        table_frame = ctk.CTkFrame(tab, corner_radius=8)
        table_frame.pack(padx=10, fill="both", expand=True)

        columns = ("website", "username", "modified_at")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("website", text="Serwis")
        self.tree.heading("username", text="Nazwa użytkownika")
        self.tree.heading("modified_at", text="Data modyfikacji")
        self.tree.column("website", width=260, anchor="w")
        self.tree.column("username", width=260, anchor="w")
        self.tree.column("modified_at", width=220, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        self._apply_tree_font()

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)
        self.tree.configure(yscrollcommand=scrollbar.set)

        button_frame = ctk.CTkFrame(tab, corner_radius=8)
        button_frame.pack(padx=10, pady=(0, 10), fill="x")
        ctk.CTkButton(button_frame, text="Kopiuj hasło", command=self._copy_password).pack(side="left", padx=8, pady=8)
        ctk.CTkButton(button_frame, text="Podgląd wpisu", command=self._preview_selected_password).pack(side="left", padx=8, pady=8)
        ctk.CTkButton(button_frame, text="Edytuj wpis", command=self._edit_selected_password).pack(side="left", padx=8, pady=8)
        ctk.CTkButton(button_frame, text="Dodaj nowe konto", command=self._open_password_dialog).pack(side="left", padx=8, pady=8)
        ctk.CTkButton(button_frame, text="Usuń wpis", fg_color="#C0392B", hover_color="#E74C3C", command=self._delete_selected_password).pack(side="left", padx=8, pady=8)
        ctk.CTkButton(button_frame, text="Wyloguj", fg_color="#D35400", hover_color="#E67E22", command=self._logout).pack(side="right", padx=8, pady=8)

    def _build_settings_tab(self):
        tab = self.tabview.tab("Ustawienia")
        form = ctk.CTkFrame(tab, corner_radius=8)
        form.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(form, text="Ustawienia aplikacji", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(16, 10))

        theme_var = tk.StringVar(value=self.theme_mode)
        font_var = tk.IntVar(value=self.font_size)
        clipboard_var = tk.StringVar(value=str(self.clipboard_timeout))
        inactivity_var = tk.StringVar(value=str(self.inactivity_timeout_minutes))

        self.settings_theme_var = theme_var
        self.settings_font_var = font_var
        self.settings_clipboard_var = clipboard_var
        self.settings_inactivity_var = inactivity_var

        label = ctk.CTkLabel(form, text="Motyw:")
        label.pack(anchor="w", padx=16, pady=(6, 2))
        self._apply_font(label)
        combo = ctk.CTkComboBox(form, values=["Light", "Dark", "System"], variable=theme_var, width=220)
        combo.pack(anchor="w", padx=16)
        self._apply_font(combo)

        label = ctk.CTkLabel(form, text="Rozmiar czcionki formularzy (10-18):")
        label.pack(anchor="w", padx=16, pady=(10, 2))
        self._apply_font(label)
        slider = ctk.CTkSlider(form, from_=10, to=18, number_of_steps=8, variable=font_var)
        slider.pack(anchor="w", padx=16, fill="x")

        label = ctk.CTkLabel(form, text="Czas przechowywania hasła w schowku (sekundy):")
        label.pack(anchor="w", padx=16, pady=(10, 2))
        self._apply_font(label)
        entry = ctk.CTkEntry(form, textvariable=clipboard_var)
        entry.pack(anchor="w", padx=16)
        self._apply_font(entry)

        label = ctk.CTkLabel(form, text="Blokada po bezczynności (minuty):")
        label.pack(anchor="w", padx=16, pady=(10, 2))
        self._apply_font(label)
        entry = ctk.CTkEntry(form, textvariable=inactivity_var)
        entry.pack(anchor="w", padx=16)
        self._apply_font(entry)

        buttons = ctk.CTkFrame(form)
        buttons.pack(pady=16)
        button = ctk.CTkButton(buttons, text="Zapisz ustawienia", command=self._save_settings)
        button.pack(side="left", padx=8)
        self._apply_font(button)
        button = ctk.CTkButton(buttons, text="Zmień hasło główne", command=self._change_master_password)
        button.pack(side="left", padx=8)
        self._apply_font(button)

    def _refresh_password_list(self):
        if not hasattr(self, "tree"):
            return
        self.tree.delete(*self.tree.get_children())
        all_passwords = self.db.get_passwords()
        filter_text = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        self.current_passwords = []
        for row in all_passwords:
            if filter_text and filter_text not in row["website"].lower():
                continue
            self.current_passwords.append(row)
        for row in self.current_passwords:
            self.tree.insert("", tk.END, iid=row["id"], values=(row["website"], row["username"], row["modified_at"]))

    def _copy_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Błąd", "Wybierz konto z listy.")
            return
        item_id = int(selected[0])
        for row in self.current_passwords:
            if row["id"] == item_id:
                try:
                    password = self.crypto_manager.decrypt(row["encrypted_password"])
                    pyperclip.copy(password)
                    # Timer musi wystartować PRZED modalnym messagebox,
                    # inaczej odliczanie zaczyna się dopiero po zamknięciu okna.
                    self.after(self.clipboard_timeout * 1000, self._clear_clipboard)
                    msg = f"Hasło skopiowano do schowka. Zostanie wyczyszczone po {self.clipboard_timeout} sekundach."
                    messagebox.showinfo("Sukces", msg)
                    return
                except Exception:
                    messagebox.showerror("Błąd", "Nie udało się odszyfrować hasła.")
                    return
        messagebox.showerror("Błąd", "Wybrane konto nie zostało znalezione.")

    @staticmethod
    def _clear_clipboard():
        pyperclip.copy("")

    def _logout(self):
        self.crypto_manager = None
        self._load_login_screen()

    def _choose_existing_database(self):
        """Otwiera dialog wyboru istniejącego pliku bazy danych."""
        path = filedialog.askopenfilename(
            initialdir=os.getcwd(),
            title="Otwórz istniejącą bazę haseł",
            filetypes=[("Bazy danych SQLite", "*.db"), ("Wszystkie pliki", "*.*")],
        )
        if path:
            self._switch_database(path)

    def _create_new_database(self):
        """Tworzy nowy plik bazy danych (lub otwiera już istniejący, jeśli tak wybrano)."""
        path = filedialog.asksaveasfilename(
            initialdir=os.getcwd(),
            title="Utwórz nową bazę haseł",
            defaultextension=".db",
            filetypes=[("Bazy danych SQLite", "*.db"), ("Wszystkie pliki", "*.*")],
        )
        if not path:
            return
        if not path.lower().endswith(".db"):
            path = f"{path}.db"
        directory = os.path.dirname(path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        if os.path.exists(path):
            if not messagebox.askyesno(
                "Uwaga",
                "Plik już istnieje. Czy chcesz go otworzyć zamiast tworzyć nową, pustą bazę?",
            ):
                return
        else:
            sqlite3.connect(path).close()
        self._switch_database(path)

    def _save_settings(self):
        try:
            theme = self.settings_theme_var.get()
            font_size = max(10, min(18, int(self.settings_font_var.get())))
            clipboard_timeout = max(5, int(self.settings_clipboard_var.get()))
            inactivity_timeout = max(1, int(self.settings_inactivity_var.get()))

            self.db.set_setting("theme", theme)
            self.db.set_setting("font_size", str(font_size))
            self.db.set_setting("clipboard_timeout", str(clipboard_timeout))
            self.db.set_setting("inactivity_timeout", str(inactivity_timeout))

            self.theme_mode = theme
            self.font_size = font_size
            self.clipboard_timeout = clipboard_timeout
            self.inactivity_timeout_minutes = inactivity_timeout

            self._apply_settings()
            self._apply_tree_font()
            messagebox.showinfo("Ustawienia", "Ustawienia zapisane.")
        except Exception as error:
            messagebox.showerror("Błąd", f"Nie udało się zapisać ustawień: {error}")

    def _switch_database(self, path: str):
        try:
            new_db = DatabaseManager(path)
        except Exception as error:
            messagebox.showerror("Błąd", f"Nie udało się otworzyć bazy: {error}")
            return
        if hasattr(self, "db"):
            self.db.close()
        self.db = new_db
        self.current_db_path = path
        self.db_path_var.set(path)
        self.crypto_manager = None
        self.current_passwords = []
        self._load_settings()
        self._apply_settings()
        self._load_login_screen()

    def _calculate_password_strength(self, password: str):
        if not password:
            return 0.0, "Brak"
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        if any(char.islower() for char in password):
            score += 1
        if any(char.isupper() for char in password):
            score += 1
        if any(char.isdigit() for char in password):
            score += 1
        if any(not char.isalnum() for char in password):
            score += 1
        strength = min(score / 7.0, 1.0)
        if strength < 0.35:
            level = "Bardzo słabe"
        elif strength < 0.6:
            level = "Słabe"
        elif strength < 0.8:
            level = "Średnie"
        else:
            level = "Silne"
        return strength, level

    def _update_password_strength(self, password_entry, strength_bar, strength_label=None):
        password = password_entry.get()
        strength, level = self._calculate_password_strength(password)
        try:
            strength_bar.set(strength)
            if strength < 0.35:
                strength_bar.configure(progress_color="#ff4d4d")
            elif strength < 0.6:
                strength_bar.configure(progress_color="#ffa500")
            elif strength < 0.8:
                strength_bar.configure(progress_color="#ffd54f")
            else:
                strength_bar.configure(progress_color="#4caf50")
        except Exception:
            pass
        if strength_label is not None:
            try:
                strength_label.configure(text=f"Siła hasła: {level}")
            except Exception:
                pass

    def _fill_generated_password(self, password_entry, strength_bar, length_var, uppercase_var, digits_var, special_var, strength_label=None):
        chars = string.ascii_lowercase
        required = []
        if uppercase_var.get():
            chars += string.ascii_uppercase
            required.append(string.ascii_uppercase)
        if digits_var.get():
            chars += string.digits
            required.append(string.digits)
        if special_var.get():
            chars += string.punctuation
            required.append(string.punctuation)
        if not chars:
            messagebox.showwarning("Błąd", "Wybierz co najmniej jeden typ znaków.")
            return
        # Długość nigdy nie może być mniejsza niż liczba wymaganych kategorii —
        # w przeciwnym razie nie zmieściłyby się wszystkie gwarantowane znaki.
        length = max(8, len(required), int(length_var.get()))
        password = [secrets.choice(pool) for pool in required]
        while len(password) < length:
            password.append(secrets.choice(chars))
        secrets.SystemRandom().shuffle(password)
        generated = "".join(password)
        password_entry.delete(0, tk.END)
        password_entry.insert(0, generated)
        self._update_password_strength(password_entry, strength_bar, strength_label)

    def _change_master_password(self):
        if self.crypto_manager is None:
            messagebox.showwarning("Błąd", "Najpierw zaloguj się do bazy.")
            return
        dialog = ctk.CTkToplevel(self)
        dialog.title("Zmień hasło główne")
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("420x320")

        ctk.CTkLabel(dialog, text="Zmień hasło główne", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(18, 10))
        current_entry = ctk.CTkEntry(dialog, show="*", placeholder_text="Aktualne hasło główne")
        current_entry.pack(padx=20, pady=8, fill="x")
        new_entry = ctk.CTkEntry(dialog, show="*", placeholder_text="Nowe hasło główne")
        new_entry.pack(padx=20, pady=8, fill="x")
        confirm_entry = ctk.CTkEntry(dialog, show="*", placeholder_text="Powtórz nowe hasło")
        confirm_entry.pack(padx=20, pady=8, fill="x")

        def save():
            current_pwd = current_entry.get()
            new_pwd = new_entry.get()
            confirm_pwd = confirm_entry.get()
            if not current_pwd or not new_pwd or not confirm_pwd:
                messagebox.showwarning("Błąd", "Wypełnij wszystkie pola.")
                return
            if new_pwd != confirm_pwd:
                messagebox.showerror("Błąd", "Nowe hasła nie są takie same.")
                return
            user = self.db.get_user()
            if user is None:
                messagebox.showerror("Błąd", "Brak użytkownika w bazie.")
                return
            salt = base64.urlsafe_b64decode(user["salt"].encode("utf-8"))
            if not CryptoManager.verify_password(current_pwd, salt, user["master_hash"]):
                messagebox.showerror("Błąd", "Aktualne hasło główne jest nieprawidłowe.")
                return
            new_salt = CryptoManager.generate_salt()
            new_hash = CryptoManager.hash_password(new_pwd, new_salt)
            old_crypto = self.crypto_manager
            new_crypto = CryptoManager(new_pwd, new_salt)

            # Cała operacja musi być atomowa: najpierw przygotowujemy re-szyfrowanie
            # wszystkich wpisów, potem — jednym commitem — zapisujemy nowe hasła
            # i nowy master hash. Gdyby cokolwiek zawiodło w środku,
            # ROLLBACK przywraca stan sprzed zmiany.
            connection = self.db.connection
            try:
                reencrypted = []
                for row in self.db.get_passwords():
                    plaintext = old_crypto.decrypt(row["encrypted_password"])
                    encrypted = new_crypto.encrypt(plaintext)
                    reencrypted.append((row["id"], encrypted))

                cursor = connection.cursor()
                cursor.execute("BEGIN")
                try:
                    for password_id, encrypted in reencrypted:
                        cursor.execute(
                            "UPDATE passwords SET encrypted_password = ? WHERE id = ?",
                            (encrypted, password_id),
                        )
                    cursor.execute(
                        "UPDATE users SET master_hash = ?, salt = ?",
                        (new_hash, base64.urlsafe_b64encode(new_salt).decode("utf-8")),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
            except Exception as error:
                messagebox.showerror(
                    "Błąd",
                    f"Nie udało się zmienić hasła głównego. Żadne dane nie zostały nadpisane.\n\n{error}",
                )
                return

            self.crypto_manager = new_crypto
            dialog.destroy()
            messagebox.showinfo("Sukces", "Hasło główne zostało zmienione.")

        button_row = ctk.CTkFrame(dialog)
        button_row.pack(pady=16)
        ctk.CTkButton(button_row, text="Zapisz", command=save).pack(side="left", padx=8)
        ctk.CTkButton(button_row, text="Anuluj", fg_color="#7f8c8d", hover_color="#95a5a6", command=dialog.destroy).pack(side="left", padx=8)

    def _open_password_dialog(self, entry=None):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Dodaj konto" if entry is None else "Edytuj konto")
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("560x680")
        dialog.minsize(480, 420)

        ctk.CTkLabel(
            dialog,
            text="Dodaj nowe konto" if entry is None else "Edytuj wpis",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(pady=(14, 6))

        # Cała zawartość formularza jest teraz w przewijanej ramce, żeby przy
        # dużej liczbie pól (generator hasła, notatki itd.) przyciski
        # "Zapisz" / "Anuluj" nigdy nie znikały poza widocznym obszarem okna.
        scroll_frame = ctk.CTkScrollableFrame(dialog, corner_radius=8)
        scroll_frame.pack(padx=10, pady=(0, 10), fill="both", expand=True)

        website_entry = ctk.CTkEntry(scroll_frame, placeholder_text="Serwis")
        website_entry.pack(padx=10, pady=8, fill="x")
        username_entry = ctk.CTkEntry(scroll_frame, placeholder_text="Nazwa użytkownika")
        username_entry.pack(padx=10, pady=8, fill="x")

        password_frame = ctk.CTkFrame(scroll_frame, corner_radius=8)
        password_frame.pack(padx=10, pady=8, fill="x")
        password_entry = ctk.CTkEntry(password_frame, placeholder_text="Hasło")
        password_entry.configure(show="*")
        password_entry.pack(padx=10, pady=(10, 6), fill="x")
        self._apply_font(password_entry)
        show_password = tk.BooleanVar(value=False)
        checkbox = ctk.CTkCheckBox(password_frame, text="Pokaż hasło", variable=show_password, command=lambda: password_entry.configure(show="" if show_password.get() else "*"))
        checkbox.pack(anchor="w", padx=10, pady=(0, 6))
        self._apply_font(checkbox)

        strength_label = ctk.CTkLabel(password_frame, text="Siła hasła: Brak")
        strength_label.pack(anchor="w", padx=10, pady=(4, 2))
        self._apply_font(strength_label)
        strength_bar = ctk.CTkProgressBar(password_frame, width=340)
        strength_bar.pack(padx=10, pady=(0, 8))
        password_entry.bind("<KeyRelease>", lambda *_: self._update_password_strength(password_entry, strength_bar, strength_label))
        self._update_password_strength(password_entry, strength_bar, strength_label)

        generator_frame = ctk.CTkFrame(scroll_frame, corner_radius=8)
        generator_frame.pack(padx=10, pady=8, fill="x")
        ctk.CTkLabel(generator_frame, text="Generator hasła", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(10, 6))
        length_var = tk.IntVar(value=16)
        slider = ctk.CTkSlider(generator_frame, from_=8, to=32, number_of_steps=24, variable=length_var)
        slider.pack(padx=12, pady=(2, 8), fill="x")
        length_label = ctk.CTkLabel(generator_frame, text=f"Długość: {length_var.get()}")
        length_label.pack(pady=(0, 8))
        self._apply_font(length_label)
        length_var.trace_add("write", lambda *_: length_label.configure(text=f"Długość: {length_var.get()}"))
        uppercase_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        special_var = tk.BooleanVar(value=True)
        for text, var in (("Wielkie litery", uppercase_var), ("Cyfry", digits_var), ("Znaki specjalne", special_var)):
            box = ctk.CTkCheckBox(generator_frame, text=text, variable=var)
            box.pack(anchor="w", padx=16)
            self._apply_font(box)
        ctk.CTkButton(generator_frame, text="Wygeneruj hasło", command=lambda: self._fill_generated_password(password_entry, strength_bar, length_var, uppercase_var, digits_var, special_var, strength_label)).pack(pady=10)

        notes_frame = ctk.CTkFrame(scroll_frame, corner_radius=8)
        notes_frame.pack(padx=10, pady=(8, 8), fill="x")
        ctk.CTkLabel(notes_frame, text="Notatki:").pack(anchor="w", padx=10, pady=(8, 2))
        notes_box = ctk.CTkTextbox(notes_frame, height=120)
        notes_box.pack(padx=10, pady=(0, 10), fill="both")

        if entry is not None:
            website_entry.insert(0, entry["website"])
            username_entry.insert(0, entry["username"])
            try:
                password_entry.insert(0, self.crypto_manager.decrypt(entry["encrypted_password"]))
                self._update_password_strength(password_entry, strength_bar, strength_label)
            except Exception:
                password_entry.insert(0, "")
            notes_box.insert("0.0", entry["notes"])
            ctk.CTkLabel(scroll_frame, text=f"Data modyfikacji: {entry['modified_at']}", font=ctk.CTkFont(size=12)).pack(pady=(4, 6))

        def save_entry():
            website = website_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            notes = notes_box.get("0.0", tk.END).strip()
            if not website or not username or not password:
                messagebox.showwarning("Błąd", "Wypełnij wszystkie pola.")
                return
            try:
                encrypted = self.crypto_manager.encrypt(password)
                modified_at = datetime.now().strftime("%Y-%m-%d %H:%M")
                if entry is None:
                    self.db.add_password(website, username, encrypted, notes, modified_at)
                else:
                    self.db.update_password(entry["id"], website, username, encrypted, notes, modified_at)
                dialog.destroy()
                self._refresh_password_list()
                messagebox.showinfo("Sukces", "Wpis został zapisany.")
            except Exception as error:
                messagebox.showerror("Błąd", f"Nie można zapisać wpisu: {error}")

        # Przyciski "Zapisz" i "Anuluj" są przypięte na stałe pod przewijaną
        # zawartością, poza scroll_frame — dzięki temu zawsze są widoczne,
        # niezależnie od tego, ile miejsca zajmuje reszta formularza.
        button_frame = ctk.CTkFrame(dialog)
        button_frame.pack(pady=(4, 14))
        save_button = ctk.CTkButton(button_frame, text="Zapisz", width=140, command=save_entry)
        save_button.pack(side="left", padx=8)
        self._apply_font(save_button)
        cancel_button = ctk.CTkButton(
            button_frame,
            text="Anuluj",
            width=140,
            fg_color="#7f8c8d",
            hover_color="#95a5a6",
            command=dialog.destroy,
        )
        cancel_button.pack(side="left", padx=8)
        self._apply_font(cancel_button)

    def _preview_selected_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Błąd", "Wybierz wpis do podglądu.")
            return
        item_id = int(selected[0])
        for row in self.current_passwords:
            if row["id"] == item_id:
                self._open_preview_dialog(row)
                return

    def _open_preview_dialog(self, entry):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Podgląd wpisu")
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("480x520")

        ctk.CTkLabel(dialog, text="Podgląd wpisu", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(16, 10))

        website_entry = ctk.CTkEntry(dialog, placeholder_text="Serwis")
        website_entry.insert(0, entry["website"])
        website_entry.configure(state="disabled")
        website_entry.pack(padx=20, pady=8, fill="x")

        username_entry = ctk.CTkEntry(dialog, placeholder_text="Nazwa użytkownika")
        username_entry.insert(0, entry["username"])
        username_entry.configure(state="disabled")
        username_entry.pack(padx=20, pady=8, fill="x")

        password_entry = ctk.CTkEntry(dialog, placeholder_text="Hasło")
        try:
            password_entry.insert(0, self.crypto_manager.decrypt(entry["encrypted_password"]))
        except Exception:
            password_entry.insert(0, "")
        password_entry.configure(state="disabled")
        password_entry.pack(padx=20, pady=8, fill="x")

        notes_frame = ctk.CTkFrame(dialog, corner_radius=8)
        notes_frame.pack(padx=20, pady=8, fill="both", expand=True)
        ctk.CTkLabel(notes_frame, text="Notatki:").pack(anchor="w", padx=10, pady=(8, 2))
        notes_box = ctk.CTkTextbox(notes_frame, height=140)
        notes_box.insert("0.0", entry["notes"])
        notes_box.configure(state="disabled")
        notes_box.pack(padx=10, pady=(0, 10), fill="both", expand=True)

        ctk.CTkLabel(dialog, text=f"Data modyfikacji: {entry['modified_at']}", font=ctk.CTkFont(size=12)).pack(pady=(4, 0))
        ctk.CTkButton(dialog, text="Zamknij", command=dialog.destroy).pack(pady=10)

    def _edit_selected_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Błąd", "Wybierz wpis do edycji.")
            return
        item_id = int(selected[0])
        for row in self.current_passwords:
            if row["id"] == item_id:
                self._open_password_dialog(row)
                return

    def _delete_selected_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Błąd", "Wybierz wpis do usunięcia.")
            return
        item_id = int(selected[0])
        target = None
        for row in self.current_passwords:
            if row["id"] == item_id:
                target = row
                break
        if target is None:
            messagebox.showerror("Błąd", "Wybrany wpis nie został znaleziony.")
            return
        if not messagebox.askyesno(
            "Potwierdzenie",
            f"Czy na pewno usunąć wpis dla „{target['website']}” ({target['username']})?",
        ):
            return
        try:
            self.db.delete_password(item_id)
        except Exception as error:
            messagebox.showerror("Błąd", f"Nie udało się usunąć wpisu: {error}")
            return
        self._refresh_password_list()

    def run(self):
        self.mainloop()

    def destroy(self):
        if hasattr(self, "db"):
            self.db.close()
        super().destroy()


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.run()