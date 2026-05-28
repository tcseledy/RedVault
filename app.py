#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import secrets
import sqlite3
import string
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request, session, send_from_directory

APP_DIR = Path.home() / ".secure_password_vault"
DB_PATH = APP_DIR / "vault.db"
FRONTEND_DIR = Path(__file__).parent

ARGON_TIME_COST = 3
ARGON_MEMORY_COST_KIB = 131_072
ARGON_PARALLELISM = 4
ARGON_HASH_LEN = 32
ARGON_SALT_LEN = 16
NONCE_LEN = 12

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
ACTIVE_VAULT_KEYS: dict[str, bytes] = {}


@dataclass
class Entry:
    service: str
    username: str
    password: str
    notes: str = ""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def connect() -> sqlite3.Connection:
    APP_DIR.mkdir(mode=0o700, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            kdf_salt TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service TEXT NOT NULL COLLATE NOCASE,
            username TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(user_id, service),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    conn.commit()


def password_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST_KIB,
        parallelism=ARGON_PARALLELISM,
        hash_len=ARGON_HASH_LEN,
        salt_len=ARGON_SALT_LEN,
        type=Type.ID,
    )


def derive_key(master_password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST_KIB,
        parallelism=ARGON_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_entry(key: bytes, entry: Entry) -> tuple[str, str]:
    nonce = secrets.token_bytes(NONCE_LEN)
    plaintext = json.dumps(entry.__dict__, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, entry.service.encode("utf-8"))
    return b64e(nonce), b64e(ciphertext)


def decrypt_entry(key: bytes, row: sqlite3.Row) -> Entry:
    plaintext = AESGCM(key).decrypt(
        b64d(row["nonce"]),
        b64d(row["ciphertext"]),
        row["service"].encode("utf-8"),
    )
    return Entry(**json.loads(plaintext.decode("utf-8")))


def start_user_session(user_id: int, username: str, key: bytes) -> None:
    end_user_session()
    token = secrets.token_urlsafe(32)
    ACTIVE_VAULT_KEYS[token] = key
    session["login_token"] = token
    session["user_id"] = user_id
    session["username"] = username


def end_user_session() -> None:
    token = session.get("login_token")
    if token:
        ACTIVE_VAULT_KEYS.pop(token, None)
    session.clear()


def require_user() -> tuple[int, bytes] | None:
    user_id = session.get("user_id")
    token = session.get("login_token")
    key = ACTIVE_VAULT_KEYS.get(token) if token else None
    if not user_id or key is None:
        return None
    return user_id, key


def generate_password(length: int = 24) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/"
    while True:
        password = "".join(secrets.choice(chars) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in password)
        ):
            return password


@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/vault")
def vault_page():
    return send_from_directory(FRONTEND_DIR, "user.html")


@app.route("/api/status", methods=["GET"])
def status():
    conn = connect()
    init_schema(conn)
    logged_in = require_user() is not None
    return jsonify(
        {
            "loggedIn": logged_in,
            "username": session.get("username") if logged_in else None,
        }
    )


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if len(username) < 3 or len(username) > 64 or any(char.isspace() for char in username):
        return jsonify({"error": "Username must be 3 to 64 characters with no spaces."}), 400
    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters."}), 400

    conn = connect()
    init_schema(conn)
    if conn.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone():
        return jsonify({"error": "That username is already registered."}), 409

    salt = secrets.token_bytes(ARGON_SALT_LEN)
    now = int(time.time())
    try:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, kdf_salt, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hasher().hash(password), b64e(salt), now),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "That username is already registered."}), 409

    start_user_session(cursor.lastrowid, username, derive_key(password, salt))
    return jsonify({"ok": True, "username": username}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")

    conn = connect()
    init_schema(conn)
    user = conn.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    if user is None:
        return jsonify({"error": "Incorrect username or password."}), 401

    try:
        password_hasher().verify(user["password_hash"], password)
    except (VerifyMismatchError, VerificationError):
        return jsonify({"error": "Incorrect username or password."}), 401

    key = derive_key(password, b64d(user["kdf_salt"]))
    start_user_session(user["id"], user["username"], key)
    return jsonify({"ok": True, "username": user["username"]})


@app.route("/api/lock", methods=["POST"])
def lock():
    end_user_session()
    return jsonify({"ok": True})


@app.route("/api/logout", methods=["POST"])
def logout():
    end_user_session()
    return jsonify({"ok": True})


@app.route("/api/generate", methods=["GET"])
def api_generate():
    length = int(request.args.get("length", 24))
    length = max(12, min(length, 64))
    return jsonify({"password": generate_password(length)})


@app.route("/api/entries", methods=["GET"])
def list_entries():
    user = require_user()
    if user is None:
        return jsonify({"error": "Please log in."}), 401
    user_id, key = user

    conn = connect()
    init_schema(conn)
    rows = conn.execute(
        "SELECT * FROM user_entries WHERE user_id = ? ORDER BY service ASC",
        (user_id,),
    ).fetchall()
    entries = []
    for row in rows:
        try:
            entry = decrypt_entry(key, row)
            entries.append({"service": entry.service, "username": entry.username, "notes": entry.notes})
        except InvalidTag:
            return jsonify({"error": "Could not decrypt vault."}), 500
    return jsonify(entries)


@app.route("/api/entries", methods=["POST"])
def save_entry():
    user = require_user()
    if user is None:
        return jsonify({"error": "Please log in."}), 401
    user_id, key = user

    data = request.get_json(force=True)
    service = data.get("service", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    notes = data.get("notes", "").strip()

    if not service or not username or not password:
        return jsonify({"error": "Service, username, and password are required."}), 400

    conn = connect()
    init_schema(conn)
    entry = Entry(service=service, username=username, password=password, notes=notes)
    nonce, ciphertext = encrypt_entry(key, entry)
    now = int(time.time())

    conn.execute(
        """
        INSERT INTO user_entries (user_id, service, username, nonce, ciphertext, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, service) DO UPDATE SET
            username = excluded.username,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            updated_at = excluded.updated_at
        """,
        (user_id, service, username, nonce, ciphertext, now, now),
    )
    conn.commit()
    return jsonify({"ok": True})


@app.route("/api/entries/<service>/password", methods=["GET"])
def get_password(service: str):
    user = require_user()
    if user is None:
        return jsonify({"error": "Please log in."}), 401
    user_id, key = user

    conn = connect()
    row = conn.execute(
        "SELECT * FROM user_entries WHERE user_id = ? AND service = ? COLLATE NOCASE",
        (user_id, service),
    ).fetchone()
    if row is None:
        return jsonify({"error": "Entry not found."}), 404

    try:
        entry = decrypt_entry(key, row)
    except InvalidTag:
        return jsonify({"error": "Could not decrypt entry."}), 500

    return jsonify({"password": entry.password})


@app.route("/api/entries/<service>", methods=["DELETE"])
def delete_entry(service: str):
    user = require_user()
    if user is None:
        return jsonify({"error": "Please log in."}), 401
    user_id, _ = user

    conn = connect()
    conn.execute(
        "DELETE FROM user_entries WHERE user_id = ? AND service = ? COLLATE NOCASE",
        (user_id, service),
    )
    conn.commit()
    return jsonify({"ok": True})


class DesktopVaultApp:
    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.root = tk.Tk()
        self.root.title("Theo Password Manager")
        self.root.geometry("980x680")
        self.root.minsize(860, 580)

        self.user_id: int | None = None
        self.username = ""
        self.key: bytes | None = None
        self.entries: list[Entry] = []
        self.visible_password = False

        self.status_var = tk.StringVar(value="Log in or create a vault to begin.")
        self.search_var = tk.StringVar()
        self.service_var = tk.StringVar()
        self.entry_username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.notes_text = None
        self.selected_service: str | None = None

        self.build_login()

    def clear_root(self) -> None:
        for child in self.root.winfo_children():
            child.destroy()

    def set_status(self, message: str) -> None:
        self.status_var.set(message)

    def build_login(self) -> None:
        tk = self.tk
        ttk = self.ttk
        self.clear_root()
        frame = ttk.Frame(self.root, padding=34)
        frame.pack(fill="both", expand=True)
        card = ttk.Frame(frame, padding=28)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(card, text="Theo Password Manager", font=("Helvetica", 24, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Label(card, text="Secure local password vault", font=("Helvetica", 13)).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 24))

        ttk.Label(card, text="Username").grid(row=2, column=0, sticky="w")
        username = ttk.Entry(card, width=36)
        username.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 12))

        ttk.Label(card, text="Master password").grid(row=4, column=0, sticky="w")
        password = ttk.Entry(card, width=36, show="*")
        password.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(4, 16))

        ttk.Button(card, text="Log In", command=lambda: self.login(username.get(), password.get())).grid(row=6, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(card, text="Create Account", command=lambda: self.register(username.get(), password.get())).grid(row=6, column=1, sticky="ew")
        ttk.Label(card, textvariable=self.status_var, wraplength=420).grid(row=7, column=0, columnspan=2, sticky="w", pady=(16, 0))
        username.focus_set()
        self.root.bind("<Return>", lambda _event: self.login(username.get(), password.get()))

    def register(self, username: str, password: str) -> None:
        username = username.strip()
        if len(username) < 3 or len(username) > 64 or any(char.isspace() for char in username):
            self.set_status("Username must be 3 to 64 characters with no spaces.")
            return
        if len(password) < 12:
            self.set_status("Password must be at least 12 characters.")
            return

        conn = connect()
        init_schema(conn)
        if conn.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone():
            self.set_status("That username is already registered.")
            return

        salt = secrets.token_bytes(ARGON_SALT_LEN)
        now = int(time.time())
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, kdf_salt, created_at) VALUES (?, ?, ?, ?)",
                (username, password_hasher().hash(password), b64e(salt), now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            self.set_status("That username is already registered.")
            return

        self.user_id = cursor.lastrowid
        self.username = username
        self.key = derive_key(password, salt)
        self.build_vault()

    def login(self, username: str, password: str) -> None:
        username = username.strip()
        conn = connect()
        init_schema(conn)
        user = conn.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
        if user is None:
            self.set_status("Incorrect username or password.")
            return
        try:
            password_hasher().verify(user["password_hash"], password)
        except (VerifyMismatchError, VerificationError):
            self.set_status("Incorrect username or password.")
            return

        self.user_id = user["id"]
        self.username = user["username"]
        self.key = derive_key(password, b64d(user["kdf_salt"]))
        self.build_vault()

    def build_vault(self) -> None:
        tk = self.tk
        ttk = self.ttk
        self.clear_root()
        self.root.bind("<Return>", lambda _event: None)

        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 14))
        ttk.Label(header, text="Secure Password Vault", font=("Helvetica", 22, "bold")).pack(side="left")
        ttk.Label(header, text=f"Signed in: {self.username}").pack(side="left", padx=(18, 0))
        ttk.Button(header, text="Log Out", command=self.logout).pack(side="right")

        body = ttk.PanedWindow(outer, orient="horizontal")
        body.pack(fill="both", expand=True)

        left = ttk.Frame(body, padding=(0, 0, 12, 0))
        right = ttk.Frame(body, padding=(12, 0, 0, 0))
        body.add(left, weight=1)
        body.add(right, weight=2)

        ttk.Label(left, text="Search").pack(anchor="w")
        search = ttk.Entry(left, textvariable=self.search_var)
        search.pack(fill="x", pady=(4, 10))
        search.bind("<KeyRelease>", lambda _event: self.render_entry_list())

        self.entry_list = tk.Listbox(left, height=24)
        self.entry_list.pack(fill="both", expand=True)
        self.entry_list.bind("<<ListboxSelect>>", lambda _event: self.select_entry())
        ttk.Button(left, text="Refresh", command=self.load_entries).pack(fill="x", pady=(10, 0))

        ttk.Label(right, text="Add or Update Password", font=("Helvetica", 16, "bold")).pack(anchor="w")
        form = ttk.Frame(right)
        form.pack(fill="x", pady=(12, 0))

        ttk.Label(form, text="Website or Service").grid(row=0, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.service_var).grid(row=1, column=0, sticky="ew", pady=(4, 10))
        ttk.Label(form, text="Username or Email").grid(row=2, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.entry_username_var).grid(row=3, column=0, sticky="ew", pady=(4, 10))
        ttk.Label(form, text="Password").grid(row=4, column=0, sticky="w")
        self.password_entry = ttk.Entry(form, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=5, column=0, sticky="ew", pady=(4, 10))
        ttk.Label(form, text="Notes").grid(row=6, column=0, sticky="w")
        self.notes_text = tk.Text(form, height=4, wrap="word")
        self.notes_text.grid(row=7, column=0, sticky="ew", pady=(4, 12))
        form.columnconfigure(0, weight=1)

        buttons = ttk.Frame(right)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Save Password", command=self.save_current_entry).pack(side="left")
        ttk.Button(buttons, text="Generate", command=self.generate_into_field).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Reveal/Hide", command=self.toggle_visible_password).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Copy Password", command=self.copy_current_password).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Delete", command=self.delete_current_entry).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="New Blank Entry", command=self.clear_form).pack(side="left", padx=(8, 0))

        ttk.Label(right, textvariable=self.status_var, wraplength=560).pack(anchor="w", pady=(18, 0))
        self.load_entries()

    def logout(self) -> None:
        self.user_id = None
        self.username = ""
        self.key = None
        self.entries = []
        self.clear_form()
        self.set_status("Logged out.")
        self.build_login()

    def load_entries(self) -> None:
        if self.user_id is None or self.key is None:
            return
        conn = connect()
        init_schema(conn)
        rows = conn.execute(
            "SELECT * FROM user_entries WHERE user_id = ? ORDER BY service ASC",
            (self.user_id,),
        ).fetchall()
        entries: list[Entry] = []
        for row in rows:
            try:
                entries.append(decrypt_entry(self.key, row))
            except InvalidTag:
                self.set_status("Could not decrypt one or more vault entries.")
        self.entries = entries
        self.render_entry_list()

    def render_entry_list(self) -> None:
        term = self.search_var.get().strip().lower()
        self.filtered_entries = [
            entry for entry in self.entries
            if term in entry.service.lower() or term in entry.username.lower()
        ]
        self.entry_list.delete(0, self.tk.END)
        for entry in self.filtered_entries:
            self.entry_list.insert(self.tk.END, f"{entry.service}  |  {entry.username}")
        self.set_status(f"{len(self.filtered_entries)} saved password{'s' if len(self.filtered_entries) != 1 else ''} shown.")

    def select_entry(self) -> None:
        selection = self.entry_list.curselection()
        if not selection:
            return
        entry = self.filtered_entries[selection[0]]
        self.selected_service = entry.service
        self.service_var.set(entry.service)
        self.entry_username_var.set(entry.username)
        self.password_var.set(entry.password)
        self.visible_password = False
        self.password_entry.configure(show="*")
        self.notes_text.delete("1.0", self.tk.END)
        self.notes_text.insert("1.0", entry.notes)

    def clear_form(self) -> None:
        self.selected_service = None
        self.service_var.set("")
        self.entry_username_var.set("")
        self.password_var.set("")
        self.visible_password = False
        if hasattr(self, "password_entry"):
            self.password_entry.configure(show="*")
        if self.notes_text is not None:
            self.notes_text.delete("1.0", self.tk.END)

    def save_current_entry(self) -> None:
        if self.user_id is None or self.key is None:
            return
        service = self.service_var.get().strip()
        username = self.entry_username_var.get().strip()
        password = self.password_var.get()
        notes = self.notes_text.get("1.0", self.tk.END).strip() if self.notes_text else ""
        if not service or not username or not password:
            self.set_status("Service, username, and password are required.")
            return
        conn = connect()
        init_schema(conn)
        entry = Entry(service=service, username=username, password=password, notes=notes)
        nonce, ciphertext = encrypt_entry(self.key, entry)
        now = int(time.time())
        conn.execute(
            """
            INSERT INTO user_entries (user_id, service, username, nonce, ciphertext, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, service) DO UPDATE SET
                username = excluded.username,
                nonce = excluded.nonce,
                ciphertext = excluded.ciphertext,
                updated_at = excluded.updated_at
            """,
            (self.user_id, service, username, nonce, ciphertext, now, now),
        )
        conn.commit()
        self.set_status(f"{service} saved to your vault.")
        self.load_entries()

    def generate_into_field(self) -> None:
        self.password_var.set(generate_password(24))
        self.visible_password = True
        self.password_entry.configure(show="")
        self.set_status("Generated a strong password.")

    def toggle_visible_password(self) -> None:
        self.visible_password = not self.visible_password
        self.password_entry.configure(show="" if self.visible_password else "*")

    def copy_current_password(self) -> None:
        password = self.password_var.get()
        if not password:
            self.set_status("No password to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.set_status("Password copied to clipboard.")

    def delete_current_entry(self) -> None:
        from tkinter import messagebox
        if self.user_id is None:
            return
        service = self.service_var.get().strip()
        if not service:
            self.set_status("Select an entry to delete.")
            return
        if not messagebox.askyesno("Delete password", f"Delete {service} from your vault?"):
            return
        conn = connect()
        conn.execute(
            "DELETE FROM user_entries WHERE user_id = ? AND service = ? COLLATE NOCASE",
            (self.user_id, service),
        )
        conn.commit()
        self.clear_form()
        self.load_entries()
        self.set_status(f"{service} deleted.")

    def run(self) -> None:
        self.root.mainloop()


def run_server() -> None:
    app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False)


if __name__ == "__main__":
    if "--web" in sys.argv or os.environ.get("THEO_PASSWORD_MANAGER_WEB") == "1":
        run_server()
    else:
        DesktopVaultApp().run()
