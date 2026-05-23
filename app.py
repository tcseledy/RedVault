#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import secrets
import sqlite3
import string
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)
