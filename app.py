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
        CREATE TABLE IF NOT EXISTS vault_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            kdf_salt TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL UNIQUE COLLATE NOCASE,
            username TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
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


def get_meta(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()


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


def require_key() -> bytes | None:
    key_b64 = session.get("vault_key")
    if not key_b64:
        return None
    return b64d(key_b64)


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


@app.route("/api/status", methods=["GET"])
def status():
    conn = connect()
    init_schema(conn)
    initialized = get_meta(conn) is not None
    return jsonify({"initialized": initialized, "unlocked": "vault_key" in session})


@app.route("/api/init", methods=["POST"])
def init_vault():
    data = request.get_json(force=True)
    master_password = data.get("masterPassword", "")

    if len(master_password) < 12:
        return jsonify({"error": "Master password must be at least 12 characters."}), 400

    conn = connect()
    init_schema(conn)
    if get_meta(conn) is not None:
        return jsonify({"error": "Vault already initialized."}), 409

    salt = secrets.token_bytes(ARGON_SALT_LEN)
    ph = password_hasher()
    password_hash = ph.hash(master_password)
    now = int(time.time())

    conn.execute(
        "INSERT INTO vault_meta (id, password_hash, kdf_salt, created_at) VALUES (1, ?, ?, ?)",
        (password_hash, b64e(salt), now),
    )
    conn.commit()

    key = derive_key(master_password, salt)
    session["vault_key"] = b64e(key)
    return jsonify({"ok": True})


@app.route("/api/unlock", methods=["POST"])
def unlock():
    data = request.get_json(force=True)
    master_password = data.get("masterPassword", "")

    conn = connect()
    init_schema(conn)
    meta = get_meta(conn)
    if meta is None:
        return jsonify({"error": "Vault not initialized."}), 404

    ph = password_hasher()
    try:
        ph.verify(meta["password_hash"], master_password)
    except (VerifyMismatchError, VerificationError):
        return jsonify({"error": "Incorrect master password."}), 401

    key = derive_key(master_password, b64d(meta["kdf_salt"]))
    session["vault_key"] = b64e(key)
    return jsonify({"ok": True})


@app.route("/api/lock", methods=["POST"])
def lock():
    session.pop("vault_key", None)
    return jsonify({"ok": True})


@app.route("/api/generate", methods=["GET"])
def api_generate():
    length = int(request.args.get("length", 24))
    length = max(12, min(length, 64))
    return jsonify({"password": generate_password(length)})


@app.route("/api/entries", methods=["GET"])
def list_entries():
    key = require_key()
    if key is None:
        return jsonify({"error": "Vault locked."}), 401

    conn = connect()
    init_schema(conn)
    rows = conn.execute("SELECT * FROM vault_entries ORDER BY service ASC").fetchall()
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
    key = require_key()
    if key is None:
        return jsonify({"error": "Vault locked."}), 401

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
        INSERT INTO vault_entries (service, username, nonce, ciphertext, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(service) DO UPDATE SET
            username = excluded.username,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            updated_at = excluded.updated_at
        """,
        (service, username, nonce, ciphertext, now, now),
    )
    conn.commit()
    return jsonify({"ok": True})


@app.route("/api/entries/<service>/password", methods=["GET"])
def get_password(service: str):
    key = require_key()
    if key is None:
        return jsonify({"error": "Vault locked."}), 401

    conn = connect()
    row = conn.execute("SELECT * FROM vault_entries WHERE service = ? COLLATE NOCASE", (service,)).fetchone()
    if row is None:
        return jsonify({"error": "Entry not found."}), 404

    try:
        entry = decrypt_entry(key, row)
    except InvalidTag:
        return jsonify({"error": "Could not decrypt entry."}), 500

    return jsonify({"password": entry.password})


@app.route("/api/entries/<service>", methods=["DELETE"])
def delete_entry(service: str):
    key = require_key()
    if key is None:
        return jsonify({"error": "Vault locked."}), 401

    conn = connect()
    conn.execute("DELETE FROM vault_entries WHERE service = ? COLLATE NOCASE", (service,))
    conn.commit()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)

