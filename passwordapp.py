#!/usr/bin/env python3
"""
Secure local password vault using Argon2id + AES-GCM.

Features:
- Argon2id master-password hashing
- Separate Argon2id key derivation salt for vault encryption
- AES-256-GCM authenticated encryption
- SQLite storage
- Password generator
- Clipboard copy with auto-clear
- Add, get, list, search, delete entries
- Change master password and re-encrypt vault

Install:
    python3 -m pip install argon2-cffi cryptography pyperclip

Run:
    python3 secure_password_vault.py init
    python3 secure_password_vault.py add gmail
    python3 secure_password_vault.py get gmail
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import secrets
import sqlite3
import string
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pyperclip
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_DIR = Path.home() / ".secure_password_vault"
DB_PATH = APP_DIR / "vault.db"

# Argon2id parameters. These are intentionally strong for a local vault.
# Increase memory_cost if your machine handles it well.
ARGON_TIME_COST = 3
ARGON_MEMORY_COST_KIB = 131_072  # 128 MiB
ARGON_PARALLELISM = 4
ARGON_HASH_LEN = 32
ARGON_SALT_LEN = 16

NONCE_LEN = 12  # AES-GCM standard nonce length


@dataclass
class Entry:
    service: str
    username: str
    password: str
    notes: str


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


def vault_exists(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT 1 FROM vault_meta WHERE id = 1").fetchone()
    return row is not None


def get_meta(conn: sqlite3.Connection) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()
    if row is None:
        raise SystemExit("Vault is not initialized. Run: python3 secure_password_vault.py init")
    return row


def make_password_hasher() -> PasswordHasher:
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


def verify_master_password(conn: sqlite3.Connection) -> tuple[str, bytes]:
    meta = get_meta(conn)
    password = getpass.getpass("Master password: ")
    ph = make_password_hasher()
    try:
        ph.verify(meta["password_hash"], password)
    except VerifyMismatchError:
        raise SystemExit("Incorrect master password.")
    except VerificationError as exc:
        raise SystemExit(f"Could not verify master password: {exc}")

    if ph.check_needs_rehash(meta["password_hash"]):
        new_hash = ph.hash(password)
        conn.execute("UPDATE vault_meta SET password_hash = ? WHERE id = 1", (new_hash,))
        conn.commit()

    key = derive_key(password, b64d(meta["kdf_salt"]))
    return password, key


def encrypt_entry(key: bytes, entry: Entry) -> tuple[str, str]:
    nonce = secrets.token_bytes(NONCE_LEN)
    plaintext = json.dumps(entry.__dict__, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=entry.service.encode("utf-8"))
    return b64e(nonce), b64e(ciphertext)


def decrypt_entry(key: bytes, row: sqlite3.Row) -> Entry:
    try:
        plaintext = AESGCM(key).decrypt(
            b64d(row["nonce"]),
            b64d(row["ciphertext"]),
            associated_data=row["service"].encode("utf-8"),
        )
        data = json.loads(plaintext.decode("utf-8"))
        return Entry(**data)
    except (InvalidTag, json.JSONDecodeError, TypeError) as exc:
        raise SystemExit(f"Could not decrypt entry '{row['service']}'. Wrong key or corrupted vault. {exc}")


def prompt_new_master_password() -> str:
    while True:
        pw1 = getpass.getpass("Create master password: ")
        pw2 = getpass.getpass("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match. Try again.")
            continue
        if len(pw1) < 12:
            print("Use at least 12 characters.")
            continue
        return pw1


def cmd_init(_: argparse.Namespace) -> None:
    conn = connect()
    init_schema(conn)
    if vault_exists(conn):
        raise SystemExit("Vault already exists.")

    master = prompt_new_master_password()
    ph = make_password_hasher()
    password_hash = ph.hash(master)
    kdf_salt = secrets.token_bytes(ARGON_SALT_LEN)
    now = int(time.time())

    conn.execute(
        "INSERT INTO vault_meta (id, password_hash, kdf_salt, created_at) VALUES (1, ?, ?, ?)",
        (password_hash, b64e(kdf_salt), now),
    )
    conn.commit()
    print(f"Vault created at {DB_PATH}")


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in pw)
        ):
            return pw


def cmd_generate(args: argparse.Namespace) -> None:
    print(generate_password(args.length))


def cmd_add(args: argparse.Namespace) -> None:
    conn = connect()
    init_schema(conn)
    _, key = verify_master_password(conn)

    service = args.service.strip()
    username = input("Username/email: ").strip()
    use_generated = input("Generate strong password? [Y/n]: ").strip().lower() != "n"
    password = generate_password(args.length) if use_generated else getpass.getpass("Password to store: ")
    notes = input("Notes optional: ").strip()

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
    print(f"Saved entry for {service}.")
    if use_generated:
        print("Generated password copied to clipboard for 30 seconds.")
        copy_to_clipboard(password, clear_after=30)


def copy_to_clipboard(value: str, clear_after: int = 30) -> None:
    pyperclip.copy(value)

    def clear_later() -> None:
        time.sleep(clear_after)
        try:
            if pyperclip.paste() == value:
                pyperclip.copy("")
        except Exception:
            pass

    threading.Thread(target=clear_later, daemon=True).start()


def cmd_get(args: argparse.Namespace) -> None:
    conn = connect()
    init_schema(conn)
    _, key = verify_master_password(conn)

    row = conn.execute("SELECT * FROM vault_entries WHERE service = ? COLLATE NOCASE", (args.service,)).fetchone()
    if row is None:
        raise SystemExit("No matching entry found.")

    entry = decrypt_entry(key, row)
    print(f"Service:  {entry.service}")
    print(f"Username: {entry.username}")
    if entry.notes:
        print(f"Notes:    {entry.notes}")

    if args.show:
        print(f"Password: {entry.password}")
    else:
        copy_to_clipboard(entry.password, clear_after=args.clear_after)
        print(f"Password copied to clipboard for {args.clear_after} seconds. Use --show to print it instead.")


def cmd_list(args: argparse.Namespace) -> None:
    conn = connect()
    init_schema(conn)
    get_meta(conn)  # confirms initialized
    query = f"%{args.search.lower()}%" if args.search else "%"
    rows = conn.execute(
        """
        SELECT service, username, updated_at
        FROM vault_entries
        WHERE lower(service) LIKE ? OR lower(username) LIKE ?
        ORDER BY service ASC
        """,
        (query, query),
    ).fetchall()

    if not rows:
        print("No entries found.")
        return

    for row in rows:
        print(f"{row['service']}  |  {row['username']}")


def cmd_delete(args: argparse.Namespace) -> None:
    conn = connect()
    init_schema(conn)
    verify_master_password(conn)
    row = conn.execute("SELECT service FROM vault_entries WHERE service = ? COLLATE NOCASE", (args.service,)).fetchone()
    if row is None:
        raise SystemExit("No matching entry found.")
    confirm = input(f"Delete '{args.service}'? Type DELETE to confirm: ")
    if confirm != "DELETE":
        raise SystemExit("Cancelled.")
    conn.execute("DELETE FROM vault_entries WHERE service = ? COLLATE NOCASE", (args.service,))
    conn.commit()
    print("Deleted.")


def cmd_change_master(_: argparse.Namespace) -> None:
    conn = connect()
    init_schema(conn)
    _, old_key = verify_master_password(conn)

    rows = conn.execute("SELECT * FROM vault_entries ORDER BY service ASC").fetchall()
    entries = [decrypt_entry(old_key, row) for row in rows]

    new_master = prompt_new_master_password()
    new_salt = secrets.token_bytes(ARGON_SALT_LEN)
    new_key = derive_key(new_master, new_salt)
    ph = make_password_hasher()
    new_hash = ph.hash(new_master)

    with conn:
        conn.execute(
            "UPDATE vault_meta SET password_hash = ?, kdf_salt = ? WHERE id = 1",
            (new_hash, b64e(new_salt)),
        )
        for entry in entries:
            nonce, ciphertext = encrypt_entry(new_key, entry)
            now = int(time.time())
            conn.execute(
                "UPDATE vault_entries SET nonce = ?, ciphertext = ?, updated_at = ? WHERE service = ? COLLATE NOCASE",
                (nonce, ciphertext, now, entry.service),
            )
    print("Master password changed and vault re-encrypted.")


def cmd_export(args: argparse.Namespace) -> None:
    conn = connect()
    init_schema(conn)
    _, key = verify_master_password(conn)
    rows = conn.execute("SELECT * FROM vault_entries ORDER BY service ASC").fetchall()
    entries = [decrypt_entry(key, row).__dict__ for row in rows]
    output = json.dumps(entries, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Exported decrypted vault to {args.output}. Protect this file carefully.")
    else:
        print(output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure local password vault")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("init", help="Create a new vault")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("generate", help="Generate a strong password")
    p.add_argument("--length", type=int, default=24)
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("add", help="Add or update a password entry")
    p.add_argument("service", help="Service name, for example gmail")
    p.add_argument("--length", type=int, default=24, help="Generated password length")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("get", help="Retrieve a password entry")
    p.add_argument("service")
    p.add_argument("--show", action="store_true", help="Print password instead of copying to clipboard")
    p.add_argument("--clear-after", type=int, default=30, help="Seconds before clipboard clear")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("list", help="List saved services")
    p.add_argument("--search", default="", help="Search service or username")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("delete", help="Delete a password entry")
    p.add_argument("service")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("change-master", help="Change master password and re-encrypt vault")
    p.set_defaults(func=cmd_change_master)

    p = sub.add_parser("export", help="Export decrypted vault as JSON")
    p.add_argument("--output", help="File to write decrypted export to")
    p.set_defaults(func=cmd_export)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)


if __name__ == "__main__":
    main()

