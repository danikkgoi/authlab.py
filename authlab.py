import argparse
import getpass
import hashlib
import hmac
import secrets
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).with_name("authlab.db")

PBKDF2_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 8

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    iterations    INTEGER NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('student', 'teacher'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS prelogins (
    token_hash TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS login_failures (
    username     TEXT PRIMARY KEY,
    fail_count   INTEGER NOT NULL,
    locked_until REAL NOT NULL DEFAULT 0
);
"""


def get_db(path=None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path=None):
    with get_db(path) as conn:
        conn.executescript(SCHEMA)


def hash_password(password, salt=None, iterations=PBKDF2_ITERATIONS):
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return digest.hex(), salt.hex(), iterations


def verify_password(password, stored_hash, salt_hex, iterations):
    new_hash, _, _ = hash_password(password, bytes.fromhex(salt_hex), iterations)
    return hmac.compare_digest(new_hash, stored_hash)


def create_user(username, password, role, path=None, iterations=PBKDF2_ITERATIONS):
    if role not in ("student", "teacher"):
        raise ValueError("Role must be student or teacher")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("Password is shorter than %d characters" % MIN_PASSWORD_LENGTH)
    pw_hash, salt_hex, iters = hash_password(password, iterations=iterations)
    with get_db(path) as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, iterations, role) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, salt_hex, iters, role),
        )


def cmd_add_user(args):
    password = getpass.getpass("Password (hidden): ")
    if password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match")
    try:
        create_user(args.username, password, args.role)
    except sqlite3.IntegrityError:
        sys.exit("User '%s' already exists" % args.username)
    except ValueError as e:
        sys.exit(str(e))
    print("User '%s' (%s) created" % (args.username, args.role))


def cmd_list_users():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, password_hash, iterations FROM users"
        ).fetchall()
    if not rows:
        print("No users")
    for r in rows:
        print("%s  %-10s %-8s PBKDF2 x%s  hash=%s..." % (
            r["id"], r["username"], r["role"], r["iterations"], r["password_hash"][:20]))


def main():
    parser = argparse.ArgumentParser(description="AuthLab")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create the database")
    p = sub.add_parser("add-user", help="add a user")
    p.add_argument("--username", required=True)
    p.add_argument("--role", required=True, choices=["student", "teacher"])
    sub.add_parser("list-users", help="show users")
    sub.add_parser("serve", help="run the web server (http://127.0.0.1:8000)")
    args = parser.parse_args()

    if args.command == "init":
        init_db()
        print("Database created: %s" % DB_PATH)
    elif args.command == "add-user":
        cmd_add_user(args)
    elif args.command == "list-users":
        cmd_list_users()
    elif args.command == "serve":
        import web
        web.run()


if __name__ == "__main__":
    main()
