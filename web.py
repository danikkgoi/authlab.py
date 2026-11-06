import hashlib
import hmac
import html
import os
import re
import secrets
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from authlab import get_db, hash_password, verify_password

HOST = "127.0.0.1"
PORT = 8000
PRELOGIN_TTL = 10 * 60
SESSION_IDLE = 20 * 60
SESSION_ABSOLUTE = 4 * 3600
MAX_BODY = 10_000
MAX_FAILURES = 5
LOCK_SECONDS = 5 * 60
GENERIC_ERROR = "Invalid username or password"
NOTE_PATH = re.compile(r"^/notes/(\d{1,9})$")

SECURE = os.environ.get("AUTHLAB_HTTPS") == "1"
PREFIX = "__Host-" if SECURE else ""
PRELOGIN_COOKIE = PREFIX + "prelogin"
SESSION_COOKIE = PREFIX + "session"

DUMMY_HASH, DUMMY_SALT, DUMMY_ITERS = hash_password("dummy-password")


def ensure_schema():
    with get_db() as conn:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(login_failures)")]
        if "last_failure" not in cols:
            conn.execute("ALTER TABLE login_failures "
                         "ADD COLUMN last_failure REAL NOT NULL DEFAULT 0")


def new_token():
    return secrets.token_urlsafe(32)


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def make_cookie(name, value, max_age=None):
    parts = ["%s=%s" % (name, value), "HttpOnly", "SameSite=Lax", "Path=/"]
    if max_age is not None:
        parts.append("Max-Age=%d" % max_age)
    if SECURE:
        parts.append("Secure")
    return "; ".join(parts)


def clear_cookie(name):
    return make_cookie(name, "", 0)


def security_headers():
    headers = [
        ("Content-Security-Policy",
         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
         "base-uri 'none'; frame-ancestors 'none'"),
        ("Cache-Control", "no-store"),
        ("Pragma", "no-cache"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
    ]
    if SECURE:
        headers.append(("Strict-Transport-Security", "max-age=31536000"))
    return headers


def esc(text):
    return html.escape(str(text), quote=True)


def page(title, body):
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>%s</title>"
        "<style>body{font-family:Arial;max-width:560px;margin:60px auto}"
        "input,textarea{display:block;width:100%%;padding:8px;margin:8px 0;"
        "box-sizing:border-box}"
        "button{padding:8px 16px}</style></head><body>%s</body></html>"
        % (esc(title), body)
    )


def login_form(csrf, message=""):
    msg = "<p style='color:#b00'>%s</p>" % esc(message) if message else ""
    return page("AuthLab login", (
        "<h2>AuthLab login</h2>%s"
        "<form method='post' action='/login'>"
        "<input type='hidden' name='csrf_token' value='%s'>"
        "<label>Username<input name='username' autocomplete='username'></label>"
        "<label>Password<input name='password' type='password' "
        "autocomplete='current-password'></label>"
        "<button type='submit'>Log in</button></form>"
    ) % (msg, esc(csrf)))


def dashboard_page(session, notes):
    if notes:
        items = "".join("<li><a href='/notes/%d'>%s</a></li>" % (n["id"], esc(n["title"]))
                        for n in notes)
    else:
        items = "<li>No notes yet</li>"
    admin_link = ""
    if session["role"] == "teacher":
        admin_link = "<p><a href='/admin/users'>Users list (teacher only)</a></p>"
    return page("Dashboard", (
        "<h2>Dashboard</h2>"
        "<p>Hello, <b>%s</b> (role: %s)</p>%s"
        "<h3>My notes</h3><ul>%s</ul>"
        "<h3>New note</h3>"
        "<form method='post' action='/notes'>"
        "<input type='hidden' name='csrf_token' value='%s'>"
        "<input name='title' placeholder='Title' maxlength='100'>"
        "<textarea name='body' rows='4' placeholder='Text' maxlength='2000'></textarea>"
        "<button type='submit'>Save note</button></form>"
        "<hr><form method='post' action='/logout'>"
        "<input type='hidden' name='csrf_token' value='%s'>"
        "<button type='submit'>Log out</button></form>"
    ) % (esc(session["username"]), esc(session["role"]), admin_link, items,
         esc(session["csrf_token"]), esc(session["csrf_token"])))


def note_page(note):
    return page("Note", (
        "<h2>%s</h2><p style='white-space:pre-wrap'>%s</p>"
        "<p><a href='/dashboard'>Back</a></p>"
    ) % (esc(note["title"]), esc(note["body"])))


def admin_users_page(users):
    rows = "".join("<tr><td>%d</td><td>%s</td><td>%s</td></tr>"
                   % (u["id"], esc(u["username"]), esc(u["role"])) for u in users)
    return page("Users", (
        "<h2>Users</h2>"
        "<table border='1' cellpadding='6'>"
        "<tr><th>ID</th><th>Username</th><th>Role</th></tr>%s</table>"
        "<p><a href='/dashboard'>Back</a></p>"
    ) % rows)


def check_login(username, password):
    now = time.time()
    with get_db() as conn:
        fail = conn.execute(
            "SELECT fail_count, locked_until, last_failure FROM login_failures "
            "WHERE username = ?", (username,)).fetchone()
        if fail and fail["locked_until"] > now:
            return "locked", None

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            ok = verify_password(password, user["password_hash"],
                                 user["salt"], user["iterations"])
        else:
            verify_password(password, DUMMY_HASH, DUMMY_SALT, DUMMY_ITERS)
            ok = False

        if ok:
            conn.execute("DELETE FROM login_failures WHERE username = ?", (username,))
            return "ok", user

        previous = 0
        if fail and now - fail["last_failure"] < LOCK_SECONDS:
            previous = fail["fail_count"]
        count = previous + 1
        locked_until = 0
        if count >= MAX_FAILURES:
            locked_until = now + LOCK_SECONDS
            count = 0
        conn.execute(
            "INSERT INTO login_failures (username, fail_count, locked_until, last_failure) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET "
            "fail_count = excluded.fail_count, locked_until = excluded.locked_until, "
            "last_failure = excluded.last_failure",
            (username, count, locked_until, now),
        )
        return "bad", None


def create_session(user_id, old_session_token=None, prelogin_token=None):
    token, csrf = new_token(), new_token()
    now = time.time()
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE last_seen < ? OR created_at < ?",
                     (now - SESSION_IDLE, now - SESSION_ABSOLUTE))
        if old_session_token:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?",
                         (token_hash(old_session_token),))
        if prelogin_token:
            conn.execute("DELETE FROM prelogins WHERE token_hash = ?",
                         (token_hash(prelogin_token),))
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (token_hash(token), user_id, csrf, now, now))
    return token


def load_session(token):
    if not token:
        return None
    now = time.time()
    with get_db() as conn:
        row = conn.execute(
            "SELECT s.token_hash, s.csrf_token, s.created_at, s.last_seen, "
            "u.id AS user_id, u.username, u.role "
            "FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ?", (token_hash(token),)).fetchone()
        if row is None:
            return None
        if (now - row["last_seen"] > SESSION_IDLE
                or now - row["created_at"] > SESSION_ABSOLUTE):
            conn.execute("DELETE FROM sessions WHERE token_hash = ?",
                         (row["token_hash"],))
            return None
        conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
                     (now, row["token_hash"]))
    return dict(row)


def delete_session(token):
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))


def list_notes(user_id):
    with get_db() as conn:
        return conn.execute(
            "SELECT id, title FROM notes WHERE owner_id = ? ORDER BY id DESC",
            (user_id,)).fetchall()


def get_note(note_id, user_id):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
            (note_id, user_id)).fetchone()


def add_note(user_id, title, body):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO notes (owner_id, title, body, created_at) VALUES (?, ?, ?, ?)",
            (user_id, title, body, time.time()))


def list_users():
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, role FROM users ORDER BY id").fetchall()


class Handler(BaseHTTPRequestHandler):

    def send_page(self, status, content, extra_headers=()):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in security_headers():
            self.send_header(name, value)
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, extra_headers=()):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for name, value in security_headers():
            self.send_header(name, value)
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()

    def error_page(self, status, text):
        self.send_page(status, page(str(status), "<h2>%d %s</h2>" % (status, esc(text))))

    def get_cookie(self, name):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            return None
        morsel = cookie.get(name)
        return morsel.value if morsel else None

    def read_form(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY:
            return None
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        return {k: v[0] for k, v in parse_qs(body).items()}

    def current_session(self):
        return load_session(self.get_cookie(SESSION_COOKIE))

    def csrf_ok(self, session, form):
        sent = (form or {}).get("csrf_token", "")
        return bool(sent) and hmac.compare_digest(session["csrf_token"], sent)

    def create_prelogin(self):
        token, csrf = new_token(), new_token()
        with get_db() as conn:
            conn.execute("DELETE FROM prelogins WHERE expires_at < ?", (time.time(),))
            conn.execute(
                "INSERT INTO prelogins (token_hash, csrf_token, expires_at) VALUES (?, ?, ?)",
                (token_hash(token), csrf, time.time() + PRELOGIN_TTL),
            )
        return token, csrf

    def check_prelogin_csrf(self, form):
        token = self.get_cookie(PRELOGIN_COOKIE)
        sent = (form or {}).get("csrf_token", "")
        if not token or not sent:
            return None
        with get_db() as conn:
            row = conn.execute(
                "SELECT csrf_token, expires_at FROM prelogins WHERE token_hash = ?",
                (token_hash(token),),
            ).fetchone()
        if row is None or row["expires_at"] < time.time():
            return None
        if hmac.compare_digest(row["csrf_token"], sent):
            return row["csrf_token"]
        return None

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.redirect("/login")
        elif path == "/login":
            token, csrf = self.create_prelogin()
            cookie = make_cookie(PRELOGIN_COOKIE, token, PRELOGIN_TTL)
            self.send_page(200, login_form(csrf), [("Set-Cookie", cookie)])
        elif path == "/dashboard":
            session = self.current_session()
            if session is None:
                self.redirect("/login")
            else:
                self.send_page(200, dashboard_page(session, list_notes(session["user_id"])))
        elif path == "/admin/users":
            self.show_users()
        elif NOTE_PATH.match(path):
            self.show_note(int(NOTE_PATH.match(path).group(1)))
        else:
            self.error_page(404, "Not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/login":
            self.handle_login()
        elif path == "/logout":
            self.handle_logout()
        elif path == "/notes":
            self.handle_create_note()
        else:
            self.error_page(404, "Not found")

    def show_users(self):
        session = self.current_session()
        if session is None:
            self.redirect("/login")
            return
        if session["role"] != "teacher":
            self.error_page(403, "Forbidden")
            return
        self.send_page(200, admin_users_page(list_users()))

    def show_note(self, note_id):
        session = self.current_session()
        if session is None:
            self.redirect("/login")
            return
        note = get_note(note_id, session["user_id"])
        if note is None:
            self.error_page(404, "Not found")
        else:
            self.send_page(200, note_page(note))

    def handle_create_note(self):
        session = self.current_session()
        if session is None:
            self.redirect("/login")
            return
        form = self.read_form()
        if not self.csrf_ok(session, form):
            self.error_page(403, "Forbidden (CSRF)")
            return
        title = form.get("title", "").strip()[:100]
        body = form.get("body", "").strip()[:2000]
        if not title:
            self.error_page(400, "Title is required")
            return
        add_note(session["user_id"], title, body)
        self.redirect("/dashboard")

    def handle_login(self):
        form = self.read_form()
        csrf = self.check_prelogin_csrf(form)
        if csrf is None:
            self.error_page(403, "Forbidden (CSRF)")
            return

        username = form.get("username", "").strip()[:64]
        password = form.get("password", "")[:200]
        result, user = check_login(username, password)

        if result == "locked":
            self.send_page(429, login_form(
                csrf, "Too many failed attempts. Try again in 5 minutes."))
        elif result == "bad":
            self.send_page(401, login_form(csrf, GENERIC_ERROR))
        else:
            token = create_session(user["id"],
                                   self.get_cookie(SESSION_COOKIE),
                                   self.get_cookie(PRELOGIN_COOKIE))
            self.redirect("/dashboard", [
                ("Set-Cookie", make_cookie(SESSION_COOKIE, token)),
                ("Set-Cookie", clear_cookie(PRELOGIN_COOKIE)),
            ])

    def handle_logout(self):
        form = self.read_form()
        session = self.current_session()
        if session is None:
            self.redirect("/login")
            return
        if not self.csrf_ok(session, form):
            self.error_page(403, "Forbidden (CSRF)")
            return
        delete_session(self.get_cookie(SESSION_COOKIE))
        self.redirect("/login", [("Set-Cookie", clear_cookie(SESSION_COOKIE))])

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


def run():
    ensure_schema()
    server = HTTPServer((HOST, PORT), Handler)
    print("AuthLab: http://%s:%d/login   (Ctrl+C to stop)" % (HOST, PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    run()
