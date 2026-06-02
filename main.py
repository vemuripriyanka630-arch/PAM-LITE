from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime, timedelta
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "pam-lite-secret")

TIMEOUT_MINUTES = 15
DB_PATH = os.path.join(os.path.dirname(__file__), "pam_lite.db")


# ── DB helpers ──────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def is_admin():
    return session.get("role") == "admin"


def log_audit(user, action, resource, status="success"):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO audit (time, user, action, resource, status) VALUES (?,?,?,?,?)",
            (ts, user, action, resource, status)
        )


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role     TEXT NOT NULL DEFAULT 'user'
            );
            CREATE TABLE IF NOT EXISTS requests (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                resource TEXT NOT NULL,
                reason   TEXT NOT NULL,
                status   TEXT NOT NULL DEFAULT 'pending',
                created  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                name     TEXT NOT NULL,
                username TEXT NOT NULL,
                url      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                time     TEXT NOT NULL,
                user     TEXT NOT NULL,
                action   TEXT NOT NULL,
                resource TEXT NOT NULL,
                status   TEXT NOT NULL DEFAULT 'success'
            );
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT,
                ip_address TEXT,
                platform TEXT,
                status TEXT
            );
           CREATE TABLE IF NOT EXISTS jit_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                server_name TEXT,
                duration TEXT,
                reason TEXT,
                status TEXT,
                created TEXT
           );
           CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                role TEXT,
                ssh_access TEXT,
                rdp_access TEXT,
                vault_access TEXT
           );
           CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                server_name TEXT,
                protocol TEXT,
                start_time TEXT,
                status TEXT
           );
           CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_name TEXT,
                changed_by TEXT,
                changed_date TEXT
           );
        """)
        # Migrate existing DBs that don't have the role column yet
        try:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        except Exception:
            pass
        # Ensure admin user has admin role
        conn.execute("UPDATE users SET role='admin' WHERE username='admin'")

        if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                ("admin", hash_pw("admin123"), "admin")
            )
        for u, p in [("alice", "alice123"), ("bob", "bob123")]:
            if not conn.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
                conn.execute(
                    "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                    (u, hash_pw(p), "user")
                )
        if not conn.execute("SELECT 1 FROM vault").fetchone():
            conn.executemany("INSERT INTO vault (name, username, url) VALUES (?, ?, ?)", [
                ("Production DB",    "db_admin",    "postgres://prod.internal"),
                ("AWS Root Account", "root",        "https://aws.amazon.com"),
                ("GitHub Org",       "ci-bot",      "https://github.com"),
                ("Billing System",   "billing_svc", "https://billing.internal"),
            ])
        if not conn.execute("SELECT 1 FROM requests").fetchone():
            conn.executemany(
                "INSERT INTO requests (username, resource, reason, status, created) VALUES (?,?,?,?,?)", [
                ("alice", "Production DB",    "Debug outage",      "pending",  "2026-06-01 18:52"),
                ("bob",   "AWS Root Account", "Cost audit",        "approved", "2026-06-01 18:40"),
                ("carol", "Billing System",   "Invoice reconcile", "denied",   "2026-06-01 17:55"),
                ("dave",  "GitHub Org",       "Add deploy key",    "pending",  "2026-06-01 17:30"),
            ])

        if not conn.execute("SELECT 1 FROM servers").fetchone():
            conn.executemany(
                "INSERT INTO servers (server_name, ip_address, platform, status) VALUES (?,?,?,?)",
                [
                ("Windows-Prod-01","10.0.1.10","Windows","Online"),
                ("Linux-App-01","10.0.1.20","Linux","Online"),
                ("Database-01","10.0.1.30","Linux","Offline"),
                ("DomainController","10.0.1.5","Windows","Online")
                ]
                )
init_db()


# ── Session timeout ─────────────────────────────────────────────────────────

@app.before_request
def check_session_timeout():
    if "user" in session:
        last_active = session.get("last_active")
        if last_active:
            elapsed = datetime.utcnow() - datetime.fromisoformat(last_active)
            if elapsed > timedelta(minutes=TIMEOUT_MINUTES):
                user = session.get("user", "unknown")
                session.clear()
                log_audit(user, "SESSION_TIMEOUT", "System")
                return redirect(url_for("login") + "?timeout=1")
        session["last_active"] = datetime.utcnow().isoformat()


# ── Auth ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, hash_pw(password))
            ).fetchone()
        if row:
            session["user"] = username
            session["role"] = row["role"]
            log_audit(username, "LOGIN", "System")
            return redirect(url_for("dashboard"))
        log_audit(username or "unknown", "LOGIN_FAILED", "System", status="failed")
        error = "Invalid username or password."
    timeout = request.args.get("timeout")
    return render_template("login.html", error=error, timeout=timeout)


@app.route("/dashboard")
def dashboard():
    username = request.args.get("username", "").strip()
    password = request.args.get("password", "")
    if username and password:
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, hash_pw(password))
            ).fetchone()
        if row:
            session["user"] = username
            session["role"] = row["role"]
            log_audit(username, "LOGIN", "System")
        else:
            log_audit(username or "unknown", "LOGIN_FAILED", "System", status="failed")
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"], role=session.get("role", "user"))


@app.route("/logout")
def logout():
    if "user" in session:
        log_audit(session["user"], "LOGOUT", "System")
    session.clear()
    return redirect(url_for("login"))


# ── Vault ───────────────────────────────────────────────────────────────────

@app.route("/vault")
def vault():
    if "user" not in session:
        return redirect(url_for("login"))
    log_audit(session["user"], "VIEW_VAULT", "Password Vault")
    with get_db() as conn:
        passwords = conn.execute("SELECT * FROM vault").fetchall()
    return render_template("vault.html", username=session["user"], passwords=passwords)
try:
    conn.execute("ALTER TABLE vault ADD COLUMN password TEXT")
except:
    pass

try:
    conn.execute("ALTER TABLE vault ADD COLUMN last_rotation TEXT")
except:
    pass

try:
    conn.execute("ALTER TABLE vault ADD COLUMN approval_required TEXT")
except:
    pass
conn.execute("""
UPDATE vault
SET password='Password123!',
    last_rotation='2026-06-01',
    approval_required='Yes'
WHERE password IS NULL
""")

# ── Requests ────────────────────────────────────────────────────────────────

@app.route("/requests")
def access_requests():
    if "user" not in session:
        return redirect(url_for("login"))
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM requests ORDER BY id DESC").fetchall()
    return render_template("requests.html", username=session["user"],
                           role=session.get("role", "user"), requests=rows)


@app.route("/requests/new", methods=["POST"])
def new_request():
    if "user" not in session:
        return redirect(url_for("login"))
    resource = request.form.get("resource", "").strip()
    reason   = request.form.get("reason", "").strip()
    if resource and reason:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO requests (username, resource, reason, status, created) VALUES (?,?,?,?,?)",
                (session["user"], resource, reason, "pending", datetime.utcnow().strftime("%Y-%m-%d %H:%M"))
            )
        log_audit(session["user"], "ACCESS_REQUEST", resource)
    return redirect(url_for("access_requests"))


@app.route("/requests/<int:req_id>/approve", methods=["POST"])
def approve_request(req_id):
    if "user" not in session or not is_admin():
        return redirect(url_for("dashboard"))
    with get_db() as conn:
        row = conn.execute("SELECT resource, username FROM requests WHERE id=?", (req_id,)).fetchone()
        conn.execute("UPDATE requests SET status='approved' WHERE id=?", (req_id,))
    if row:
        log_audit(session["user"], "APPROVE_REQUEST", f"{row['resource']} (for {row['username']})")
    return redirect(url_for("access_requests"))


@app.route("/requests/<int:req_id>/deny", methods=["POST"])
def deny_request(req_id):
    if "user" not in session or not is_admin():
        return redirect(url_for("dashboard"))
    with get_db() as conn:
        row = conn.execute("SELECT resource, username FROM requests WHERE id=?", (req_id,)).fetchone()
        conn.execute("UPDATE requests SET status='denied' WHERE id=?", (req_id,))
    if row:
        log_audit(session["user"], "DENY_REQUEST", f"{row['resource']} (for {row['username']})")
    return redirect(url_for("access_requests"))
    
@app.route("/vault/<int:id>/rotate", methods=["POST"])
def rotate_password(id):

    if "user" not in session:
        return redirect(url_for("login"))

    new_password = "NewPassword123!"

    with get_db() as conn:
        conn.execute(
            """
            UPDATE vault
            SET password=?,
                last_rotation=?
            WHERE id=?
            """,
            (
                new_password,
                datetime.utcnow().strftime("%Y-%m-%d"),
                id
            )
        )

    log_audit(
        session["user"],
        "PASSWORD_ROTATION",
        f"Vault {id}"
    )

    return redirect("/vault")

@app.route("/vault/<int:id>/checkout")
def checkout_password(id):

    log_audit(
        session["user"],
        "PASSWORD_CHECKOUT",
        f"Vault {id}"
    )

    return redirect("/vault")


@app.route("/vault/<int:id>/rotate",
           methods=["POST"])
def rotate_password(id):

    log_audit(
        session["user"],
        "PASSWORD_ROTATION",
        f"Vault {id}"
    )

    return redirect("/vault")

# ── Audit ───────────────────────────────────────────────────────────────────

@app.route("/audit")
def audit_logs():
    if "user" not in session:
        return redirect(url_for("login"))
    with get_db() as conn:
        logs = conn.execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT 200"
        ).fetchall()
    return render_template("audit.html", username=session["user"], logs=logs)


# ── Users ───────────────────────────────────────────────────────────────────

@app.route("/users")
def users():
    if "user" not in session or not is_admin():
        return redirect(url_for("dashboard"))
    with get_db() as conn:
        all_users = conn.execute("SELECT username, role FROM users ORDER BY username").fetchall()
    return render_template("users.html", username=session["user"], users=all_users)


@app.route("/users/new", methods=["POST"])
def new_user():
    if "user" not in session or not is_admin():
        return redirect(url_for("dashboard"))
    uname = request.form.get("username", "").strip()
    pw    = request.form.get("password", "").strip()
    role  = request.form.get("role", "user").strip()
    if role not in ("admin", "user"):
        role = "user"
    def reload(error=None, message=None):
        with get_db() as conn:
            all_users = conn.execute("SELECT username, role FROM users ORDER BY username").fetchall()
        return render_template("users.html", username=session["user"], users=all_users,
                               error=error, message=message)
    if not uname or not pw:
        return reload(error="Username and password are required.")
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (uname, hash_pw(pw), role)
            )
        log_audit(session["user"], "CREATE_USER", f"{uname} (role={role})")
        return reload(message=f"User '{uname}' added with role '{role}'.")
    except sqlite3.IntegrityError:
        return reload(error=f"User '{uname}' already exists.")


@app.route("/users/<uname>/role", methods=["POST"])
def change_role(uname):
    if "user" not in session or not is_admin():
        return redirect(url_for("dashboard"))
    new_role = request.form.get("role", "user").strip()
    if new_role not in ("admin", "user"):
        new_role = "user"
    def reload(error=None, message=None):
        with get_db() as conn:
            all_users = conn.execute("SELECT username, role FROM users ORDER BY username").fetchall()
        return render_template("users.html", username=session["user"], users=all_users,
                               error=error, message=message)
    if uname == session["user"]:
        return reload(error="You cannot change your own role.")
    with get_db() as conn:
        conn.execute("UPDATE users SET role=? WHERE username=?", (new_role, uname))
    log_audit(session["user"], "CHANGE_ROLE", f"{uname} → {new_role}")
    return reload(message=f"Role for '{uname}' changed to '{new_role}'.")


@app.route("/users/<uname>/delete", methods=["POST"])
def delete_user(uname):
    if "user" not in session or not is_admin():
        return redirect(url_for("dashboard"))
    def reload(error=None, message=None):
        with get_db() as conn:
            all_users = conn.execute("SELECT username, role FROM users ORDER BY username").fetchall()
        return render_template("users.html", username=session["user"], users=all_users,
                               error=error, message=message)
    if uname == session["user"]:
        return reload(error="You cannot delete your own account.")
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE username=?", (uname,))
    log_audit(session["user"], "DELETE_USER", uname)
    return reload(message=f"User '{uname}' deleted.")


# ── Profile ─────────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("profile.html", username=session["user"],
                           role=session.get("role", "user"))


@app.route("/profile/password", methods=["POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))
    uname   = session["user"]
    current = request.form.get("current_password", "")
    new_pw  = request.form.get("new_password", "").strip()
    confirm = request.form.get("confirm_password", "").strip()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=? AND password=?",
                           (uname, hash_pw(current))).fetchone()
    if not row:
        log_audit(uname, "PASSWORD_CHANGE", "System", status="failed")
        return render_template("profile.html", username=uname,
                               role=session.get("role", "user"),
                               error="Current password is incorrect.")
    if not new_pw:
        return render_template("profile.html", username=uname,
                               role=session.get("role", "user"),
                               error="New password cannot be empty.")
    if new_pw != confirm:
        return render_template("profile.html", username=uname,
                               role=session.get("role", "user"),
                               error="New passwords do not match.")
    with get_db() as conn:
        conn.execute("UPDATE users SET password=? WHERE username=?", (hash_pw(new_pw), uname))
    log_audit(uname, "PASSWORD_CHANGE", "System")
    return render_template("profile.html", username=uname,
                           role=session.get("role", "user"),
                           message="Password updated successfully.")
@app.route("/server_access")
def server_access():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        servers = conn.execute(
            "SELECT * FROM servers"
        ).fetchall()

    return render_template(
        "server_access.html",
        username=session["user"],
        servers=servers
    )


@app.route("/jit_access")
def jit_access():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "jit_access.html",
        username=session["user"]
    )


@app.route("/least_privilege")
def least_privilege():

    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        policies = conn.execute(
            "SELECT * FROM policies"
        ).fetchall()

    return render_template(
        "least_privilege.html",
        username=session["user"],
        policies=policies
    )


@app.route("/evm")
def evm():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "evm.html",
        username=session["user"]
    )


@app.route("/sessions")
def sessions_page():

    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        sessions_list = conn.execute(
            "SELECT * FROM sessions"
        ).fetchall()

    return render_template(
        "sessions.html",
        username=session["user"],
        sessions=sessions_list
    )


@app.route("/reports")
def reports():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "reports.html",
        username=session["user"]
    )


@app.route("/breakglass")
def breakglass():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "breakglass.html",
        username=session["user"]
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
