import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps

import qrcode
from flask import (
    Flask, jsonify, redirect, render_template, request, session,
    send_file, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "secure_qr.db")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-flask-secret-in-production")
HMAC_SECRET = os.environ.get(
    "QR_HMAC_SECRET",
    "change-this-qr-hmac-secret-before-production"
).encode("utf-8")

QR_VALIDITY_SECONDS = 60


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT UNIQUE,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','student')),
        department TEXT,
        year TEXT
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        event_name TEXT NOT NULL,
        event_date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS qr_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        nonce TEXT UNIQUE NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        mac TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        event_id INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        UNIQUE(user_id, event_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE SET NULL
    );
    """)

    admin = conn.execute(
        "SELECT id FROM users WHERE email = ?", ("admin@college.local",)
    ).fetchone()
    if not admin:
        conn.execute("""
            INSERT INTO users
            (student_id, name, email, password_hash, role, department, year)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "ADMIN001", "College Admin", "admin@college.local",
            generate_password_hash("Admin@123"), "admin", "IT", "Faculty"
        ))

    students = [
        ("IT001", "Tushar Pawar", "tushar@college.local", "IT", "Final Year"),
        ("IT002", "Rahul Sharma", "rahul@college.local", "IT", "Final Year"),
        ("IT003", "Amit Patil", "amit@college.local", "IT", "Final Year"),
    ]
    for sid, name, email, dept, year in students:
        exists = conn.execute(
            "SELECT id FROM users WHERE student_id = ?", (sid,)
        ).fetchone()
        if not exists:
            conn.execute("""
                INSERT INTO users
                (student_id, name, email, password_hash, role, department, year)
                VALUES (?, ?, ?, ?, 'student', ?, ?)
            """, (
                sid, name, email, generate_password_hash("Student@123"),
                dept, year
            ))

    conn.commit()
    conn.close()


def current_user():
    if "user_id" not in session:
        return None
    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()
    return user


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if role and user["role"] != role:
                return "Forbidden", 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def canonical_message(event_id, issued_at, expires_at, nonce):
    return f"{event_id}|{issued_at}|{expires_at}|{nonce}"


def make_mac(message):
    return hmac.new(HMAC_SECRET, message.encode(), hashlib.sha256).hexdigest()


def secure_compare(a, b):
    return hmac.compare_digest(a, b)


def encode_payload(payload):
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_payload(token):
    padding = "=" * (-len(token) % 4)
    raw = base64.urlsafe_b64decode(token + padding)
    return json.loads(raw.decode())


def log_security(user_id, event_id, action, details):
    conn = db()
    conn.execute("""
        INSERT INTO security_logs(user_id, event_id, action, details, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, event_id, action, details, now_iso()))
    conn.commit()
    conn.close()


@app.route("/")
def index():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return redirect(url_for("admin_dashboard" if user["role"] == "admin" else "student_dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for(
                "admin_dashboard" if user["role"] == "admin"
                else "student_dashboard"
            ))
        error = "Invalid email or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    conn = db()
    events = conn.execute("""
        SELECT e.*,
               (SELECT COUNT(*) FROM attendance a WHERE a.event_id=e.id) AS present_count,
               (SELECT COUNT(*) FROM users u WHERE u.role='student') AS total_students
        FROM events e
        ORDER BY e.id DESC
    """).fetchall()
    logs = conn.execute("""
        SELECT s.*, u.name AS user_name, e.event_name
        FROM security_logs s
        LEFT JOIN users u ON u.id=s.user_id
        LEFT JOIN events e ON e.id=s.event_id
        ORDER BY s.id DESC LIMIT 15
    """).fetchall()
    conn.close()
    return render_template("admin.html", events=events, logs=logs)


@app.route("/student")
@login_required("student")
def student_dashboard():
    conn = db()
    events = conn.execute("""
        SELECT e.*,
               EXISTS(
                   SELECT 1 FROM attendance a
                   WHERE a.event_id=e.id AND a.user_id=?
               ) AS attended
        FROM events e
        ORDER BY e.id DESC
    """, (session["user_id"],)).fetchall()
    conn.close()
    return render_template("student.html", events=events)


@app.post("/api/events")
@login_required("admin")
def create_event():
    data = request.get_json(silent=True) or {}
    event_id = data.get("event_id", "").strip()
    event_name = data.get("event_name", "").strip()
    event_date = data.get("event_date", "").strip()
    start_time = data.get("start_time", "").strip()
    end_time = data.get("end_time", "").strip()

    if not all([event_id, event_name, event_date, start_time, end_time]):
        return jsonify(ok=False, error="All fields are required."), 400

    conn = db()
    try:
        conn.execute("""
            INSERT INTO events(event_id, event_name, event_date, start_time, end_time, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (event_id, event_name, event_date, start_time, end_time, now_iso()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify(ok=False, error="Event ID already exists."), 409
    conn.close()

    return jsonify(ok=True)


@app.get("/api/events/<int:event_db_id>/qr")
@login_required("admin")
def generate_qr(event_db_id):
    conn = db()
    event = conn.execute(
        "SELECT * FROM events WHERE id=?", (event_db_id,)
    ).fetchone()

    if not event:
        conn.close()
        return jsonify(ok=False, error="Event not found."), 404

    issued_at = int(time.time())
    expires_at = issued_at + QR_VALIDITY_SECONDS
    nonce = secrets.token_urlsafe(18)

    message = canonical_message(event["event_id"], issued_at, expires_at, nonce)
    mac = make_mac(message)

    conn.execute("""
        INSERT INTO qr_sessions(event_id, nonce, issued_at, expires_at, mac)
        VALUES (?, ?, ?, ?, ?)
    """, (event_db_id, nonce, issued_at, expires_at, mac))
    conn.commit()
    conn.close()

    payload = {
        "event_id": event["event_id"],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
        "mac": mac
    }
    token = encode_payload(payload)

    qr = qrcode.QRCode(version=None, box_size=10, border=4)
    qr.add_data(token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    output = io.BytesIO()
    img.save(output, format="PNG")
    output.seek(0)

    return send_file(
        output,
        mimetype="image/png",
        download_name=f"{event['event_id']}_secure_qr.png"
    )


@app.post("/api/attendance/scan")
@login_required("student")
def scan_attendance():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()

    if not token:
        return jsonify(ok=False, error="QR token is missing."), 400

    user_id = session["user_id"]

    try:
        payload = decode_payload(token)
        required = ["event_id", "issued_at", "expires_at", "nonce", "mac"]
        if any(key not in payload for key in required):
            raise ValueError("Invalid QR payload")
    except Exception:
        log_security(user_id, None, "INVALID_QR", "Malformed QR payload")
        return jsonify(ok=False, error="Invalid QR payload."), 400

    event_code = str(payload["event_id"])
    issued_at = int(payload["issued_at"])
    expires_at = int(payload["expires_at"])
    nonce = str(payload["nonce"])
    received_mac = str(payload["mac"])

    expected_message = canonical_message(
        event_code, issued_at, expires_at, nonce
    )
    expected_mac = make_mac(expected_message)

    if not secure_compare(expected_mac, received_mac):
        log_security(user_id, None, "HMAC_FAILURE", "QR data was modified or forged")
        return jsonify(ok=False, error="Invalid QR signature/HMAC. Possible tampering detected."), 403

    now = int(time.time())
    if now > expires_at or issued_at > now + 10:
        log_security(user_id, None, "EXPIRED_QR", f"QR expired at {expires_at}")
        return jsonify(ok=False, error="QR has expired. Scan the latest QR."), 403

    conn = db()
    event = conn.execute(
        "SELECT * FROM events WHERE event_id=?", (event_code,)
    ).fetchone()

    if not event:
        conn.close()
        log_security(user_id, None, "UNKNOWN_EVENT", event_code)
        return jsonify(ok=False, error="Event not found."), 404

    qr_session = conn.execute("""
        SELECT * FROM qr_sessions
        WHERE event_id=? AND nonce=? AND mac=?
    """, (event["id"], nonce, received_mac)).fetchone()

    if not qr_session:
        conn.close()
        log_security(user_id, event["id"], "UNKNOWN_NONCE", nonce)
        return jsonify(ok=False, error="Unknown or invalid QR session."), 403

    if qr_session["used"]:
        conn.close()
        log_security(user_id, event["id"], "REPLAY_BLOCKED", nonce)
        return jsonify(ok=False, error="This QR has already been used."), 409

    existing = conn.execute("""
        SELECT id FROM attendance
        WHERE user_id=? AND event_id=?
    """, (user_id, event["id"])).fetchone()

    if existing:
        conn.close()
        return jsonify(ok=False, error="Attendance already marked for this event."), 409

    try:
        conn.execute(
            "UPDATE qr_sessions SET used=1 WHERE id=?",
            (qr_session["id"],)
        )
        conn.execute("""
            INSERT INTO attendance(user_id, event_id, nonce, scanned_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, event["id"], nonce, now_iso()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return jsonify(ok=False, error="Attendance could not be recorded."), 409

    conn.close()
    log_security(user_id, event["id"], "ATTENDANCE_SUCCESS", "Valid HMAC and nonce")
    return jsonify(ok=True, message="Attendance marked successfully.")


@app.get("/api/events/<int:event_db_id>/attendance")
@login_required("admin")
def attendance(event_db_id):
    conn = db()
    rows = conn.execute("""
        SELECT u.student_id, u.name, u.email, u.department, u.year,
               a.scanned_at, a.nonce
        FROM attendance a
        JOIN users u ON u.id=a.user_id
        WHERE a.event_id=?
        ORDER BY a.scanned_at DESC
    """, (event_db_id,)).fetchall()
    conn.close()
    return jsonify(ok=True, attendance=[dict(r) for r in rows])


@app.get("/api/security-logs")
@login_required("admin")
def security_logs():
    conn = db()
    rows = conn.execute("""
        SELECT s.created_at, s.action, s.details,
               u.name AS user_name, e.event_name
        FROM security_logs s
        LEFT JOIN users u ON u.id=s.user_id
        LEFT JOIN events e ON e.id=s.event_id
        ORDER BY s.id DESC LIMIT 100
    """).fetchall()
    conn.close()
    return jsonify(ok=True, logs=[dict(r) for r in rows])


@app.route("/api/me")
@login_required()
def me():
    user = current_user()
    return jsonify(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        role=user["role"],
        student_id=user["student_id"]
    )


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
