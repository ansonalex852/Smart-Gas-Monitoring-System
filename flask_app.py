from flask_mail import Mail, Message
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'davidbeckamm0707@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'davidbeckamm0707@gmail.com'

mail = Mail(app)
CORS(app, supports_credentials=True)

DB_FILE = "gasguard.db"
LEAK_THRESHOLD = 300
TOKEN_EXPIRY_H = 24


# ═══════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            created_at TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS sensor_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ppm INTEGER NOT NULL,
            weight_kg REAL NOT NULL,
            is_leak INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Database initialized")


# ═══════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password, stored):
    try:
        salt, hashed = stored.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except:
        return False


def generate_token():
    return secrets.token_urlsafe(32)


def create_session(user_id):
    token = generate_token()
    now = datetime.now()
    expires = (now + timedelta(hours=TOKEN_EXPIRY_H)).isoformat()

    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (user_id, token, expires, now.isoformat())
    )
    conn.commit()
    conn.close()
    return token


def get_user_from_token(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute('''
        SELECT u.id, u.fullname, u.email, u.username, u.role
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
        AND s.expires_at > ?
    ''', (token, datetime.now().isoformat())).fetchone()
    conn.close()
    return dict(row) if row else None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"message": "Unauthorized"}), 401
        user = get_user_from_token(token)
        if not user:
            return jsonify({"message": "Invalid or expired token"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════
# HTML ROUTES (Templates Folder)
# ═══════════════════════════════════════

@app.route('/')
def login_page():
    return render_template("login.html")


@app.route('/register')
def register_page():
    return render_template("register.html")


@app.route('/dashboard')
def dashboard_page():
    return render_template("index.html")


# ═══════════════════════════════════════
# AUTH API
# ═══════════════════════════════════════

@app.route('/auth/register', methods=['POST'])
def register():
    
    data = request.get_json()
    fullname = data.get("fullname", "")
    email = data.get("email", "").lower()
    username = data.get("username", "").lower()
    password = data.get("password", "")

    if not all([fullname, email, username, password]):
        return jsonify({"message": "All fields required"}), 400

    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE email=? OR username=?",
        (email, username)
    ).fetchone()

    if existing:
        conn.close()
        return jsonify({"message": "User already exists"}), 409

    hashed = hash_password(password)
    conn.execute(
        "INSERT INTO users (fullname, email, username, password, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (fullname, email, username, hashed, "member", datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    # ✅ SEND WELCOME EMAIL
    try:
        msg = Message(
            subject="Welcome to GasGuard 🔥",
            recipients=[email]
        )
        msg.body = f"""
Hello {fullname},

Welcome to GasGuard!

Your account has been successfully created.

Username: {username}

Stay safe,
GasGuard Security System
        """
        mail.send(msg)

    except Exception as e:
        print("Email failed:", e)

    return jsonify({"message": "Account created"}), 201


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username", "").lower()
    password = data.get("password", "")

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? OR email=?",
        (username, username)
    ).fetchone()
    conn.close()

    if not user or not verify_password(password, user["password"]):
        return jsonify({"message": "Invalid credentials"}), 401

    token = create_session(user["id"])

    # ✅ SEND LOGIN ALERT EMAIL
    try:
        msg = Message(
            subject="GasGuard Login Alert ⚠",
            recipients=[user["email"]]
        )
        msg.body = f"""
Hello {user["fullname"]},

Your GasGuard account was just logged in.

If this was not you, please reset your password immediately.

- GasGuard Security
        """
        mail.send(msg)

    except Exception as e:
        print("Email failed:", e)

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "fullname": user["fullname"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
    }), 200
def send_leak_alert(ppm_value):
    conn = get_db()
    users = conn.execute("SELECT email, fullname FROM users").fetchall()
    conn.close()

    for user in users:
        try:
            msg = Message(
                subject="🚨 GAS LEAK DETECTED - GasGuard Alert",
                recipients=[user["email"]]
            )
            msg.body = f"""
Hello {user['fullname']},

⚠ WARNING: Gas leak detected!

Gas Level: {ppm_value} PPM

Please check your gas system immediately.

Stay safe,
GasGuard Security System
            """
            mail.send(msg)

        except Exception as e:
            print("Leak email failed:", e)
# ═══════════════════════════════════════
# SENSOR API
# ═══════════════════════════════════════

def send_leak_alert(ppm_value):
    conn = get_db()
    users = conn.execute("SELECT email, fullname FROM users").fetchall()
    conn.close()

    if not users:
        print("⚠️ No users found in database to send alerts to!")
        return

    for user in users:
        try:
            print(f"📧 Attempting to send alert to {user['email']}...")
            msg = Message(
                subject="🚨 GAS LEAK DETECTED - GasGuard Alert",
                recipients=[user["email"]]
            )
            msg.body = f"""
Hello {user['fullname']},

⚠ WARNING: Gas leak detected!

Gas Level: {ppm_value} PPM

Please check your gas system immediately.

Stay safe,
GasGuard Security System
            """
            mail.send(msg)
            print(f"✅ Alert sent successfully to {user['email']}")

        except Exception as e:
            print(f"❌ Leak email failed for {user['email']}:", e)


@app.route('/sensors', methods=['POST'])
def receive_data():
    # 1. Add force=True to handle hardware requests missing the header
    data = request.get_json(force=True, silent=True)
    
    if not data:
        print("❌ Error: No JSON data received from sensor")
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    ppm = int(data.get("ppm", 0))
    weight = float(data.get("weight_kg", 0))
    is_leak = 1 if ppm >= LEAK_THRESHOLD else 0
    ts = datetime.now().isoformat()

    conn = get_db()
    conn.execute(
        "INSERT INTO sensor_readings (ppm, weight_kg, is_leak, timestamp) VALUES (?, ?, ?, ?)",
        (ppm, weight, is_leak, ts)
    )
    conn.commit()
    conn.close()

    # 🚨 SEND EMAIL IF LEAK DETECTED
    if is_leak == 1:
        print(f"⚠️ DANGER: Leak detected ({ppm} PPM). Triggering email alerts...")
        send_leak_alert(ppm)

    return jsonify({"status": "ok", "is_leak": bool(is_leak)})


# ═══════════════════════════════════════
# MAIN
# ═══════════════════════════════════════

if __name__ == '__main__':
    init_db()
    print("\n🛡 GasGuard Server Running")
    print("🌐 http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=True)