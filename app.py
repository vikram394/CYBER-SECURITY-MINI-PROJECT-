
from flask import Flask, render_template, request
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import time
from datetime import datetime

app = Flask(__name__)

# Login credentials
USERNAME = "admin"
PASSWORD_HASH = generate_password_hash("admin123")

# Security settings
MAX_ATTEMPTS = 1
LOCK_TIME = 30

failed_attempts = 0
locked_until = 0


# Database connection
def get_db_connection():
    conn = sqlite3.connect("login_activity.db")
    conn.row_factory = sqlite3.Row
    return conn


# Create database table
def create_database():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            status TEXT NOT NULL,
            login_time TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Save login activity
def save_log(username, status):
    conn = get_db_connection()

    conn.execute(
        """INSERT INTO login_logs
        (username, status, login_time)
        VALUES (?, ?, ?)""",
        (
            username if username else "Unknown",
            status,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()


# Home page
@app.route("/")
def home():
    return render_template("index.html")


# Login route
@app.route("/login", methods=["POST"])
def login():
    global failed_attempts, locked_until

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    current_time = time.time()

    # Check whether login is locked
    if current_time < locked_until:

        remaining = max(
            0,
            int(locked_until - current_time + 0.999)
        )

        save_log(username, "Blocked")

        return render_template(
            "index.html",
            message="Too many failed attempts! Login is temporarily blocked.",
            status="error",
            remaining_seconds=remaining
        )

    # Check correct credentials
    if username == USERNAME and check_password_hash(
        PASSWORD_HASH, password
    ):

        failed_attempts = 0
        locked_until = 0

        save_log(username, "Success")

        return render_template(
            "index.html",
            message="Login successful! Welcome.",
            status="success"
        )

    # Count incorrect login attempts
    failed_attempts += 1

    attempts_left = MAX_ATTEMPTS - failed_attempts

    print("Username:", username)
    print("Failed attempts:", failed_attempts)
    print("Attempts left:", attempts_left)

    # Activate temporary lockout
    if attempts_left <= 0:

        locked_until = current_time + LOCK_TIME

        save_log(username, "Blocked")

        return render_template(
            "index.html",
            message="Too many failed attempts! Login blocked.",
            status="error",
            remaining_seconds=LOCK_TIME
        )

    # Save normal failed attempt
    save_log(username, "Failed")

    return render_template(
        "index.html",
        message=f"Incorrect username or password. Attempts left: {attempts_left}",
        status="error"
    )


# Run application
if __name__ == "__main__":
    create_database()
    app.run(debug=True)
