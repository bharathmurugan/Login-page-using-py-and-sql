import hmac
import os
import re
import secrets
import time
from datetime import date, datetime, timedelta

import mysql.connector
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


# ========================================================= # DATABASE
# =========================================================

def get_db_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", 3306)),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD", "Bharath@123"),
        database=os.environ.get("DB_NAME", "login_app"),
    )


def close_all(cursor, connection):
    if cursor:
        cursor.close()

    if connection and connection.is_connected():
        connection.close()


def password_matches(stored, entered):
    """Supports Werkzeug hashes and legacy plaintext passwords."""

    if stored.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored, entered)

    return hmac.compare_digest(
        stored.encode(),
        entered.encode(),
    )


def count_users():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM users")

        return cursor.fetchone()[0]

    except mysql.connector.Error:
        return None

    finally:
        close_all(cursor, connection)


COLUMN_TOO_SHORT = (
    "The password column is too short for a secure hash. "
    "Run this in MySQL once: "
    "ALTER TABLE users MODIFY password VARCHAR(255) NOT NULL;"
)


# ========================================================= # SECURITY
# =========================================================

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)

    return session["csrf"]


def csrf_ok():
    return hmac.compare_digest(
        session.get("csrf", ""),
        request.form.get("csrf", ""),
    )


MAX_ATTEMPTS = 5
LOCK_SECONDS = 60

ATTEMPTS = {}


def attempt_key(username):
    return f"{request.remote_addr}|{username.lower()}"


def lock_remaining(key):
    record = ATTEMPTS.get(key)

    if record and record["locked_until"]:
        left = record["locked_until"] - time.time()

        if left > 0:
            return int(left) + 1

        ATTEMPTS.pop(key, None)

    return 0


def record_failure(key):
    record = ATTEMPTS.setdefault(
        key,
        {
            "count": 0,
            "locked_until": 0,
        },
    )

    record["count"] += 1

    if record["count"] >= MAX_ATTEMPTS:
        record["locked_until"] = time.time() + LOCK_SECONDS

    return MAX_ATTEMPTS - record["count"]


# ========================================================= # LIVE FEATURES
# =========================================================

LAST_SEEN = {}

ONLINE_WINDOW = 75

POST_LOG = {}

MESSAGES_READY = False


def init_db():
    global MESSAGES_READY

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "CREATE TABLE IF NOT EXISTS messages ("
            "id INT AUTO_INCREMENT PRIMARY KEY, "
            "username VARCHAR(50) NOT NULL, "
            "body VARCHAR(300) NOT NULL, "
            "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )

        connection.commit()

        MESSAGES_READY = True

    except mysql.connector.Error as e:
        print("Could not prepare the messages table:", e)
        MESSAGES_READY = False

    finally:
        close_all(cursor, connection)

    return MESSAGES_READY


def ensure_messages():
    return MESSAGES_READY or init_db()


def csrf_header_ok():
    return hmac.compare_digest(
        session.get("csrf", ""),
        request.headers.get("X-CSRF-Token", ""),
    )


def api_error(message, status):
    return jsonify(error=message), status


def too_fast(user):
    now = time.time()

    log = [
        t
        for t in POST_LOG.get(user, [])
        if now - t < 60
    ]

    if log and now - log[-1] < 1:
        POST_LOG[user] = log
        return "Slow down a little."

    if len(log) >= 20:
        POST_LOG[user] = log
        return "You are sending messages too quickly. Wait a moment."

    log.append(now)
    POST_LOG[user] = log

    return None


def pretty_time(stamp):
    if stamp.date() == date.today():
        return stamp.strftime("%I:%M %p").lstrip("0")

    return stamp.strftime("%d %b, %I:%M %p").lstrip("0")


@app.before_request
def track_presence():
    if "user" in session:
        LAST_SEEN[session["user"]] = time.time()


USERNAME_RULE = re.compile(
    r"^[A-Za-z0-9_.]{3,30}$"
)


def render(page, **ctx):
    notice = session.pop("notice", None)

    ctx.setdefault("error", None)
    ctx.setdefault("notice", notice)
    ctx.setdefault("form_username", "")

    return render_template_string(
        HTML,
        page=page,
        csrf=csrf_token(),
        **ctx,
    )


# ========================================================= # HTML
# =========================================================

HTML = """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<meta
    name="csrf"
    content="{{ csrf }}"
>

<title>
    {{
        {
            'login': 'Sign in',
            'register': 'Create account',
            'password': 'Change password',
            'dashboard': 'Dashboard'
        }[page]
    }}
    · Glassgate
</title>

<link
    rel="preconnect"
    href="https://fonts.googleapis.com"
>

<link
    rel="preconnect"
    href="https://fonts.gstatic.com"
    crossorigin
>

<link
    href="https://fonts.googleapis.com/css2?family=Outfit:wght@500;700&family=Inter:wght@400;500;600&display=swap"
    rel="stylesheet"
>

<style>

:root {
    --bg: #070b18;

    --glow-teal: #14b8a6;
    --glow-violet: #7c3aed;
    --glow-blue: #2563eb;

    --text: #f1f5f9;
    --text-muted: rgba(226, 232, 240, 0.68);

    --glass: rgba(255, 255, 255, 0.08);
    --glass-strong: rgba(255, 255, 255, 0.13);
    --glass-border: rgba(255, 255, 255, 0.18);

    --accent-1: #0d9488;
    --accent-2: #6d28d9;
    --focus: #5eead4;

    --danger: #fecaca;
    --danger-bg: rgba(248, 113, 113, 0.14);
    --danger-line: rgba(248, 113, 113, 0.45);

    --ok: #86efac;
    --ok-bg: rgba(74, 222, 128, 0.14);
    --ok-line: rgba(74, 222, 128, 0.35);

    --warn: #fcd34d;

    --font-display: "Outfit", "Segoe UI", system-ui, sans-serif;
    --font-body: "Inter", "Segoe UI", system-ui, sans-serif;

    --radius-card: 28px;
    --radius-field: 14px;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    min-height: 100vh;

    display: grid;
    place-items: center;

    padding: 32px 16px;

    font-family: var(--font-body);
    color: var(--text);

    background: var(--bg);
}

:focus-visible {
    outline: 3px solid var(--focus);
    outline-offset: 2px;
}

[hidden] {
    display: none !important;
}


/* AURORA */

.aurora {
    position: fixed;
    inset: 0;

    z-index: 0;

    overflow: hidden;
    pointer-events: none;
}

.aurora span {
    position: absolute;

    border-radius: 50%;

    filter: blur(90px);

    opacity: 0.75;

    animation:
        drift 16s ease-in-out infinite alternate;
}

.aurora span:nth-child(1) {
    width: 46vmax;
    height: 46vmax;

    background: var(--glow-teal);

    top: -14vmax;
    left: -10vmax;
}

.aurora span:nth-child(2) {
    width: 42vmax;
    height: 42vmax;

    background: var(--glow-violet);

    bottom: -14vmax;
    right: -8vmax;

    animation-delay: -6s;
}

.aurora span:nth-child(3) {
    width: 30vmax;
    height: 30vmax;

    background: var(--glow-blue);

    top: 35%;
    left: 55%;

    opacity: 0.55;

    animation-delay: -11s;
}


/* GLASS */

.glass {
    position: relative;

    z-index: 1;

    width: 100%;
    max-width: 430px;

    padding: 30px 36px 32px;

    background: var(--glass);

    border: 1px solid var(--glass-border);

    border-radius: var(--radius-card);

    -webkit-backdrop-filter:
        blur(26px)
        saturate(150%);

    backdrop-filter:
        blur(26px)
        saturate(150%);

    box-shadow:
        0 30px 70px rgba(0, 0, 0, 0.45),
        inset 0 1px 0 rgba(255, 255, 255, 0.28);

    animation:
        enter 0.7s
        cubic-bezier(0.2, 0.8, 0.3, 1)
        both;
}

.glass--wide {
    max-width: 640px;
}

@supports not (
    (backdrop-filter: blur(1px))
    or
    (-webkit-backdrop-filter: blur(1px))
) {
    .glass {
        background: rgba(20, 26, 52, 0.88);
    }
}


/* TOP */

.topline {
    display: flex;

    align-items: center;
    justify-content: space-between;

    gap: 12px;

    margin-bottom: 28px;
}

.brand {
    display: flex;

    align-items: center;

    gap: 12px;

    font-family: var(--font-display);

    font-size: 19px;

    font-weight: 700;

    line-height: 1;
}

.brand__logo {
    width: 38px;
    height: 38px;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            var(--accent-1),
            var(--accent-2)
        );

    display: grid;
    place-items: center;

    box-shadow:
        0 8px 20px
        rgba(109, 40, 217, 0.4);
}

.status {
    display: inline-flex;

    align-items: center;

    gap: 8px;

    height: 30px;

    padding: 0 13px 0 11px;

    font-size: 12px;

    font-weight: 600;

    white-space: nowrap;

    color: var(--text);

    background: var(--glass-strong);

    border: 1px solid var(--glass-border);

    border-radius: 999px;
}

.status i {
    flex: none;

    width: 8px;
    height: 8px;

    border-radius: 50%;

    background: var(--warn);

    box-shadow: 0 0 10px var(--warn);
}

.status[data-state="online"] i {
    background: #4ade80;

    box-shadow:
        0 0 10px #4ade80;
}

.status[data-state="offline"] i {
    background: #f87171;

    box-shadow:
        0 0 10px #f87171;
}


/* TYPOGRAPHY */

h1 {
    margin-bottom: 8px;

    font-family: var(--font-display);

    font-size: 32px;

    font-weight: 700;

    letter-spacing: -0.5px;

    line-height: 1.12;
}

.subtitle {
    margin-bottom: 26px;

    color: var(--text-muted);

    font-size: 15px;

    line-height: 1.5;
}


/* FORM */

.field {
    margin-bottom: 16px;
}

.field label {
    display: block;

    margin-bottom: 7px;

    font-size: 13px;

    font-weight: 600;

    color:
        rgba(241, 245, 249, 0.85);
}

.control {
    position: relative;
}

.control__icon {
    position: absolute;

    left: 16px;
    top: 50%;

    transform: translateY(-50%);

    color: var(--text-muted);

    pointer-events: none;

    transition: color 0.2s;
}

.control input {
    width: 100%;
    height: 54px;

    padding: 0 48px;

    font: inherit;

    font-size: 15px;

    color: var(--text);

    background:
        rgba(255, 255, 255, 0.07);

    border:
        1px solid var(--glass-border);

    border-radius:
        var(--radius-field);

    transition:
        border-color 0.2s,
        background 0.2s,
        box-shadow 0.2s;
}

.control input::placeholder {
    color:
        rgba(226, 232, 240, 0.42);
}

.control input:hover {
    background:
        rgba(255, 255, 255, 0.1);
}

.control input:focus {
    outline: none;

    background:
        rgba(255, 255, 255, 0.12);

    border-color: var(--focus);

    box-shadow:
        0 0 0 4px
        rgba(94, 234, 212, 0.18);
}

.control:focus-within .control__icon {
    color: var(--focus);
}

.control input:-webkit-autofill {
    -webkit-text-fill-color: var(--text);

    -webkit-box-shadow:
        0 0 0 100px
        #1b2140 inset;

    caret-color: var(--text);
}

.control__toggle {
    position: absolute;

    right: 6px;
    top: 50%;

    transform: translateY(-50%);

    width: 40px;
    height: 40px;

    border: none;

    border-radius: 10px;

    background: transparent;

    color: var(--text-muted);

    cursor: pointer;

    display: grid;

    place-items: center;
}

.control__toggle:hover {
    background:
        rgba(255, 255, 255, 0.1);

    color: var(--text);
}

.capswarn {
    display: block;

    margin-top: 7px;

    font-size: 12px;

    font-weight: 500;

    color: var(--warn);
}

.meter {
    height: 6px;

    margin-top: 10px;

    border-radius: 99px;

    background:
        rgba(255, 255, 255, 0.12);

    overflow: hidden;
}

.meter span {
    display: block;

    height: 100%;

    width: 0;

    border-radius: inherit;

    background: #f87171;

    transition:
        width 0.25s,
        background 0.25s;
}

.meter__label {
    display: block;

    margin-top: 6px;

    font-size: 12px;

    color: var(--text-muted);
}

.remember {
    display: flex;

    align-items: center;

    gap: 10px;

    margin: 2px 0 6px;

    font-size: 13px;

    color: var(--text-muted);

    cursor: pointer;
}

.remember input {
    width: 18px;
    height: 18px;

    accent-color: var(--accent-1);
}


/* BUTTONS */

.btn {
    width: 100%;
    height: 54px;

    margin-top: 10px;

    display: flex;

    justify-content: center;
    align-items: center;

    gap: 10px;

    font: inherit;

    font-size: 16px;

    font-weight: 600;

    text-decoration: none;

    color: #fff;

    background:
        linear-gradient(
            135deg,
            var(--accent-1),
            var(--accent-2)
        );

    border: none;

    border-radius:
        var(--radius-field);

    cursor: pointer;

    box-shadow:
        0 14px 30px
        rgba(109, 40, 217, 0.35);

    transition:
        transform 0.15s,
        box-shadow 0.2s,
        filter 0.2s;
}

.btn:hover {
    filter: brightness(1.1);

    box-shadow:
        0 18px 38px
        rgba(109, 40, 217, 0.5);
}

.btn:active {
    transform: scale(0.99);
}

.btn[disabled] {
    opacity: 0.85;
    cursor: progress;
}

.btn--glass {
    margin-top: 0;

    background:
        var(--glass-strong);

    border:
        1px solid var(--glass-border);

    box-shadow: none;
}

.btn--glass:hover {
    background:
        rgba(255, 255, 255, 0.2);

    box-shadow: none;
}

.spinner {
    display: none;

    width: 18px;
    height: 18px;

    border-radius: 50%;

    border:
        2.5px solid
        rgba(255, 255, 255, 0.4);

    border-top-color: #fff;

    animation:
        spin 0.7s linear infinite;
}

.btn.is-loading .spinner {
    display: block;
}

.switch {
    margin-top: 22px;

    text-align: center;

    font-size: 14px;

    color: var(--text-muted);
}

.switch a {
    color: var(--focus);

    font-weight: 600;

    text-decoration: none;
}

.switch a:hover {
    text-decoration: underline;
}


/* MESSAGES */

.alert {
    margin-bottom: 18px;

    padding: 12px 14px;

    font-size: 14px;

    font-weight: 500;

    line-height: 1.45;

    color: var(--danger);

    background:
        var(--danger-bg);

    border:
        1px solid
        var(--danger-line);

    border-radius: 12px;
}

.alert--ok {
    color: var(--ok);

    background:
        var(--ok-bg);

    border-color:
        var(--ok-line);
}


/* DASHBOARD */

.badge {
    display: inline-flex;

    align-items: center;

    gap: 8px;

    margin-bottom: 18px;

    padding: 6px 13px 6px 9px;

    font-size: 13px;

    font-weight: 600;

    color: var(--ok);

    background:
        var(--ok-bg);

    border:
        1px solid
        var(--ok-line);

    border-radius: 999px;
}

.badge i {
    width: 8px;
    height: 8px;

    border-radius: 50%;

    background: #4ade80;

    box-shadow:
        0 0 10px #4ade80;
}

.profile {
    display: flex;

    align-items: center;

    gap: 16px;
}

.profile h1 {
    margin: 0;

    font-size: 30px;

    word-break: break-word;
}

.avatar {
    flex: none;

    width: 62px;
    height: 62px;

    border-radius: 18px;

    display: grid;

    place-items: center;

    font-family: var(--font-display);

    font-size: 26px;

    font-weight: 700;

    color: #fff;

    background:
        linear-gradient(
            135deg,
            var(--accent-1),
            var(--accent-2)
        );

    box-shadow:
        0 10px 24px
        rgba(109, 40, 217, 0.4);
}

.tiles {
    display: grid;

    grid-template-columns:
        repeat(2, 1fr);

    gap: 12px;

    margin: 24px 0;
}

.tile {
    padding: 16px 18px;

    background:
        rgba(255, 255, 255, 0.07);

    border:
        1px solid
        var(--glass-border);

    border-radius: 16px;
}

.tile small {
    display: block;

    margin-bottom: 5px;

    font-size: 12px;

    color: var(--text-muted);
}

.tile b {
    font-size: 18px;

    font-weight: 600;

    font-variant-numeric:
        tabular-nums;
}

.actions {
    display: grid;

    grid-template-columns:
        1fr 1fr;

    gap: 12px;
}


/* TABS */

.tabs {
    display: flex;

    gap: 6px;

    padding: 5px;

    margin-bottom: 22px;

    background:
        rgba(255, 255, 255, 0.06);

    border:
        1px solid
        var(--glass-border);

    border-radius: 16px;
}

.tab {
    flex: 1;

    height: 42px;

    border: none;

    border-radius: 12px;

    background: transparent;

    color: var(--text-muted);

    font: inherit;

    font-size: 14px;

    font-weight: 600;

    cursor: pointer;

    display: flex;

    align-items: center;

    justify-content: center;

    gap: 8px;

    transition:
        background 0.2s,
        color 0.2s;
}

.tab:hover {
    color: var(--text);
}

.tab[aria-selected="true"] {
    background:
        var(--glass-strong);

    color: var(--text);

    box-shadow:
        inset 0 1px 0
        rgba(255, 255, 255, 0.2);
}

.tab__count {
    min-width: 20px;

    height: 20px;

    padding: 0 6px;

    border-radius: 99px;

    background:
        var(--accent-2);

    color: #fff;

    font-size: 11px;

    line-height: 20px;

    text-align: center;
}

.tab__count--online {
    background:
        rgba(74, 222, 128, 0.22);

    color: var(--ok);
}


/* CHAT */

.chat__list {
    height: 330px;

    overflow-y: auto;

    padding: 14px;

    display: flex;

    flex-direction: column;

    gap: 10px;

    background:
        rgba(255, 255, 255, 0.05);

    border:
        1px solid
        var(--glass-border);

    border-radius: 16px;
}

.msg {
    max-width: 84%;

    align-self: flex-start;

    padding: 9px 13px 10px;

    border-radius:
        16px 16px 16px 4px;

    background:
        rgba(255, 255, 255, 0.1);
}

.msg--me {
    align-self: flex-end;

    border-radius:
        16px 16px 4px 16px;

    background:
        linear-gradient(
            135deg,
            rgba(13, 148, 136, 0.55),
            rgba(109, 40, 217, 0.55)
        );
}

.msg--mention {
    box-shadow:
        0 0 0 1.5px var(--warn);
}

.msg__meta {
    display: flex;

    align-items: baseline;

    gap: 8px;

    margin-bottom: 3px;

    font-size: 11px;

    color: var(--text-muted);
}

.msg__name {
    font-weight: 600;

    color: var(--text);
}

.msg__del {
    margin-left: auto;

    padding: 0 2px;

    border: none;

    background: transparent;

    color: var(--text-muted);

    font-size: 15px;

    line-height: 1;

    cursor: pointer;
}

.msg__del:hover {
    color: #fca5a5;
}

.msg__body {
    font-size: 14px;

    line-height: 1.45;

    overflow-wrap: anywhere;
}

.empty {
    margin: auto;

    text-align: center;

    font-size: 14px;

    color: var(--text-muted);
}

.compose {
    display: flex;

    gap: 10px;

    margin-top: 12px;
}

.compose .control {
    flex: 1;
}

.control--plain input {
    padding: 0 16px;

    height: 50px;
}

.send {
    flex: none;

    width: 54px;

    height: 50px;

    border: none;

    border-radius:
        var(--radius-field);

    background:
        linear-gradient(
            135deg,
            var(--accent-1),
            var(--accent-2)
        );

    color: #fff;

    cursor: pointer;

    display: grid;

    place-items: center;

    transition:
        filter 0.2s,
        transform 0.1s;
}

.send:hover {
    filter: brightness(1.12);
}

.send:active {
    transform: scale(0.96);
}

.send[disabled] {
    opacity: 0.6;

    cursor: progress;
}

.counter {
    margin-top: 6px;

    text-align: right;

    font-size: 12px;

    color: var(--text-muted);
}


/* MEMBERS */

.members__meta {
    margin:
        10px 2px;

    font-size: 12px;

    color: var(--text-muted);
}

.members {
    height: 270px;

    overflow-y: auto;

    display: flex;

    flex-direction: column;

    gap: 8px;
}

.member {
    width: 100%;

    display: flex;

    align-items: center;

    gap: 12px;

    padding: 10px 12px;

    font: inherit;

    text-align: left;

    color: inherit;

    background:
        rgba(255, 255, 255, 0.06);

    border:
        1px solid transparent;

    border-radius: 14px;

    cursor: pointer;

    transition:
        background 0.2s,
        border-color 0.2s;
}

.member:hover {
    background:
        rgba(255, 255, 255, 0.12);

    border-color:
        var(--glass-border);
}

.member__avatar {
    flex: none;

    width: 36px;
    height: 36px;

    border-radius: 11px;

    display: grid;

    place-items: center;

    font-family: var(--font-display);

    font-weight: 700;

    color: #fff;
}

.member__name {
    flex: 1;

    font-size: 14px;

    font-weight: 500;

    overflow-wrap: anywhere;
}

.member__tag {
    font-size: 11px;

    color: var(--text-muted);
}

.dot {
    flex: none;

    width: 9px;
    height: 9px;

    border-radius: 50%;

    background: #64748b;
}

.dot--on {
    background: #4ade80;

    box-shadow:
        0 0 8px #4ade80;
}


/* TOAST */

.toast {
    position: fixed;

    left: 50%;

    bottom: 28px;

    z-index: 10;

    max-width:
        calc(100% - 32px);

    padding: 11px 18px;

    font-size: 14px;

    color: var(--text);

    background:
        rgba(15, 20, 40, 0.94);

    border:
        1px solid
        var(--glass-border);

    border-radius: 12px;

    opacity: 0;

    transform:
        translate(-50%, 20px);

    pointer-events: none;

    transition:
        opacity 0.25s,
        transform 0.25s;
}

.toast.show {
    opacity: 1;

    transform:
        translate(-50%, 0);
}

.toast--error {
    color: var(--danger);

    border-color:
        var(--danger-line);
}


/* ANIMATION */

@keyframes enter {
    from {
        opacity: 0;

        transform:
            translateY(24px)
            scale(0.97);
    }

    to {
        opacity: 1;

        transform: none;
    }
}

@keyframes drift {
    from {
        transform:
            translate(0, 0)
            scale(1);
    }

    to {
        transform:
            translate(6vmax, 4vmax)
            scale(1.12);
    }
}

@keyframes spin {
    to {
        transform: rotate(360deg);
    }
}


/* RESPONSIVE */

@media (max-width: 520px) {

    .glass {
        padding:
            26px 20px;
    }

    .actions {
        grid-template-columns: 1fr;
    }

    h1 {
        font-size: 28px;
    }
}

@media (prefers-reduced-motion: reduce) {

    *,
    *::before,
    *::after {
        animation: none !important;

        transition: none !important;
    }
}


/* LIGHT THEME */

body.theme-light {

    --bg: #eef4ff;

    --text: #172033;

    --text-muted:
        rgba(23, 32, 51, .65);

    --glass:
        rgba(255, 255, 255, .62);

    --glass-strong:
        rgba(255, 255, 255, .78);

    --glass-border:
        rgba(20, 35, 70, .14);
}

.theme-toggle {
    width: 38px;

    height: 38px;

    border:
        1px solid
        var(--glass-border);

    border-radius: 12px;

    background:
        var(--glass-strong);

    color: var(--text);

    cursor: pointer;

    display: grid;

    place-items: center;

    transition:
        transform .2s,
        background .2s;
}

.theme-toggle:hover {
    transform:
        translateY(-2px);

    background:
        rgba(255,255,255,.22);
}

</style>

</head>


<body>

<div class="aurora">
    <span></span>
    <span></span>
    <span></span>
</div>


{% if page in ["login", "register", "password"] %}

<div class="glass">

    <div class="topline">

        <div class="brand">

            <div class="brand__logo">
                ◈
            </div>

            <span>Glassgate</span>

        </div>

        <div
            class="status"
            id="systemStatus"
            data-state="checking"
        >
            <i></i>
            <span>Checking</span>
        </div>

    </div>


    {% if page == "login" %}

        <h1>Welcome back</h1>

        <p class="subtitle">
            Sign in to continue to your account.
        </p>

    {% elif page == "register" %}

        <h1>Create account</h1>

        <p class="subtitle">
            Create your Glassgate account.
        </p>

    {% else %}

        <h1>Change password</h1>

        <p class="subtitle">
            Keep your account secure with a new password.
        </p>

    {% endif %}


    {% if error %}

    <div class="alert">
        {{ error }}
    </div>

    {% endif %}


    {% if notice %}

    <div class="alert alert--ok">
        {{ notice }}
    </div>

    {% endif %}


    {% if page == "login" %}

    <form
        method="POST"
        action="{{ url_for('login') }}"
        data-submit
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ csrf }}"
        >

        <div class="field">

            <label for="username">
                Username
            </label>

            <div class="control">

                <span class="control__icon">
                    👤
                </span>

                <input
                    id="username"
                    name="username"
                    type="text"
                    value="{{ form_username }}"
                    placeholder="Enter username"
                    autocomplete="username"
                    maxlength="30"
                    required
                >

            </div>

        </div>


        <div class="field">

            <label for="password">
                Password
            </label>

            <div class="control">

                <span class="control__icon">
                    🔒
                </span>

                <input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="Enter password"
                    autocomplete="current-password"
                    required
                >

                <button
                    type="button"
                    class="control__toggle"
                    data-toggle-password="password"
                    aria-label="Show password"
                >
                    👁
                </button>

            </div>

        </div>


        <label class="remember">

            <input
                type="checkbox"
                name="remember"
            >

            Remember me

        </label>


        <button
            class="btn"
            type="submit"
        >

            <span class="spinner"></span>

            <span>
                Sign in
            </span>

        </button>

    </form>


    <div class="switch">

        Don't have an account?

        <a href="{{ url_for('register') }}">
            Create one
        </a>

    </div>


    {% elif page == "register" %}


    <form
        method="POST"
        action="{{ url_for('register') }}"
        data-submit
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ csrf }}"
        >


        <div class="field">

            <label for="username">
                Username
            </label>

            <div class="control">

                <span class="control__icon">
                    👤
                </span>

                <input
                    id="username"
                    name="username"
                    type="text"
                    value="{{ form_username }}"
                    placeholder="Choose a username"
                    autocomplete="username"
                    maxlength="30"
                    required
                >

            </div>

        </div>


        <div class="field">

            <label for="password">
                Password
            </label>

            <div class="control">

                <span class="control__icon">
                    🔒
                </span>

                <input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="Create a password"
                    autocomplete="new-password"
                    minlength="8"
                    required
                >

                <button
                    type="button"
                    class="control__toggle"
                    data-toggle-password="password"
                    aria-label="Show password"
                >
                    👁
                </button>

            </div>

            <div class="meter">
                <span id="strengthBar"></span>
            </div>

            <span
                class="meter__label"
                id="strengthLabel"
            >
                Use 8+ characters.
            </span>

        </div>


        <div class="field">

            <label for="confirm">
                Confirm password
            </label>

            <div class="control">

                <span class="control__icon">
                    🔐
                </span>

                <input
                    id="confirm"
                    name="confirm"
                    type="password"
                    placeholder="Repeat your password"
                    autocomplete="new-password"
                    minlength="8"
                    required
                >

            </div>

        </div>


        <button
            class="btn"
            type="submit"
        >

            <span class="spinner"></span>

            <span>
                Create account
            </span>

        </button>

    </form>


    <div class="switch">

        Already have an account?

        <a href="{{ url_for('home') }}">
            Sign in
        </a>

    </div>


    {% else %}


    <form
        method="POST"
        action="{{ url_for('change_password') }}"
        data-submit
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ csrf }}"
        >


        <div class="field">

            <label for="current">
                Current password
            </label>

            <div class="control">

                <span class="control__icon">
                    🔒
                </span>

                <input
                    id="current"
                    name="current"
                    type="password"
                    autocomplete="current-password"
                    required
                >

                <button
                    type="button"
                    class="control__toggle"
                    data-toggle-password="current"
                    aria-label="Show password"
                >
                    👁
                </button>

            </div>

        </div>


        <div class="field">

            <label for="new_password">
                New password
            </label>

            <div class="control">

                <span class="control__icon">
                    🔐
                </span>

                <input
                    id="new_password"
                    name="new_password"
                    type="password"
                    minlength="8"
                    autocomplete="new-password"
                    required
                >

                <button
                    type="button"
                    class="control__toggle"
                    data-toggle-password="new_password"
                    aria-label="Show password"
                >
                    👁
                </button>

            </div>

        </div>


        <div class="field">

            <label for="confirm">
                Confirm new password
            </label>

            <div class="control">

                <span class="control__icon">
                    🔐
                </span>

                <input
                    id="confirm"
                    name="confirm"
                    type="password"
                    minlength="8"
                    autocomplete="new-password"
                    required
                >

            </div>

        </div>


        <button
            class="btn"
            type="submit"
        >

            <span class="spinner"></span>

            <span>
                Update password
            </span>

        </button>

    </form>


    <div class="switch">

        <a href="{{ url_for('dashboard') }}">
            Back to dashboard
        </a>

    </div>


    {% endif %}

</div>


{% else %}


<div class="glass glass--wide">

    <div class="topline">

        <div class="brand">

            <div class="brand__logo">
                ◈
            </div>

            <span>Glassgate</span>

        </div>


        <div style="display:flex;align-items:center;gap:8px;">

            <button
                class="theme-toggle"
                id="themeToggle"
                type="button"
                aria-label="Toggle theme"
            >
                ☀
            </button>

            <div
                class="status"
                id="systemStatus"
                data-state="checking"
            >
                <i></i>
                <span>Checking</span>
            </div>

        </div>

    </div>


    <div class="badge">

        <i></i>

        Signed in

    </div>


    <div class="profile">

        <div class="avatar">
            {{ username[0]|upper }}
        </div>

        <div>

            <h1>
                Hello, {{ username }}
            </h1>

            <p class="subtitle">
                Welcome to your Glassgate dashboard.
            </p>

        </div>

    </div>


    <div class="tiles">

        <div class="tile">

            <small>
                Signed in
            </small>

            <b>
                {{ login_time }}
            </b>

        </div>


        <div class="tile">

            <small>
                Session
            </small>

            <b id="sessionTime">
                {{ elapsed }}s
            </b>

        </div>


        <div class="tile">

            <small>
                Registered users
            </small>

            <b>
                {{ user_count if user_count is not none else "—" }}
            </b>

        </div>


        <div class="tile">

            <small>
                Security
            </small>

            <b>
                Protected
            </b>

        </div>

    </div>


    <div class="tabs">

        <button
            class="tab"
            type="button"
            data-tab="chat"
            aria-selected="true"
        >
            💬 Chat
        </button>

        <button
            class="tab"
            type="button"
            data-tab="members"
            aria-selected="false"
        >
            👥 Members

            <span
                class="tab__count tab__count--online"
                id="onlineCount"
            >
                0
            </span>

        </button>

    </div>


    <section
        id="panel-chat"
        data-panel
    >

        <div
            class="chat__list"
            id="chatList"
        >

            <div class="empty">
                Loading messages...
            </div>

        </div>


        <form
            class="compose"
            id="messageForm"
        >

            <div class="control control--plain">

                <input
                    id="messageInput"
                    type="text"
                    maxlength="300"
                    autocomplete="off"
                    placeholder="Write a message..."
                >

            </div>


            <button
                class="send"
                id="sendButton"
                type="submit"
                aria-label="Send message"
            >
                ➤
            </button>

        </form>


        <div
            class="counter"
            id="messageCounter"
        >
            0 / 300
        </div>

    </section>


    <section
        id="panel-members"
        data-panel
        hidden
    >

        <div class="members__meta">
            Click a member to copy their username.
        </div>

        <div
            class="members"
            id="membersList"
        >

            <div class="empty">
                Loading members...
            </div>

        </div>

    </section>


    <div
        class="actions"
        style="margin-top:22px;"
    >

        <a
            class="btn btn--glass"
            href="{{ url_for('change_password') }}"
        >
            Change password
        </a>

        <a
            class="btn btn--glass"
            href="{{ url_for('logout') }}"
        >
            Sign out
        </a>

    </div>

</div>


<div
    class="toast"
    id="toast"
></div>


{% endif %}


<script>

const CSRF = {{ csrf|tojson }};

const CURRENT_USER = {{ username|default("", true)|tojson }};


function showToast(message, error = false) {

    const toast = document.getElementById("toast");

    if (!toast) {
        return;
    }

    toast.textContent = message;

    toast.classList.toggle(
        "toast--error",
        error
    );

    toast.classList.add("show");

    clearTimeout(
        window.__toastTimer
    );

    window.__toastTimer = setTimeout(
            () => toast.classList.remove("show"),
            3000
        );
}


async function checkHealth() {

    const status = document.getElementById("systemStatus");

    if (!status) {
        return;
    }

    try {

        const response = await fetch("/health", {
                cache: "no-store"
            });

        const data = await response.json();

        const online = response.ok &&
            data.server &&
            data.database;

        status.dataset.state = online
                ? "online"
                : "offline";

        status.querySelector("span")
            .textContent = online
                    ? "Online"
                    : "Database offline";

    } catch {

        status.dataset.state = "offline";

        status.querySelector("span")
            .textContent = "Offline";
    }
}


document.querySelectorAll(
    "[data-toggle-password]"
).forEach(button => {

    button.addEventListener(
        "click",
        () => {

            const id = button.dataset.togglePassword;

            const input = document.getElementById(id);

            if (!input) {
                return;
            }

            const showing = input.type === "text";

            input.type = showing
                    ? "password"
                    : "text";

            button.textContent = showing
                    ? "👁"
                    : "🙈";

            button.setAttribute(
                "aria-label",
                showing
                    ? "Show password"
                    : "Hide password"
            );
        }
    );

});


document.querySelectorAll(
    "[data-submit]"
).forEach(form => {

    form.addEventListener(
        "submit",
        () => {

            const button = form.querySelector(
                    "button[type='submit']"
                );

            if (!button) {
                return;
            }

            button.classList.add(
                "is-loading"
            );

            button.disabled = true;
        }
    );

});


const passwordInput = document.getElementById("password");

const strengthBar = document.getElementById("strengthBar");

const strengthLabel = document.getElementById("strengthLabel");


function updateStrength() {

    if (
        !passwordInput ||
        !strengthBar ||
        !strengthLabel
    ) {
        return;
    }

    const value = passwordInput.value;

    let score = 0;

    if (value.length >= 8) {
        score++;
    }

    if (/[A-Z]/.test(value)) {
        score++;
    }

    if (/[a-z]/.test(value)) {
        score++;
    }

    if (/[0-9]/.test(value)) {
        score++;
    }

    if (/[^A-Za-z0-9]/.test(value)) {
        score++;
    }

    const widths = [
            "0%",
            "20%",
            "40%",
            "60%",
            "80%",
            "100%"
        ];

    const labels = [
            "Use 8+ characters.",
            "Very weak",
            "Weak",
            "Medium",
            "Strong",
            "Very strong"
        ];

    strengthBar.style.width = widths[score];

    strengthLabel.textContent = labels[score];

    if (score <= 1) {

        strengthBar.style.background = "#f87171";

    } else if (score <= 3) {

        strengthBar.style.background = "#fbbf24";

    } else {

        strengthBar.style.background = "#4ade80";
    }
}


if (passwordInput) {

    passwordInput.addEventListener(
        "input",
        updateStrength
    );

    updateStrength();
}


const themeToggle = document.getElementById("themeToggle");


if (themeToggle) {

    const savedTheme = localStorage.getItem(
            "glassgate-theme"
        );

    if (savedTheme === "light") {

        document.body.classList.add(
            "theme-light"
        );

        themeToggle.textContent = "🌙";
    }


    themeToggle.addEventListener(
        "click",
        () => {

            const light = document.body.classList.toggle(
                    "theme-light"
                );

            localStorage.setItem(
                "glassgate-theme",
                light
                    ? "light"
                    : "dark"
            );

            themeToggle.textContent = light
                    ? "🌙"
                    : "☀";
        }
    );
}


/* ===================================================== DASHBOARD
   ===================================================== */

let sessionSeconds = {{ elapsed|default(0, true) }};


function updateSessionTimer() {

    const element = document.getElementById(
            "sessionTime"
        );

    if (!element) {
        return;
    }

    sessionSeconds++;

    element.textContent = sessionSeconds + "s";
}


setInterval(
    updateSessionTimer,
    1000
);


/* ===================================================== TABS
   ===================================================== */

document.querySelectorAll(
    ".tab"
).forEach(tab => {

    tab.addEventListener(
        "click",
        () => {

            const name = tab.dataset.tab;

            document.querySelectorAll(
                ".tab"
            ).forEach(item => {

                item.setAttribute(
                    "aria-selected",
                    item === tab
                        ? "true"
                        : "false"
                );
            });


            document.querySelectorAll(
                "[data-panel]"
            ).forEach(panel => {

                panel.hidden = panel.id !==
                    "panel-" + name;
            });


            if (name === "members") {
                loadMembers();
            }

            if (name === "chat") {
                loadMessages();
            }
        }
    );

});


/* ===================================================== CHAT
   ===================================================== */

const chatList = document.getElementById(
        "chatList"
    );

const messageForm = document.getElementById(
        "messageForm"
    );

const messageInput = document.getElementById(
        "messageInput"
    );

const messageCounter = document.getElementById(
        "messageCounter"
    );

const sendButton = document.getElementById(
        "sendButton"
    );


function escapeHtml(value) {

    const div = document.createElement(
            "div"
        );

    div.textContent = value;

    return div.innerHTML;
}


function renderMessages(messages) {

    if (!chatList) {
        return;
    }

    if (!messages.length) {

        chatList.innerHTML = '<div class="empty">' +'No messages yet. Start the conversation.' +
            '</div>';

        return;
    }


    chatList.innerHTML = messages.map(message => {

            const mine = message.username ===
                CURRENT_USER;

            const mention = CURRENT_USER &&
                message.body
                    .toLowerCase()
                    .includes(
                        "@" +
                        CURRENT_USER.toLowerCase()
                    );

            return `
                <div class="msg ${
                    mine ? "msg--me" : ""
                } ${
                    mention ? "msg--mention" : ""
                }">

                    <div class="msg__meta">

                        <span class="msg__name">
                            ${escapeHtml(message.username)}
                        </span>

                        <span>
                            ${escapeHtml(message.time)}
                        </span>

                        ${
                            mine
                                ? `
                                    <button
                                        class="msg__del"
                                        type="button"
                                        data-delete-message="${message.id}"
                                        aria-label="Delete message"
                                    >
                                        ×
                                    </button>
                                `
                                : ""
                        }

                    </div>

                    <div class="msg__body">
                        ${escapeHtml(message.body)}
                    </div>

                </div>
            `;

        }).join("");

    chatList.scrollTop = chatList.scrollHeight;
}


async function loadMessages() {

    if (!chatList) {
        return;
    }

    try {

        const response = await fetch(
                "/api/messages",
                {
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            const data = await response.json()
                    .catch(() => ({}));

            throw new Error(
                data.error ||
                "Could not load messages."
            );
        }

        const data = await response.json();

        renderMessages(
            data.messages || []
        );

    } catch (error) {

        chatList.innerHTML = `<div class="empty">
                ${escapeHtml(error.message)}
             </div>`;
    }
}


if (messageInput) {

    messageInput.addEventListener(
        "input",
        () => {

            if (messageCounter) {

                messageCounter.textContent = messageInput.value.length +
                    " / 300";
            }
        }
    );
}


if (messageForm) {

    messageForm.addEventListener(
        "submit",
        async event => {

            event.preventDefault();

            const body = messageInput.value.trim();

            if (!body) {

                showToast(
                    "Type a message first.",
                    true
                );

                return;
            }

            sendButton.disabled = true;

            try {

                const response = await fetch(
                        "/api/messages",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json",

                                "X-CSRF-Token":
                                    CSRF
                            },

                            body:
                                JSON.stringify({
                                    body
                                })
                        }
                    );

                const data = await response.json()
                        .catch(() => ({}));

                if (!response.ok) {

                    throw new Error(
                        data.error ||
                        "Could not send message."
                    );
                }

                messageInput.value = "";

                if (messageCounter) {

                    messageCounter.textContent = "0 / 300";
                }

                await loadMessages();

            } catch (error) {

                showToast(
                    error.message,
                    true
                );

            } finally {

                sendButton.disabled = false;

                messageInput.focus();
            }
        }
    );
}


if (chatList) {

    chatList.addEventListener(
        "click",
        async event => {

            const button = event.target.closest(
                    "[data-delete-message]"
                );

            if (!button) {
                return;
            }

            const id = button.dataset.deleteMessage;

            try {

                const response = await fetch(
                        "/api/messages/" + id,
                        {
                            method: "DELETE",

                            headers: {
                                "X-CSRF-Token":
                                    CSRF
                            }
                        }
                    );

                const data = await response.json()
                        .catch(() => ({}));

                if (!response.ok) {

                    throw new Error(
                        data.error ||
                        "Could not delete message."
                    );
                }

                await loadMessages();

            } catch (error) {

                showToast(
                    error.message,
                    true
                );
            }
        }
    );
}


/* ===================================================== MEMBERS
   ===================================================== */

const membersList = document.getElementById(
        "membersList"
    );

const onlineCount = document.getElementById(
        "onlineCount"
    );


function avatarColor(username) {

    let hash = 0;

    for (
        let i = 0;
        i < username.length;
        i++
    ) {
        hash = username.charCodeAt(i) +
            ((hash << 5) - hash);
    }

    const colors = [
            "#0d9488",
            "#2563eb",
            "#7c3aed",
            "#db2777",
            "#ea580c",
            "#0891b2"
        ];

    return colors[
        Math.abs(hash) %
        colors.length
    ];
}


function renderMembers(members) {

    if (!membersList) {
        return;
    }

    const online = members.filter(
            member => member.online
        ).length;

    if (onlineCount) {
        onlineCount.textContent = online;
    }


    if (!members.length) {

        membersList.innerHTML = '<div class="empty">' +'No members found.' +
            '</div>';

        return;
    }


    membersList.innerHTML = members.map(member => {

            const initial = member.username
                    .charAt(0)
                    .toUpperCase();

            return `
                <button
                    class="member"
                    type="button"
                    data-username="${escapeHtml(member.username)}"
                >

                    <span
                        class="member__avatar"
                        style="background:${avatarColor(member.username)}"
                    >
                        ${escapeHtml(initial)}
                    </span>

                    <span class="member__name">
                        ${escapeHtml(member.username)}
                    </span>

                    ${
                        member.me
                            ? `
                                <span class="member__tag">
                                    You
                                </span>
                            `
                            : ""
                    }

                    <span
                        class="dot ${
                            member.online
                                ? "dot--on"
                                : ""
                        }"
                    ></span>

                </button>
            `;

        }).join("");
}


async function loadMembers() {

    if (!membersList) {
        return;
    }

    try {

        const response = await fetch(
                "/api/members",
                {
                    cache: "no-store"
                }
            );

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Could not load members."
            );
        }

        renderMembers(
            data.members || []
        );

    } catch (error) {

        membersList.innerHTML = `<div class="empty">
                ${escapeHtml(error.message)}
             </div>`;
    }
}


if (membersList) {

    membersList.addEventListener(
        "click",
        async event => {

            const button = event.target.closest(
                    "[data-username]"
                );

            if (!button) {
                return;
            }

            const username = button.dataset.username;

            try {

                await navigator.clipboard.writeText(
                    username
                );

                showToast(
                    "Username copied."
                );

            } catch {

                showToast(
                    username
                );
            }
        }
    );
}


/* INITIAL LOAD */

checkHealth();

if (chatList) {
    loadMessages();
}

if (membersList) {
    loadMembers();
}


/* Refresh */

setInterval(
    checkHealth,
    15000
);

setInterval(
    () => {

        if (
            document.getElementById(
                "panel-chat"
            ) &&
            !document.getElementById(
                "panel-chat"
            ).hidden
        ) {
            loadMessages();
        }

    },
    5000
);

setInterval(
    () => {

        if (
            document.getElementById(
                "panel-members"
            ) &&
            !document.getElementById(
                "panel-members"
            ).hidden
        ) {
            loadMembers();
        }

    },
    10000
);

</script>

</body>

</html>
"""


# ========================================================= # ROUTES
# =========================================================

@app.route("/")
def home():

    if "user" in session:
        return redirect(
            url_for("dashboard")
        )

    return render("login")


@app.route("/health")
def health():

    database_ok = False

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute("SELECT 1")

        cursor.fetchone()

        database_ok = True

    except mysql.connector.Error:

        database_ok = False

    finally:

        close_all(
            cursor,
            connection
        )

    return jsonify(
        server=True,
        database=database_ok
    )


@app.route("/login", methods=["POST"])
def login():

    username = request.form.get(
            "username",
            ""
        ).strip()

    password = request.form.get(
            "password",
            ""
        )

    if not csrf_ok():

        return render(
            "login",
            form_username=username,
            error= "This page expired. Reload it and try again."
        )

    if not username or not password:

        return render(
            "login",
            form_username=username,
            error= "Enter both your username and password."
        )

    key = attempt_key(username)

    wait = lock_remaining(key)

    if wait:

        return render(
            "login",
            form_username=username,
            error= f"Too many failed attempts. "f"Try again in {wait} seconds."
        )

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
                dictionary=True
            )

        cursor.execute(
            """
            SELECT id, username, password
            FROM users
            WHERE username = %s
            LIMIT 1
            """,
            (username,)
        )

        user = cursor.fetchone()

        if (
            user
            and password_matches(
                user["password"],
                password
            )
        ):

            ATTEMPTS.pop(
                key,
                None
            )

            session.clear()

            session.permanent = True

            session["user"] = user["username"]

            session["login_time"] = datetime.now().strftime(
                    "%d %b, %I:%M %p"
                )

            session["login_ts"] = time.time()

            return redirect(
                url_for("dashboard")
            )


        left = record_failure(key)

        if left > 0:

            message = f"Username or password is incorrect. "f"{left} attempt"f"{'s' if left != 1 else ''} left."

        else:

            message = f"Too many failed attempts. "f"Try again in {LOCK_SECONDS} seconds."

        return render(
            "login",
            form_username=username,
            error=message
        )


    except mysql.connector.Error as e:

        print(
            "Database error:",
            e
        )

        return render(
            "login",
            form_username=username,
            error= "We could not reach the database. ""Make sure MySQL is running and try again."
        )

    finally:

        close_all(
            cursor,
            connection
        )


@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if "user" in session:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "GET":

        return render("register")


    username = request.form.get(
            "username",
            ""
        ).strip()

    password = request.form.get(
            "password",
            ""
        )

    confirm = request.form.get(
            "confirm",
            ""
        )


    def fail(message):

        return render(
            "register",
            form_username=username,
            error=message
        )


    if not csrf_ok():

        return fail(
            "This page expired. Reload it and try again."
        )


    if not USERNAME_RULE.match(username):

        return fail(
            "Username must be 3 to 30 characters: "
            "letters, numbers, . or _ only."
        )


    if len(password) < 8:

        return fail(
            "Password must be at least 8 characters."
        )


    if password != confirm:

        return fail(
            "The two passwords do not match."
        )


    connection = None
    cursor = None


    try:

        connection = get_db_connection()

        cursor = connection.cursor()


        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE username = %s
            LIMIT 1
            """,
            (username,)
        )


        if cursor.fetchone():

            return fail(
                "That username is taken. "
                "Choose another one."
            )


        hashed_password = generate_password_hash(
                password,
                method="pbkdf2:sha256"
            )


        cursor.execute(
            """
            INSERT INTO users
                (username, password)
            VALUES
                (%s, %s)
            """,
            (
                username,
                hashed_password
            )
        )


        connection.commit()


        session["notice"] = "Account created. ""Sign in to continue."


        return redirect(
            url_for("home")
        )


    except mysql.connector.Error as e:

        print(
            "Database error:",
            e
        )


        if e.errno == 1406:

            return fail(
                COLUMN_TOO_SHORT
            )


        if e.errno == 1062:

            return fail(
                "That username is taken. "
                "Choose another one."
            )


        return fail(
            "We could not create the account. "
            "Make sure MySQL is running and try again."
        )


    finally:

        close_all(
            cursor,
            connection
        )


@app.route("/dashboard")
def dashboard():

    if "user" not in session:

        return redirect(
            url_for("home")
        )


    elapsed = int(
            time.time()
            -
            session.get(
                "login_ts",
                time.time()
            )
        )


    return render(
        "dashboard",

        username= session["user"],

        login_time= session.get(
                "login_time",
                ""
            ),

        elapsed= max(
                elapsed,
                0
            ),

        user_count= count_users()
    )


@app.route(
    "/change-password",
    methods=["GET", "POST"]
)
def change_password():

    if "user" not in session:

        return redirect(
            url_for("home")
        )


    if request.method == "GET":

        return render("password")


    current = request.form.get(
            "current",
            ""
        )

    new = request.form.get(
            "new_password",
            ""
        )

    confirm = request.form.get(
            "confirm",
            ""
        )


    def fail(message):

        return render(
            "password",
            error=message
        )


    if not csrf_ok():

        return fail(
            "This page expired. Reload it and try again."
        )


    if len(new) < 8:

        return fail(
            "New password must be at least 8 characters."
        )


    if new != confirm:

        return fail(
            "The two new passwords do not match."
        )


    if new == current:

        return fail(
            "Choose a password different from your current one."
        )


    connection = None
    cursor = None


    try:

        connection = get_db_connection()

        cursor = connection.cursor(
                dictionary=True
            )


        cursor.execute(
            """
            SELECT password
            FROM users
            WHERE username = %s
            LIMIT 1
            """,
            (session["user"],)
        )


        row = cursor.fetchone()


        if (
            not row
            or not password_matches(
                row["password"],
                current
            )
        ):

            return fail(
                "Your current password is incorrect."
            )


        hashed_password = generate_password_hash(
                new,
                method="pbkdf2:sha256"
            )


        cursor.execute(
            """
            UPDATE users
            SET password = %s
            WHERE username = %s
            """,
            (
                hashed_password,
                session["user"]
            )
        )


        connection.commit()


        session["notice"] = "Password updated."


        return redirect(
            url_for("dashboard")
        )


    except mysql.connector.Error as e:

        print(
            "Database error:",
            e
        )


        if e.errno == 1406:

            return fail(
                COLUMN_TOO_SHORT
            )


        return fail(
            "We could not update the password. "
            "Make sure MySQL is running and try again."
        )


    finally:

        close_all(
            cursor,
            connection
        )


# ========================================================= # API
# =========================================================

@app.route("/api/members")
def api_members():

    if "user" not in session:

        return api_error(
            "Sign in required.",
            401
        )


    connection = None
    cursor = None


    try:

        connection = get_db_connection()

        cursor = connection.cursor()


        cursor.execute(
            """
            SELECT username
            FROM users
            ORDER BY username
            LIMIT 200
            """
        )


        names = [
                row[0]
                for row in cursor.fetchall()
            ]


    except mysql.connector.Error as e:

        print(
            "Database error:",
            e
        )

        return api_error(
            "Could not load members.",
            500
        )


    finally:

        close_all(
            cursor,
            connection
        )


    now = time.time()


    members = [
            {
                "username": name,

                "online":
                    now
                    -
                    LAST_SEEN.get(
                        name,
                        0
                    )
                    <
                    ONLINE_WINDOW,

                "me":
                    name
                    == session["user"],
            }

            for name in names
        ]


    members.sort(
        key=lambda m: (
            not m["online"],
            m["username"].lower()
        )
    )


    return jsonify(
        members=members
    )


@app.route(
    "/api/messages",
    methods=["GET", "POST"]
)
def api_messages():

    if "user" not in session:

        return api_error(
            "Sign in required.",
            401
        )


    if not ensure_messages():

        return api_error(
            "Chat is unavailable. "
            "Check that MySQL is running.",
            503
        )


    connection = None
    cursor = None


    try:

        connection = get_db_connection()


        if request.method == "GET":

            cursor = connection.cursor(
                    dictionary=True
                )


            cursor.execute(
                """
                SELECT
                    id,
                    username,
                    body,
                    created_at
                FROM (
                    SELECT
                        id,
                        username,
                        body,
                        created_at
                    FROM messages
                    ORDER BY id DESC
                    LIMIT 50
                ) AS recent
                ORDER BY id ASC
                """
            )


            rows = cursor.fetchall()


            return jsonify(
                messages= [
                        {
                            "id": r["id"],

                            "username":
                                r["username"],

                            "body":
                                r["body"],

                            "time":
                                pretty_time(
                                    r["created_at"]
                                ),
                        }

                        for r in rows
                    ]
            )


        if not csrf_header_ok():

            return api_error(
                "This page expired. Reload it and try again.",
                403
            )


        data = request.get_json(
                silent=True
            ) or {}


        body = re.sub(
                r"[\x00-\x1f\x7f]",
                " ",
                str(
                    data.get(
                        "body",
                        ""
                    )
                )
            ).strip()


        if not body:

            return api_error(
                "Type a message first.",
                400
            )


        if len(body) > 300:

            return api_error(
                "Messages can be up to 300 characters.",
                400
            )


        limited = too_fast(
                session["user"]
            )


        if limited:

            return api_error(
                limited,
                429
            )


        cursor = connection.cursor()


        cursor.execute(
            """
            INSERT INTO messages
                (username, body)
            VALUES
                (%s, %s)
            """,
            (
                session["user"],
                body
            )
        )


        connection.commit()


        return jsonify(
            ok=True
        )


    except mysql.connector.Error as e:

        print(
            "Database error:",
            e
        )

        return api_error(
            "Something went wrong with the database.",
            500
        )


    finally:

        close_all(
            cursor,
            connection
        )


@app.route(
    "/api/messages/<int:message_id>",
    methods=["DELETE"]
)
def api_delete_message(message_id):

    if "user" not in session:

        return api_error(
            "Sign in required.",
            401
        )


    if not csrf_header_ok():

        return api_error(
            "This page expired. Reload it and try again.",
            403
        )


    if not ensure_messages():

        return api_error(
            "Chat is unavailable. "
            "Check that MySQL is running.",
            503
        )


    connection = None
    cursor = None


    try:

        connection = get_db_connection()

        cursor = connection.cursor()


        cursor.execute(
            """
            DELETE FROM messages
            WHERE id = %s
              AND username = %s
            """,
            (
                message_id,
                session["user"]
            )
        )


        connection.commit()


        if cursor.rowcount == 0:

            return api_error(
                "You can only delete your own messages.",
                404
            )


        return jsonify(
            ok=True
        )


    except mysql.connector.Error as e:

        print(
            "Database error:",
            e
        )

        return api_error(
            "Something went wrong with the database.",
            500
        )


    finally:

        close_all(
            cursor,
            connection
        )


@app.route("/logout")
def logout():

    LAST_SEEN.pop(
        session.get("user"),
        None
    )

    session.clear()

    return redirect(
        url_for("home")
    )


# ========================================================= # START APPLICATION
# =========================================================

init_db()


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
