#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Stabil sürüm (hata-önleyici düzeltmeler yapıldı)
Çalıştırma: HF_API_KEY ve GROQ_API_KEY environment'a eklenecek.
"""

import os
import sqlite3
import json
from datetime import datetime
from functools import wraps

import requests
from flask import (
    Flask, request, g, session, redirect, url_for, flash, jsonify, send_from_directory
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------
# Ayarlar
# ----------------------------
DATABASE = os.environ.get("DATABASE", "kralzeka.db")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
HF_API_KEY = os.environ.get("HF_API_KEY", "")        # user provides
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")    # user provides
SECRET_KEY = os.environ.get("SECRET_KEY", "change_me_in_env")
PORT = int(os.environ.get("PORT", 5000))

# Model ayarları
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3-8b-instruct")
GROQ_ENDPOINT = os.environ.get("GROQ_ENDPOINT", "https://api.groq.com/v1")
HF_TEXT_MODEL = os.environ.get("HF_TEXT_MODEL", "meta-llama/Llama-3-8b-instruct")
HF_IMAGE_MODEL = os.environ.get("HF_IMAGE_MODEL", "stabilityai/stable-diffusion-2")

DAILY_QUALITY_LIMIT = int(os.environ.get("DAILY_QUALITY_LIMIT", 5))
ADMIN_USER = os.environ.get("INITIAL_ADMIN_USER", "enes")
ADMIN_PASS = os.environ.get("INITIAL_ADMIN_PASS", "enes1357924680")

# ----------------------------
# Flask app
# ----------------------------
app = Flask(__name__)
app.config.update(
    DATABASE=DATABASE,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SECRET_KEY=SECRET_KEY,
)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ----------------------------
# DB yardımcıları
# ----------------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(app.config['DATABASE'], timeout=30)
        db.row_factory = sqlite3.Row
        g._db = db
    return db

@app.teardown_appcontext
def close_db(error=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()
        g._db = None

def now_iso():
    return datetime.utcnow().isoformat()

def init_db(force=False):
    """DB init. executescript tek argüman alır; bunu doğru kullan."""
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        if force:
            cur.executescript("""
                DROP TABLE IF EXISTS users;
                DROP TABLE IF EXISTS messages;
                DROP TABLE IF EXISTS admin_actions;
                DROP TABLE IF EXISTS requests_log;
            """)
            db.commit()
        # create tables; sabitleri Python ile yerleştiriyoruz
        sql = f"""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            quota_quality_daily INTEGER NOT NULL DEFAULT {DAILY_QUALITY_LIMIT},
            created_at TEXT NOT NULL,
            last_seen TEXT,
            protected INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            role TEXT,
            content TEXT,
            response TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS admin_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user TEXT,
            action TEXT,
            target_user TEXT,
            extra TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS requests_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            endpoint TEXT,
            payload TEXT,
            response TEXT,
            status INTEGER,
            created_at TEXT
        );
        """
        cur.executescript(sql)
        db.commit()
        # İlk admini oluştur (korumalı)
        cur.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,))
        if not cur.fetchone():
            now = now_iso()
            pw_hash = generate_password_hash(ADMIN_PASS)
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin, quota_quality_daily, created_at, protected) VALUES (?, ?, 1, ?, ?, 1)",
                (ADMIN_USER, pw_hash, DAILY_QUALITY_LIMIT, now)
            )
            db.commit()

# ----------------------------
# Auth dekoratörleri
# ----------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(ok=False, error="Giriş gerekli."), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return jsonify(ok=False, error="Giriş gerekli."), 401
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT is_admin FROM users WHERE id=?", (uid,))
        r = cur.fetchone()
        if not r or r["is_admin"] != 1:
            return jsonify(ok=False, error="Yetki yok."), 403
        return f(*args, **kwargs)
    return decorated

def current_user_obj():
    uid = session.get("user_id")
    if not uid: return None
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    r = cur.fetchone()
    return r

# ----------------------------
# Logging helpers
# ----------------------------
def record_request(username, endpoint, payload, response, status):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO requests_log (username, endpoint, payload, response, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (username, endpoint, json.dumps(payload, ensure_ascii=False), json.dumps(response, ensure_ascii=False), status, now_iso())
        )
        db.commit()
    except Exception:
        app.logger.exception("requests_log yazma hatası")

def record_message(user_id, username, role, content, response):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO messages (user_id, username, role, content, response, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, username, role, content, response, now_iso())
        )
        db.commit()
    except Exception:
        app.logger.exception("messages yazma hatası")

def add_admin_action(admin_user, action, target_user=None, extra=None):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO admin_actions (admin_user, action, target_user, extra, created_at) VALUES (?, ?, ?, ?, ?)",
            (admin_user, action, target_user or "", extra or "", now_iso())
        )
        db.commit()
    except Exception:
        app.logger.exception("admin_actions yazma hatası")

# ----------------------------
# Model çağrıları (Groq -> HF fall-back)
# ----------------------------
def call_groq(prompt, model=GROQ_MODEL, max_tokens=512):
    """Groq çağrısı. Hata yakalama ve parse ile güvenle çalışır."""
    if not GROQ_API_KEY:
        return False, "GROQ_API_KEY tanımlı değil."
    url = f"{GROQ_ENDPOINT}/models/{model}/generate"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {"prompt": prompt, "max_output_tokens": max_tokens}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        if r.status_code != 200:
            # dönen JSON varsa parse et
            try:
                return False, f"Groq hata {r.status_code}: {r.json()}"
            except Exception:
                return False, f"Groq hata {r.status_code}: {r.text}"
        # başarılıysa JSON parse
        try:
            j = r.json()
            # farklı yapı olabileceğinden birkaç yer dene
            if isinstance(j, dict):
                if "text" in j:
                    return True, j["text"]
                if "outputs" in j and isinstance(j["outputs"], list):
                    # concat içerikleri
                    out = ""
                    for o in j["outputs"]:
                        if isinstance(o, dict):
                            out += o.get("content", "") or o.get("text", "")
                        elif isinstance(o, str):
                            out += o
                    if out:
                        return True, out
            # fallback: düz metin
            return True, r.text
        except Exception:
            return True, r.text
    except Exception as e:
        return False, f"Groq isteği başarısız: {e}"

def call_hf_text(prompt, model=HF_TEXT_MODEL):
    if not HF_API_KEY:
        return False, "HF_API_KEY tanımlı değil."
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        if r.status_code != 200:
            try:
                return False, f"HF hata {r.status_code}: {r.json()}"
            except Exception:
                return False, f"HF hata {r.status_code}: {r.text}"
        try:
            j = r.json()
            if isinstance(j, list) and len(j) > 0 and isinstance(j[0], dict) and "generated_text" in j[0]:
                return True, j[0]["generated_text"]
            if isinstance(j, dict) and "generated_text" in j:
                return True, j["generated_text"]
            # fallback:
            return True, r.text
        except Exception:
            return True, r.text
    except Exception as e:
        return False, f"HF isteği başarısız: {e}"

def ask_kral(prompt, username):
    # Önce Groq
    ok, resp = call_groq(prompt)
    if ok:
        return True, resp, "groq"
    # Groq başarısızsa HF
    ok2, resp2 = call_hf_text(prompt)
    if ok2:
        return True, resp2, "huggingface"
    # her ikisi de başarısızsa hata döndür
    return False, f"Groq: {resp} | HF: {resp2}", "none"

# ----------------------------
# Yardımcı: dosya kontrol
# ----------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------------------
# Basit HTTP API (frontend yerine API kullanalım)
# ----------------------------
@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    mode = data.get("mode") or "chat"
    if not prompt:
        return jsonify(ok=False, error="Boş prompt."), 400
    user = current_user_obj()
    username = user["username"] if user else "anon"
    # mode'a göre sistem mesajı
    if mode == "homework":
        prompt2 = "Ödev modu - adım adım ve açıklayıcı: " + prompt
    elif mode == "joke":
        prompt2 = "Şaka modu - eğlenceli kısa şaka: " + prompt
    else:
        prompt2 = prompt
    success, response_text, engine = ask_kral(prompt2, username)
    # log & kaydet
    record_request(username, "/api/chat", {"prompt":prompt,"mode":mode}, {"engine":engine,"resp":response_text if success else ""}, 200 if success else 500)
    record_message(user_id=user["id"] if user else None, username=username, role="user", content=prompt, response=response_text if success else "")
    if success:
        return jsonify(ok=True, engine=engine, response=response_text)
    else:
        return jsonify(ok=False, error=response_text), 500

# Upload endpoint
@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    if "file" not in request.files:
        return jsonify(ok=False, error="file yok"), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify(ok=False, error="dosya adı boş"), 400
    if not allowed_file(f.filename):
        return jsonify(ok=False, error="izinli dosya değil"), 400
    filename = secure_filename(f.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(path)
    # basit cevap
    return jsonify(ok=True, filename=filename)

# Auth (basit)
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
    r = cur.fetchone()
    if not r or not check_password_hash(r["password_hash"], password):
        return jsonify(ok=False, error="Kullanıcı/şifre hatalı"), 401
    session.clear()
    session["user_id"] = r["id"]
    cur.execute("UPDATE users SET last_seen=? WHERE id=?", (now_iso(), r["id"]))
    db.commit()
    return jsonify(ok=True)

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    pw = data.get("password") or ""
    pw2 = data.get("password2") or ""
    if not username or not pw or pw != pw2:
        return jsonify(ok=False, error="Bilgiler hatalı"), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash, is_admin, quota_quality_daily, created_at) VALUES (?, ?, 0, ?, ?)",
                    (username, generate_password_hash(pw), DAILY_QUALITY_LIMIT, now_iso()))
        db.commit()
        return jsonify(ok=True)
    except sqlite3.IntegrityError:
        return jsonify(ok=False, error="Kullanıcı adı alınmış"), 409

# Admin endpoints
@app.route("/api/admin/users", methods=["GET"])
@admin_required
def api_admin_users():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, is_admin, quota_quality_daily, created_at, protected FROM users ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify(ok=True, users=rows)

@app.route("/api/admin/action", methods=["POST"])
@admin_required
def api_admin_action():
    data = request.get_json() or {}
    action = data.get("action")
    target = data.get("username")
    admin = current_user_obj()
    if not action or not target:
        return jsonify(ok=False, error="Eksik param"), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, protected, is_admin FROM users WHERE username=?", (target,))
    r = cur.fetchone()
    if not r:
        return jsonify(ok=False, error="Kullanıcı yok"), 404
    if r["protected"] == 1:
        add_admin_action(admin["username"], f"attempt_{action}_protected", target_user=target, extra="denied")
        return jsonify(ok=False, error="Bu kullanıcı korunuyor"), 403
    if action == "promote":
        cur.execute("UPDATE users SET is_admin=1 WHERE username=?", (target,))
        db.commit()
        add_admin_action(admin["username"], "promote", target_user=target)
        return jsonify(ok=True)
    if action == "demote":
        cur.execute("UPDATE users SET is_admin=0 WHERE username=?", (target,))
        db.commit()
        add_admin_action(admin["username"], "demote", target_user=target)
        return jsonify(ok=True)
    if action == "delete":
        cur.execute("DELETE FROM users WHERE username=?", (target,))
        db.commit()
        add_admin_action(admin["username"], "delete", target_user=target)
        return jsonify(ok=True)
    return jsonify(ok=False, error="Bilinmeyen işlem"), 400

# Health
@app.route("/health")
def health():
    return jsonify(status="ok", time=now_iso())

# ----------------------------
# Başlatma (context içinde init_db çağrısı)
# ----------------------------
def start_app():
    try:
        with app.app_context():
            init_db(force=False)
        app.run(host="0.0.0.0", port=PORT)
    except Exception as e:
        # Log ve exit
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    start_app()
