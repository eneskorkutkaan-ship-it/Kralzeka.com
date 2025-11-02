#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 — Tek dosya Flask uygulaması
- Groq öncelikli, Hugging Face fallback
- Admin (enes) korunur; kod-yazma sohbeti sadece enes'e özel
- Görsel oluşturma/kalite arttırma HF ile (admin sınırsız, kullanıcı günlük 5)
- Tek dosya, Render ile gunicorn kralzeka_app:app çalıştırılacak şekilde hazırlandı
"""

import os
import sqlite3
import json
import uuid
import time
import traceback
from datetime import datetime, date
from functools import wraps

import requests
from flask import (
    Flask, g, request, session, redirect, url_for, render_template_string,
    flash, jsonify, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ----------------------------
# CONFIG
# ----------------------------
DB_PATH = os.environ.get("KZ_DB_PATH", os.path.join(os.path.dirname(__file__), "kralzeka.db"))
UPLOAD_FOLDER = os.environ.get("KZ_UPLOADS", os.path.join(os.path.dirname(__file__), "uploads"))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

FLASK_SECRET = os.environ.get("FLASK_SECRET", os.urandom(24).hex())
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
HF_API_KEY = os.environ.get("HF_API_KEY", "").strip()

# Models / endpoints (default values; change via env if needed)
GROQ_MODEL = os.environ.get("GROQ_MODEL", "grok-1")
GROQ_ENDPOINT = os.environ.get("GROQ_ENDPOINT", "https://api.groq.com/v1")
HF_TEXT_MODEL = os.environ.get("HF_TEXT_MODEL", "meta-llama/Llama-3-8b-instruct")
HF_IMAGE_MODEL = os.environ.get("HF_IMAGE_MODEL", "stabilityai/stable-diffusion-2")  # example

# Limits
DAILY_IMAGE_LIMIT = int(os.environ.get("DAILY_IMAGE_LIMIT", 5))
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "gif"}
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 16))

# First admin
FIRST_ADMIN_USERNAME = os.environ.get("KZ_FIRST_ADMIN_USER", "enes")
FIRST_ADMIN_PASSWORD = os.environ.get("KZ_FIRST_ADMIN_PASS", "enes1357924680")

# Flask app
app = Flask(__name__)
app.config.update(SECRET_KEY=FLASK_SECRET, MAX_CONTENT_LENGTH=MAX_UPLOAD_MB*1024*1024, UPLOAD_FOLDER=UPLOAD_FOLDER)

# ----------------------------
# DATABASE HELPERS
# ----------------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, timeout=30, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db:
        db.close()
        g._db = None

def init_db(force=False):
    """Initialize DB schema. Use app.app_context() when called outside request."""
    db = get_db()
    cur = db.cursor()
    if force:
        cur.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS usage;
        DROP TABLE IF EXISTS admin_events;
        DROP TABLE IF EXISTS logs;
        """)
        db.commit()
    cur.executescript(f"""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT,
        image_quota_reset TEXT DEFAULT NULL,
        protected INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        role TEXT, -- user/assistant/system
        content TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        feature TEXT,
        count INTEGER DEFAULT 0,
        last_used TEXT
    );
    CREATE TABLE IF NOT EXISTS admin_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT,
        action TEXT,
        target TEXT,
        details TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        tb TEXT,
        created_at TEXT
    );
    """)
    db.commit()
    # create first admin if not exists
    cur.execute("SELECT id FROM users WHERE username = ?", (FIRST_ADMIN_USERNAME,))
    if not cur.fetchone():
        pw_hash = generate_password_hash(FIRST_ADMIN_PASSWORD)
        now = datetime.utcnow().isoformat()
        cur.execute("INSERT INTO users (username, password_hash, is_admin, created_at, image_quota_reset, protected) VALUES (?,?,?,?,?,1)",
                    (FIRST_ADMIN_USERNAME, pw_hash, 1, now, date.today().isoformat()))
        db.commit()
        app.logger.info("İlk admin oluşturuldu: %s", FIRST_ADMIN_USERNAME)

# Initialize DB on import/app start
with app.app_context():
    init_db(force=False)

# ----------------------------
# UTILITIES
# ----------------------------
def now_iso():
    return datetime.utcnow().isoformat()

def log(level, message, tb=None):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO logs (level, message, tb, created_at) VALUES (?,?,?,?)", (level, message, tb or "", now_iso()))
        db.commit()
    except Exception:
        app.logger.exception("log yazılamadı")
    app.logger.info("[%s] %s", level, message)

def record_admin_event(actor, action, target="", details=""):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO admin_events (actor, action, target, details, created_at) VALUES (?,?,?,?,?)",
                    (actor, action, target, details, now_iso()))
        db.commit()
    except Exception:
        app.logger.exception("admin event kaydedilemedi")

def record_message(user_id, username, role, content):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO messages (user_id, username, role, content, created_at) VALUES (?,?,?,?,?)",
                    (user_id, username, role, content, now_iso()))
        db.commit()
    except Exception:
        app.logger.exception("message kaydı başarısız")

# ----------------------------
# AUTH DECORATORS
# ----------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Lütfen giriş yapın.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            flash("Yönetici girişi gerekli.", "warning")
            return redirect(url_for("login"))
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT is_admin, username FROM users WHERE id = ?", (uid,))
        r = cur.fetchone()
        if not r or r["is_admin"] != 1:
            flash("Bu sayfaya erişim yetkiniz yok.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper

def enes_only(f):
    """Decorator: only FIRST_ADMIN_USERNAME (enes) can access."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            flash("Giriş gerekli.", "warning")
            return redirect(url_for("login"))
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT username, is_admin FROM users WHERE id = ?", (uid,))
        r = cur.fetchone()
        if not r or r["username"] != FIRST_ADMIN_USERNAME:
            flash("Bu özellik sadece Enes'e özel.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper

# ----------------------------
# USAGE QUOTA HELPERS
# ----------------------------
def ensure_reset_for_user(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT image_quota_reset FROM users WHERE id = ?", (user_id,))
    r = cur.fetchone()
    today = date.today().isoformat()
    if not r or r["image_quota_reset"] != today:
        # reset usage entries for image_upscale
        cur.execute("DELETE FROM usage WHERE user_id = ? AND feature = ?", (user_id, "image_upscale"))
        cur.execute("UPDATE users SET image_quota_reset = ? WHERE id = ?", (today, user_id))
        db.commit()

def increment_feature_usage(user_id, feature):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, count FROM usage WHERE user_id = ? AND feature = ?", (user_id, feature))
    r = cur.fetchone()
    if r:
        cur.execute("UPDATE usage SET count = count + 1, last_used = ? WHERE id = ?", (date.today().isoformat(), r["id"]))
    else:
        cur.execute("INSERT INTO usage (user_id, feature, count, last_used) VALUES (?, ?, 1, ?)", (user_id, feature, date.today().isoformat()))
    db.commit()

def get_feature_usage_count(user_id, feature):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT count FROM usage WHERE user_id = ? AND feature = ?", (user_id, feature))
    r = cur.fetchone()
    return r["count"] if r else 0

# ----------------------------
# AI INTEGRATIONS
# ----------------------------
def call_groq(prompt, model=GROQ_MODEL, max_tokens=512, temperature=0.2):
    if not GROQ_API_KEY:
        return False, "Groq anahtarı tanımlı değil."
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    # Try common Groq endpoints/formats; be tolerant
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens, "temperature": temperature}
    urls = [
        f"{GROQ_ENDPOINT}/chat/completions",
        f"{GROQ_ENDPOINT}/v1/chat/completions",
        f"{GROQ_ENDPOINT}/completions",
        f"{GROQ_ENDPOINT}/models/{model}/generate"
    ]
    last_err = None
    for url in urls:
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=25)
            if r.status_code != 200:
                last_err = f"{url} -> {r.status_code} {r.text[:400]}"
                continue
            try:
                j = r.json()
                # parse common shapes
                if isinstance(j, dict):
                    if "choices" in j and len(j["choices"])>0:
                        c = j["choices"][0]
                        if isinstance(c.get("message"), dict):
                            return True, c["message"].get("content","")
                        if "text" in c:
                            return True, c.get("text","")
                    if "output" in j and isinstance(j["output"], list):
                        texts=[]
                        for o in j["output"]:
                            if isinstance(o, dict):
                                texts.append(o.get("content","") or o.get("text",""))
                            elif isinstance(o, str):
                                texts.append(o)
                        return True, " ".join(texts)
                    if "text" in j:
                        return True, j.get("text","")
                return True, r.text
            except Exception:
                return True, r.text
        except Exception as e:
            last_err = str(e)
            continue
    return False, f"Groq isteği başarısız: {last_err}"

def call_hf_text(prompt, model=HF_TEXT_MODEL, max_tokens=512):
    if not HF_API_KEY:
        return False, "HF anahtarı tanımlı değil."
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    url = f"https://api-inference.huggingface.co/models/{model}"
    payload = {"inputs": prompt, "parameters": {"max_new_tokens": max_tokens}}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=40)
        if r.status_code != 200:
            # try to show error
            try:
                return False, f"HF hata {r.status_code}: {r.json()}"
            except Exception:
                return False, f"HF hata {r.status_code}: {r.text}"
        try:
            j = r.json()
            if isinstance(j, list) and len(j)>0 and "generated_text" in j[0]:
                return True, j[0]["generated_text"]
            if isinstance(j, dict) and "generated_text" in j:
                return True, j["generated_text"]
            # fallback
            return True, str(j)
        except Exception:
            return True, r.text
    except Exception as e:
        tb = traceback.format_exc()
        log("error", "HF text çağrısı hata", tb)
        return False, f"HF isteği hatası: {e}"

def call_hf_image(prompt, model=HF_IMAGE_MODEL):
    # returns (ok, bytes_or_err, mime)
    if not HF_API_KEY:
        return False, "HF anahtarı yok.", None
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    url = f"https://api-inference.huggingface.co/models/{model}"
    payload = {"inputs": prompt}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=120, stream=True)
        if r.status_code != 200:
            try:
                return False, f"HF image hata {r.status_code}: {r.json()}", None
            except Exception:
                return False, f"HF image hata {r.status_code}: {r.text}", None
        # If content-type is JSON, parse
        content_type = r.headers.get("content-type","")
        if "application/json" in content_type:
            try:
                j = r.json()
                return False, f"HF beklenmedik json yanıt: {j}", None
            except Exception:
                return False, "HF beklenmedik json yanıt", None
        # else return bytes
        return True, r.content, content_type
    except Exception as e:
        tb = traceback.format_exc()
        log("error", "HF image çağrısı hata", tb)
        return False, f"HF image isteği hatası: {e}", None

# ----------------------------
# ROUTES / VIEWS
# ----------------------------
# Inline templates for simplicity (Turkish)
BASE_TEMPLATE = """
<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KralZeka v1</title>
<style>
body{background:#061016;color:#e6f6f3;font-family:Inter,Arial;margin:0;padding:18px}
.container{max-width:980px;margin:0 auto}
.header{display:flex;justify-content:space-between;align-items:center}
.btn{background:#12b46a;color:#021; padding:8px 12px;border-radius:8px;border:0;cursor:pointer}
.card{background:#072a2a;padding:14px;border-radius:10px;margin-top:12px}
.small{color:#9fbeb6;font-size:13px}
.msg{background:#082f2f;padding:8px;border-radius:8px;margin-bottom:8px}
.nav a{color:#8be0a1;margin-left:10px;text-decoration:none}
.admin{color:#ffd166}
.danger{background:#2a0b0b}
input,textarea,select{width:100%;padding:8px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:#021515;color:#fff}
</style></head><body><div class="container">
<div class="header"><div><h1>KralZeka v1</h1><div class="small">KralZeka, Enes'in zekasıyla hayat buldu.</div></div>
<div class="nav">
{% if user %}
  Merhaba <strong>{{ user['username'] }}</strong> {% if user['is_admin'] %}<span class="admin">[ADMIN]</span>{% endif %}
  <a href="{{ url_for('index') }}">Ana</a><a href="{{ url_for('dashboard') }}">Panel</a><a href="{{ url_for('logout') }}">Çıkış</a>
{% else %}
  <a href="{{ url_for('index') }}">Ana</a><a href="{{ url_for('login') }}">Giriş</a><a href="{{ url_for('register') }}">Kayıt</a>
{% endif %}
</div></div>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    <div class="card">{% for cat,msg in messages %}<div class="small">{{ msg }}</div>{% endfor %}</div>
  {% endif %}
{% endwith %}
<div class="card">
{% block content %}{% endblock %}
</div>
<footer class="small" style="margin-top:20px">© KralZeka v1</footer>
</div></body></html>
"""

# index
@app.route("/")
def index():
    user = None
    if "user_id" in session:
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
    content = """
    <h2>Ana Sayfa</h2>
    <p class="small">Modları seçip sorularınızı sorabilirsiniz. Cevaplar önce Groq ile denenir; hata olursa Hugging Face kullanılır.</p>
    {% if user %}
      <form method="post" action="{{ url_for('ask') }}">
        <label>Mod:</label>
        <select name="mode"><option value="chat">Sohbet</option><option value="homework">Ödev Yardım</option><option value="joke">Espri Modu</option><option value="presentation">Sunum Modu</option></select>
        <label>Soru / İstek:</label>
        <textarea name="prompt" rows="3" required></textarea>
        <div style="margin-top:8px"><button class="btn">Gönder</button></div>
      </form>
      <hr>
      <h3>Son Mesajlar</h3>
      {% for m in messages %}
        <div class="msg"><strong>{{ m['username'] }}</strong>: {{ m['content'] }} <div class="small">{{ m['created_at'] }}</div></div>
      {% endfor %}
    {% else %}
      <p>Giriş yapıp KralZeka ile sohbet edin.</p>
    {% endif %}
    """
    # last messages
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT username, content, created_at FROM messages ORDER BY id DESC LIMIT 8")
    messages = cur.fetchall()
    return render_template_string(BASE_TEMPLATE, user=user, messages=messages, content=content)

# Dashboard (user)
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (session["user_id"],))
    user = cur.fetchone()
    # usage
    ensure_reset_for_user = globals().get("ensure_reset_for_user")
    ensure_reset_for_user(session["user_id"])
    # build simple dashboard
    content = """
    <h2>Panel</h2>
    <p class="small">Modlar ve araçlar</p>
    <ul>
      <li><a href="{{ url_for('index') }}">Sohbet / Modlar</a></li>
      <li><a href="{{ url_for('uploads') }}">Görsel Yükle / Kalite Artır</a></li>
      {% if user.is_admin %}
      <li><a href="{{ url_for('admin_panel') }}">Yönetici Paneli</a></li>
      {% endif %}
    </ul>
    """
    return render_template_string(BASE_TEMPLATE, user=user, content=content)

# Login / Register / Logout
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("Kullanıcı adı ve parola gerekli.", "danger")
            return redirect(url_for("login"))
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        r = cur.fetchone()
        if not r or not check_password_hash(r["password_hash"], password):
            flash("Kullanıcı adı veya parola hatalı.", "danger")
            return redirect(url_for("login"))
        session.clear()
        session["user_id"] = r["id"]
        flash("Giriş başarılı.", "success")
        return redirect(url_for("dashboard"))
    # GET
    form = """
    <h2>Giriş Yap</h2>
    <form method="post">
      <label>Kullanıcı adı</label><input name="username" required>
      <label>Parola</label><input name="password" type="password" required>
      <div style="margin-top:8px"><button class="btn">Giriş</button></div>
    </form>
    <p class="small">İlk admin: enes / enes1357924680</p>
    """
    return render_template_string(BASE_TEMPLATE, user=None, content=form)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if not username or not password:
            flash("Bilgiler eksik.", "danger"); return redirect(url_for("register"))
        if password != password2:
            flash("Parolalar eşleşmiyor.", "danger"); return redirect(url_for("register"))
        if len(password) < 4:
            flash("Parola en az 4 karakter olmalı.", "danger"); return redirect(url_for("register"))
        db = get_db(); cur = db.cursor()
        try:
            cur.execute("INSERT INTO users (username, password_hash, is_admin, created_at, image_quota_reset) VALUES (?, ?, 0, ?, ?)",
                        (username, generate_password_hash(password), now_iso(), date.today().isoformat()))
            db.commit(); flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success"); return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Bu kullanıcı adı zaten alınmış.", "danger"); return redirect(url_for("register"))
    form = """
    <h2>Kayıt Ol</h2>
    <form method="post">
      <label>Kullanıcı adı</label><input name="username" required>
      <label>Parola</label><input name="password" type="password" required>
      <label>Parola (tekrar)</label><input name="password2" type="password" required>
      <div style="margin-top:8px"><button class="btn">Kayıt ol</button></div>
    </form>
    """
    return render_template_string(BASE_TEMPLATE, user=None, content=form)

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("index"))

# Ask route (form submit)
@app.route("/ask", methods=["POST"])
@login_required
def ask():
    prompt = (request.form.get("prompt") or "").strip()
    mode = (request.form.get("mode") or "chat")
    if not prompt:
        flash("Boş soru gönderilemez.", "danger"); return redirect(url_for("index"))
    user_id = session["user_id"]
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,)); u = cur.fetchone(); username = u["username"]
    # prepare prompt per mode
    sys_pfx = ""
    if mode == "homework":
        sys_pfx = "Ödev yardımı: adım adım ve öğrenci seviyesine uygun cevapla.\n"
    elif mode == "joke":
        sys_pfx = "Kısa, komik bir şaka üret.\n"
    elif mode == "presentation":
        sys_pfx = "Sunum için madde madde notlar ve slayt başlıkları oluştur.\n"
    full_prompt = sys_pfx + prompt
    # record user message
    record_message(user_id, username, "user", prompt)
    # call Groq first
    ok, resp = call_groq(full_prompt)
    engine = "groq"
    if not ok:
        # fallback HF
        ok2, resp2 = call_hf_text(full_prompt)
        if ok2:
            ok = True; resp = resp2; engine = "hf"
        else:
            # both failed
            resp = f"Cevap alınamadı. Groq: {resp} | HF: {resp2}"
            engine = "none"
    # record assistant message
    record_message(None, "KralZeka", "assistant", resp)
    flash("Cevap hazırlandı. Panelde görebilirsiniz.", "success")
    return redirect(url_for("dashboard"))

# Uploads & image generation
@app.route("/uploads", methods=["GET","POST"])
@login_required
def uploads():
    user_id = session["user_id"]
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if request.method == "POST":
        if "file" not in request.files:
            flash("Dosya seçilmedi.", "danger"); return redirect(url_for("uploads"))
        f = request.files["file"]
        if f.filename == "":
            flash("Dosya adı boş.", "danger"); return redirect(url_for("uploads"))
        ext = f.filename.rsplit(".",1)[-1].lower()
        if ext not in ALLOWED_IMAGE_EXT:
            flash("Desteklenmeyen dosya türü.", "danger"); return redirect(url_for("uploads"))
        # check quota for non-admin
        ensure_reset_for_user(user_id)
        if not user["is_admin"]:
            used = get_feature_usage_count(user_id, "image_upscale")
            if used >= DAILY_IMAGE_LIMIT:
                flash(f"Günlük kalite yükseltme kotanız doldu ({DAILY_IMAGE_LIMIT}).", "danger"); return redirect(url_for("uploads"))
        # save file
        fname = f"{int(time.time())}_{uuid.uuid4().hex}_{secure_filename(f.filename)}"
        path = os.path.join(UPLOAD_FOLDER, fname)
        try:
            f.save(path)
        except Exception as e:
            log("error", "dosya kaydetme hatası", traceback.format_exc()); flash("Dosya kaydedilemedi.", "danger"); return redirect(url_for("uploads"))
        # call HF upscale/generate (we'll call a generic HF image model)
        ok, payload, mime = call_hf_image(request.form.get("prompt",""))
        if not ok:
            # if api returned error, still allow upload
            flash(f"Görsel işlenemedi: {payload}", "danger")
            return redirect(url_for("uploads"))
        # save returned bytes (if bytes)
        out_name = f"out_{fname}"
        out_path = os.path.join(UPLOAD_FOLDER, out_name)
        try:
            with open(out_path, "wb") as wf:
                wf.write(payload)
        except Exception:
            log("error", "gorsel yazma hatası", traceback.format_exc()); flash("İşlenmiş görsel kaydedilemedi.", "danger"); return redirect(url_for("uploads"))
        # increment usage if not admin
        if not user["is_admin"]:
            increment_feature_usage(user_id, "image_upscale")
        flash("Görsel yüklendi ve işlendi.", "success")
        return redirect(url_for("uploads"))
    # GET: list uploads (basic)
    cur.execute("SELECT id, username, content, created_at FROM messages WHERE role='assistant' ORDER BY id DESC LIMIT 20")
    messages = cur.fetchall()
    content = """
    <h2>Görsel Yükle / Kalite Arttır</h2>
    <form method="post" enctype="multipart/form-data">
      <label>Görsel (png/jpg/webp)</label><input type="file" name="file" required>
      <label>İşleme Talimatı (ör: kalite yükselt / detaylandır):</label><input name="prompt">
      <div style="margin-top:8px"><button class="btn">Yükle ve İşle</button></div>
    </form>
    <hr>
    <h3>Son Asistan Cevapları</h3>
    {% for m in messages %}<div class="msg"><strong>{{ m['username'] }}</strong>: {{ m['content'] }} <div class="small">{{ m['created_at'] }}</div></div>{% endfor %}
    """
    return render_template_string(BASE_TEMPLATE, user=user, messages=messages, content=content)

@app.route("/uploads/file/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ADMIN PANEL
@app.route("/admin", methods=["GET","POST"])
@admin_required
def admin_panel():
    uid = session["user_id"]
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT username, is_admin FROM users WHERE id = ?", (uid,)); me = cur.fetchone()
    # handle actions
    if request.method == "POST":
        action = request.form.get("action"); target = request.form.get("target")
        if not action or not target:
            flash("Eksik parametre.", "danger"); return redirect(url_for("admin_panel"))
        # protect first admin
        if target == FIRST_ADMIN_USERNAME and action in ("delete","demote"):
            record_admin_event(me["username"], f"attempt_{action}", target, "İlk admin koruması")
            flash("Bu işlem yapılamaz (ilk admin korunuyor). Deneme loglandı.", "danger")
            return redirect(url_for("admin_panel"))
        try:
            if action == "promote":
                cur.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (target,))
                db.commit()
                record_admin_event(me["username"], "promote", target, "")
                flash(f"{target} admin yapıldı.", "success")
            elif action == "demote":
                cur.execute("UPDATE users SET is_admin = 0 WHERE username = ?", (target,))
                db.commit()
                record_admin_event(me["username"], "demote", target, "")
                flash(f"{target} adminlıktan alındı.", "success")
            elif action == "delete":
                cur.execute("DELETE FROM users WHERE username = ?", (target,))
                db.commit()
                record_admin_event(me["username"], "delete", target, "")
                flash(f"{target} silindi.", "success")
            elif action == "inspect":
                # simple system check
                probs = []
                if not HF_API_KEY: probs.append("HF_API_KEY tanımlı değil.")
                if not GROQ_API_KEY: probs.append("GROQ_API_KEY tanımlı değil.")
                if not probs:
                    flash("Sistem kontrolden geçti. Önemli sorun yok.", "success")
                else:
                    flash("Sistem kontrolu sonuçları: " + "; ".join(probs), "warning")
            elif action == "open_code_session":
                # create code session token
                skey = uuid.uuid4().hex
                cur.execute("INSERT INTO admin_events (actor, action, target, details, created_at) VALUES (?,?,?,?,?)",
                            (me["username"], "start_code_session", me["username"], skey, now_iso()))
                db.commit()
                return redirect(url_for("code_session", session_key=skey))
        except Exception:
            log("error", "admin action hata", traceback.format_exc()); flash("Admin işlemi başarısız.", "danger")
        return redirect(url_for("admin_panel"))
    # GET: list users, events, logs
    cur.execute("SELECT username, is_admin, created_at, protected FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.execute("SELECT * FROM admin_events ORDER BY id DESC LIMIT 50"); events = cur.fetchall()
    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 80"); logs = cur.fetchall()
    content = """
    <h2>Yönetici Paneli</h2>
    <h3>Kullanıcılar</h3>
    <form method="post">
      <select name="target">{% for u in users %}<option value="{{ u['username'] }}">{{ u['username'] }} {% if u['is_admin'] %}(admin){% endif %} {% if u['protected'] %}[KORUNMUŞ]{% endif %}</option>{% endfor %}</select>
      <select name="action"><option value="promote">Admin Yap</option><option value="demote">Adminlıktan Al</option><option value="delete">Sil</option></select>
      <button class="btn">Uygula</button>
    </form>
    <h3>Hızlı İşlemler</h3>
    <form method="post"><input type="hidden" name="action" value="inspect"><button class="btn">Sistemi İncele</button></form>
    <form method="post"><input type="hidden" name="action" value="open_code_session"><button class="btn">Kod Yazma Oturumu Başlat (Enes)</button></form>
    <h3>Admin Olaylar</h3>{% for e in events %}<div class="msg"><strong>{{ e['action'] }}</strong> - {{ e['actor'] }} -> {{ e['target'] }} <div class="small">{{ e['details'] }} / {{ e['created_at'] }}</div></div>{% endfor %}
    <h3>Loglar</h3>{% for l in logs %}<div class="msg danger"><strong>{{ l['level'] }}</strong> - {{ l['message'] }} <div class="small">{{ l['created_at'] }}</div></div>{% endfor %}
    """
    return render_template_string(BASE_TEMPLATE, user=me, users=users, events=events, logs=logs, content=content)

# CODE SESSION (only enes)
@app.route("/admin/code/<session_key>", methods=["GET","POST"])
@enes_only
def code_session(session_key):
    db = get_db(); cur = db.cursor()
    # verify session exists in admin_events as start_code_session
    cur.execute("SELECT * FROM admin_events WHERE details = ? AND action = ?", (session_key, "start_code_session"))
    row = cur.fetchone()
    # If no such row, create ephemeral record
    if not row:
        cur.execute("INSERT INTO admin_events (actor, action, target, details, created_at) VALUES (?,?,?,?,?)",
                    (FIRST_ADMIN_USERNAME, "start_code_session", FIRST_ADMIN_USERNAME, session_key, now_iso()))
        db.commit()
    # session state kept in server memory simple dict keyed by session_key (persist not required for this demo)
    if "code_sessions" not in g:
        g.code_sessions = {}
    sess = g.code_sessions.get(session_key, {"state":"init","data":{}})
    if request.method == "POST":
        text = (request.form.get("text") or "").strip()
        if not text:
            flash("Boş cevap gönderilemez.", "danger"); return redirect(url_for("code_session", session_key=session_key))
        # simple state machine
        if sess["state"] == "init":
            sess["data"]["title"] = text
            sess["state"] = "ask_language"
            flash("Hangi dilde istersiniz? (örn: python, javascript)", "info")
        elif sess["state"] == "ask_language":
            sess["data"]["language"] = text.lower()
            sess["state"] = "ask_features"
            flash("Hangi özellikler olmalı? (virgülle ayır: chat, api, gui, db)", "info")
        elif sess["state"] == "ask_features":
            sess["data"]["features"] = [s.strip() for s in text.split(",") if s.strip()]
            sess["state"] = "ask_output"
            flash("Çıktı türü ne olsun? (console, web, file)", "info")
        elif sess["state"] == "ask_output":
            sess["data"]["output"] = text.lower()
            sess["state"] = "ready"
            flash("Oluşturmaya hazır. 'Oluştur' butonuna bas.", "success")
        elif sess["state"] == "ready":
            # create code using AI
            prompt = f"Başlık: {sess['data'].get('title')}\nDil: {sess['data'].get('language')}\nÖzellikler: {', '.join(sess['data'].get('features',[]))}\nÇıktı: {sess['data'].get('output')}\nLütfen çalıştırılabilir ve iyi yorumlanmış kod üret."
            ok, resp = call_groq(prompt)
            engine = "groq"
            if not ok:
                ok2, resp2 = call_hf_text(prompt)
                if ok2:
                    ok = True; resp = resp2; engine = "hf"
            # store generated code as admin event
            cur.execute("INSERT INTO admin_events (actor, action, target, details, created_at) VALUES (?,?,?,?,?)",
                        (FIRST_ADMIN_USERNAME, "generated_code", FIRST_ADMIN_USERNAME, f"engine:{engine}\n{resp[:200]}", now_iso()))
            db.commit()
            # also record message
            record_message(None, "KralZeka(CodeGen)", "assistant", resp)
            flash("Kod oluşturuldu ve mesajlara eklendi.", "success")
            sess["state"] = "done"
        g.code_sessions[session_key] = sess
        return redirect(url_for("code_session", session_key=session_key))
    # render session
    state = sess["state"]
    data = sess["data"]
    code_preview = None
    if state == "ready":
        code_preview = "Hazır: Oluştur tuşuna bas."
    elif state == "done":
        # show last generated code from messages (simple)
        cur.execute("SELECT content FROM messages WHERE username = 'KralZeka(CodeGen)' ORDER BY id DESC LIMIT 1")
        jr = cur.fetchone(); code_preview = jr["content"] if jr else "Kod yok."
    content = f"""
    <h2>Kod Yazıcı (Enes'e Özel)</h2>
    <div class="small">Durum: {state}</div>
    <form method="post">
      <input name="text" placeholder="Yanıtınızı yazın (örn: başlık, dil vs.)">
      <div style="margin-top:8px"><button class="btn">Gönder</button></div>
    </form>
    <h3>Oturum Verisi</h3><pre>{json.dumps(data, ensure_ascii=False, indent=2)}</pre>
    <h3>Kod Önizleme</h3><pre>{code_preview or ''}</pre>
    """
    return render_template_string(BASE_TEMPLATE, user={"username":FIRST_ADMIN_USERNAME,"is_admin":1}, content=content)

# MESSAGES view (for admin)
@app.route("/messages")
@admin_required
def messages_view():
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 200")
    msgs = cur.fetchall()
    out = "<h2>Mesajlar (son)</h2>"
    for m in msgs:
        out += f"<div class='msg'><strong>{m['username']}</strong> ({m['role']}) - {m['created_at']}<div class='small'>{m['content'][:1000]}</div></div>"
    return render_template_string(BASE_TEMPLATE, user={"username":"admin","is_admin":1}, content=out)

# Simple health
@app.route("/health")
def health():
    return jsonify({"ok": True, "time": now_iso()})

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template_string(BASE_TEMPLATE, user=None, content="<h2>404 - Sayfa bulunamadı</h2>"), 404

@app.errorhandler(500)
def server_error(e):
    tb = traceback.format_exc()
    log("error", "Internal Server Error", tb)
    return render_template_string(BASE_TEMPLATE, user=None, content=f"<h2>Sunucu hatası</h2><pre>{str(e)}</pre>"), 500

# ----------------------------
# START (main)
# ----------------------------
if __name__ == "__main__":
    # local dev fallback
    with app.app_context():
        init_db(force=False)
    port = int(os.environ.get("PORT", 10000))
    print("KralZeka v1 başlatılıyor port:", port)
    app.run(host="0.0.0.0", port=port, debug=False)
