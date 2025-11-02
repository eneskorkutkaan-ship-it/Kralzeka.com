#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Tam sürüm (tek dosya)
- Groq öncelikli (GROQ_API_KEY)
- Hugging Face yedek (HF_API_KEY)
- Admin: enes (değiştirilemez / silinemez)
- Kullanıcı kayıt + giriş + admin panel
- Görsel üretme (HF) ve kalite yükseltme (admin sınırsız, normal kullanıcı günde 5)
- Admin-only kod-yazma "assistant" bölümü (isteğe göre kod üretir)
- Tüm arayüz Türkçe. Tek dosya; SQLite DB kullanan güvenli yapı.
"""

import os
import sqlite3
import json
import time
import uuid
import functools
from datetime import datetime, timedelta
from typing import Optional
from flask import (
    Flask, request, redirect, url_for, session, g,
    render_template_string, jsonify, abort, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from io import BytesIO
import base64
import logging

# ========== AYARLAR ==========
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("KRALZEKA_DB", os.path.join(BASE_DIR, "kralzeka.db"))

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
HF_API_KEY = os.environ.get("HF_API_KEY", "").strip()
SECRET_KEY = os.environ.get("SECRET_KEY", os.environ.get("FLASK_SECRET_KEY", str(uuid.uuid4())))
if not SECRET_KEY:
    SECRET_KEY = str(uuid.uuid4())

# modeli kod içinde belirle (kullanıcı değiştirmeyecek)
DEFAULT_GROQ_MODEL = "llama-3.1-70b"   # öncelikli (sunucu erişimi varsa)
DEFAULT_HF_TEXT_MODEL = "meta-llama/Llama-2-7b-chat-hf"  # fallback text model
DEFAULT_HF_IMAGE_MODEL = "stabilityai/stable-diffusion-xl"  # örnek

# Limits / özellikler
IMAGE_DAILY_LIMIT = 5  # normal kullanıcı için günlük kalite yükseltme sınırlaması
ADMIN_USERNAME = "enes"
ADMIN_PASSWORD = "enes1357924680"  # ilk admin (db'ye eklenecek, kodda salt okunur kurallar var)

# güvenlik - CORS/CSRF vb production'da eklenmeli (basit demo için minimum)
# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kralzeka")

# Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ========== DB YARDIMCILARI ==========
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        need_init = not os.path.exists(DB_PATH)
        db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
        g._db = db
        if need_init:
            init_db(db)
    return db

def init_db(db_conn=None, force=False):
    db = db_conn or sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = db.cursor()
    # users: id, username unique, password_hash, is_admin, created_at
    cur.executescript("""
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        sender TEXT, -- 'user' or 'kralzeka' or 'system'
        content TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        meta TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS image_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        usage_date TEXT,
        count INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    db.commit()
    # ensure initial admin exists (immutable)
    try:
        cur.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), 1)
            )
            db.commit()
            logger.info("İlk admin oluşturuldu: %s", ADMIN_USERNAME)
    except Exception as e:
        logger.exception("init_db error: %s", e)

def close_db(e=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()
        g._db = None

app.teardown_appcontext(close_db)

# ========== YARDIMCI FONKSİYONLAR ==========
def log_event(level: str, message: str, meta: Optional[dict] = None):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO logs (level, message, meta) VALUES (?, ?, ?)", (level, message, json.dumps(meta or {})))
        db.commit()
    except Exception:
        logger.exception("log_event failed")

def get_user_by_username(username: str):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def create_user(username: str, password: str, is_admin: int = 0):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), is_admin))
        db.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None

def require_login(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        # load user
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
        if not user:
            session.clear()
            return redirect(url_for("login"))
        g.user = user
        return fn(*args, **kwargs)
    return wrapper

def require_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
        if not user or not user["is_admin"]:
            return "Bu bölüm yalnızca adminlere özeldir.", 403
        g.user = user
        return fn(*args, **kwargs)
    return wrapper

def protected_admin_modify(target_username: str, acting_admin: str):
    """
    İlk admini (enes) demote/silme gibi işlemleri engeller.
    Eğer bir admin 'enes' üzerinde işlem yapmaya çalışırsa, bunu logla ve uyar.
    """
    if target_username == ADMIN_USERNAME:
        # log the attempt
        log_event("WARN", f"Admin yetki değişikliği denemesi: {acting_admin} -> {target_username}", {"actor": acting_admin, "target": target_username})
        return False
    return True

def format_time(ts=None):
    return (ts or datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S")

# ========== AI BACKENDS ==========
def call_groq_chat(prompt: str, model=DEFAULT_GROQ_MODEL):
    """
    Basit istek: Groq API benzeri bir endpoint çağrısı.
    Bu örnek kodda, Groq erişimi yoksa hata fırlatır; üst katman fallback yapar.
    """
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ key yok")
    url = "https://api.groq.com/openai/v1/chat/completions"  # örnek (kendi endpoint'ini kullan)
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    }
    try:
        r = requests.post(url, headers=headers, json=data, timeout=30)
        r.raise_for_status()
        resp = r.json()
        # farklı servislerin cevap formatı farklı olabilir; esnek davran
        if "choices" in resp and resp["choices"]:
            return resp["choices"][0].get("message", {}).get("content") or resp["choices"][0].get("text")
        # fallback if structure differs
        return resp.get("output_text") or json.dumps(resp)
    except Exception as e:
        logger.exception("Groq çağrısı başarısız: %s", e)
        raise

def call_hf_text(prompt: str, model: str = DEFAULT_HF_TEXT_MODEL):
    """
    Hugging Face text generation inference API çağrısı.
    """
    if not HF_API_KEY:
        raise RuntimeError("HF key yok")
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        resp = r.json()
        if isinstance(resp, dict) and "error" in resp:
            raise RuntimeError(resp["error"])
        # HF often returns a list of dicts with 'generated_text'
        if isinstance(resp, list) and resp and "generated_text" in resp[0]:
            return resp[0]["generated_text"]
        # else if string
        if isinstance(resp, str):
            return resp
        # else dump
        return json.dumps(resp)
    except Exception:
        logger.exception("HF text generation failed")
        raise

def generate_image_hf(prompt: str, model: str = DEFAULT_HF_IMAGE_MODEL, size: str = "1024x1024"):
    """
    Basit HF image generation call; base64 PNG returned.
    """
    if not HF_API_KEY:
        raise RuntimeError("HF key yok")
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}", "Accept": "application/json"}
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    # Some HF image models expect different payloads; attempt general call
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=120)
        r.raise_for_status()
        content_type = r.headers.get("Content-Type", "")
        if "application/json" in content_type:
            data = r.json()
            # If HF returns base64 image or url
            if isinstance(data, dict) and "image_base64" in data:
                return base64.b64decode(data["image_base64"])
            if isinstance(data, dict) and "generated_image" in data:
                return base64.b64decode(data["generated_image"])
            # sometimes HF returns bytes directly (rare)
            # else if 'error' in data raise
            if "error" in data:
                raise RuntimeError(data["error"])
            # otherwise dump
            raise RuntimeError("HF image model returned unexpected JSON")
        else:
            # raw bytes (png/jpg)
            return r.content
    except Exception:
        logger.exception("HF image generation failed")
        raise

def ai_chat(prompt: str) -> str:
    """
    Öncelikle Groq dene; başarısız olursa HF text fallback.
    """
    try:
        if GROQ_API_KEY:
            try:
                out = call_groq_chat(prompt)
                if out:
                    return out
            except Exception:
                logger.warning("Groq başarısız, HF'e düşülüyor.")
        # fallback
        if HF_API_KEY:
            return call_hf_text(prompt)
        raise RuntimeError("Hiçbir model yapılamıyor (GROQ/HF anahtarları yok veya hata).")
    except Exception as e:
        logger.exception("ai_chat exception")
        return f"KralZeka Hata: {str(e)}"

# ========== UTIL: LIMITLER ==========
def get_image_usage_for_today(user_id: int):
    db = get_db()
    cur = db.cursor()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    cur.execute("SELECT count FROM image_usage WHERE user_id = ? AND usage_date = ?", (user_id, today))
    row = cur.fetchone()
    return row["count"] if row else 0

def increment_image_usage(user_id: int, amount: int = 1):
    db = get_db()
    cur = db.cursor()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    cur.execute("SELECT id, count FROM image_usage WHERE user_id = ? AND usage_date = ?", (user_id, today))
    r = cur.fetchone()
    if r:
        cur.execute("UPDATE image_usage SET count = count + ? WHERE id = ?", (amount, r["id"]))
    else:
        cur.execute("INSERT INTO image_usage (user_id, usage_date, count) VALUES (?, ?, ?)", (user_id, today, amount))
    db.commit()

# ========== ROUTES & UI ==========
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>KralZeka v1</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{background:#071018;color:#d8efe9;font-family:Inter,Segoe UI,Arial;padding:20px}
    .wrap{max-width:900px;margin:0 auto}
    header{display:flex;justify-content:space-between;align-items:center}
    h1{margin:0;font-size:28px}
    .card{background:rgba(0,0,0,0.45);padding:18px;border-radius:10px;box-shadow:0 6px 30px rgba(0,0,0,0.6);margin-top:18px}
    input,textarea,button,select{font-size:16px;padding:10px;border-radius:8px;border:1px solid #263238;background:#0b1517;color:#d8efe9;width:100%}
    .row{display:flex;gap:10px}
    .row > *{flex:1}
    .muted{color:#9cb8b8;font-size:14px}
    .msg{background:#042627;padding:12px;border-radius:8px;margin-bottom:8px}
    .admin-tag{color:#ffd54f;font-weight:bold}
    .top-buttons a{color:#d8efe9;margin-left:12px}
    footer{margin-top:40px;text-align:center;color:#6c9b9b}
    .small{font-size:13px;color:#9dbdbd}
    .danger{color:#ffd2d2}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>KralZeka v1</h1>
      <div class="top-buttons">
        {% if user %}
          Merhaba, <strong>{{ user['username'] }}</strong> {% if user['is_admin'] %}<span class="admin-tag">[ADMIN]</span>{% endif %}
           | <a href="{{ url_for('logout') }}">Çıkış yap</a>
           {% if user['is_admin'] %} | <a href="{{ url_for('admin_panel') }}">Admin Panel</a>{% endif %}
        {% else %}
          <a href="{{ url_for('login') }}">Giriş</a> | <a href="{{ url_for('register') }}">Kayıt</a>
        {% endif %}
      </div>
    </header>

    {% block body %}{% endblock %}

    <footer>
      © KralZeka v1 — KralZeka, Enes'in zekasıyla hayat buldu. <div class="small">Tüm arayüz Türkçe. Gizli anahtarlar sadece ENV'de tutulur.</div>
    </footer>
  </div>
</body>
</html>
"""

INDEX_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <form method="post" action="{{ url_for('chat') }}">
      <label class="small">Sohbet (Groq öncelikli, Hugging Face yedek)</label>
      <div style="display:flex;gap:10px">
        <input name="prompt" placeholder="Bir şey yaz..." autocomplete="off" required>
        <button type="submit">Gönder</button>
      </div>
    </form>
  </div>

  <div class="card">
    <h3>Son mesajlar</h3>
    {% for m in messages %}
      <div class="msg">
        <div class="small muted">{{ m['created_at'] }} — <strong>{{ m['sender'] }}</strong></div>
        <div>{{ m['content'] }}</div>
      </div>
    {% endfor %}
  </div>

  <div class="card">
    <h3>Modlar</h3>
    <div class="small">Seçilebilir modlar (gelecekte UI üzerinden geçiş yapılabilir):</div>
    <ul class="small">
      <li>Ödev Modu — Sınav/çalışma kağıtları oluşturma, yüklenen görsellerde soruları çözme.</li>
      <li>Espri Modu — Şakalar karışık, hafif sohbet.</li>
      <li>Sohbet Modu — Normal sohbet.</li>
      <li>Sunum Modu — Slayt/sunum/afiş oluşturma (görseller ve metin).</li>
      <li>Kalite Yükseltme — Görsel kalite yükseltme (admin sınırsız, kullanıcı günlük {{ image_limit }}).</li>
    </ul>
  </div>

  <div class="card">
    <h3>Yenilik talep / Güncelleme isteği</h3>
    <form method="post" action="{{ url_for('feature_request') }}">
      <textarea name="request_text" rows="3" placeholder="Yeni bir özellik veya düzeltme isteği yaz..." required></textarea>
      <div style="display:flex;gap:10px;margin-top:8px">
        <input name="tag" placeholder="Kısa etiket (örn: sunum, ödev, görsel)">
        <button>Gönder</button>
      </div>
    </form>
    <div class="small muted">Admin panelde bu istekler görüntülenecek.</div>
  </div>
{% endblock %}
"""

LOGIN_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Giriş</h3>
    {% if error %}<div class="danger">{{ error }}</div>{% endif %}
    <form method="post">
      <label>Kullanıcı adı</label>
      <input name="username" required>
      <label>Parola</label>
      <input name="password" type="password" required>
      <div style="margin-top:10px"><button>Giriş yap</button></div>
    </form>
  </div>
{% endblock %}
"""

REGISTER_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Kayıt ol</h3>
    {% if error %}<div class="danger">{{ error }}</div>{% endif %}
    <form method="post">
      <label>Kullanıcı adı</label>
      <input name="username" required>
      <label>Parola</label>
      <input name="password" type="password" required>
      <label>Parola tekrar</label>
      <input name="password2" type="password" required>
      <div style="margin-top:10px"><button>Kayıt ol</button></div>
    </form>
    <div class="small muted">İlk admin ({{ admin_username }}) silinemez veya demote edilemez.</div>
  </div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Admin Paneli</h3>
    <div class="small">Kullanıcı yönetimi, limitler, kod-yazma bölümü (sadece adminlere özel), günlük kullanım yönetimi.</div>
    <hr>
    <h4>Kullanıcılar</h4>
    <table style="width:100%" class="small">
      <tr><th>Kullanıcı</th><th>Admin</th><th>Oluşturma</th><th>İşlemler</th></tr>
      {% for u in users %}
        <tr>
          <td>{{ u['username'] }}</td>
          <td>{{ 'Evet' if u['is_admin'] else 'Hayır' }}</td>
          <td>{{ u['created_at'] }}</td>
          <td>
            {% if u['username'] != admin_username %}
              {% if not u['is_admin'] %}
                <form style="display:inline" method="post" action="{{ url_for('make_admin', user_id=u['id']) }}"><button>Admin yap</button></form>
              {% else %}
                <form style="display:inline" method="post" action="{{ url_for('revoke_admin', user_id=u['id']) }}"><button>Adminlığı kaldır</button></form>
              {% endif %}
              <form style="display:inline" method="post" action="{{ url_for('delete_user', user_id=u['id']) }}"><button class="danger">Sil</button></form>
            {% else %}
              (korunuyor)
            {% endif %}
          </td>
        </tr>
      {% endfor %}
    </table>

    <hr>
    <h4>Kod Yazma / Otomatik Yardımcı (Admin-only)</h4>
    <div class="small">Admin olarak örneğin "bir yapay zeka yardımcı yaz" dediğinde sistem sana sorular soracak ve kodu üretecek.</div>
    <form method="post" action="{{ url_for('admin_code_tool') }}">
      <textarea name="prompt" rows="4" placeholder="Üretilecek kod veya talimat..." required></textarea>
      <div style="margin-top:8px"><button>Yaz</button></div>
    </form>
    <div class="small muted">Üretilen sonuçlar loglanır ve yalnızca adminler görür.</div>

    <hr>
    <h4>Loglar (son 100)</h4>
    <div class="small">
      {% for l in logs %}
        <div class="msg small"><strong>{{ l['level'] }}</strong> — {{ l['message'] }} <div class="muted">{{ l['created_at'] }}</div></div>
      {% endfor %}
    </div>
  </div>
{% endblock %}
"""

ERROR_500 = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Sunucu Hatası (500)</h3>
    <p>Bir hata oluştu. Admin'e bildirin veya logları kontrol edin.</p>
  </div>
{% endblock %}
"""

# register templates
app.jinja_loader.mapping = {
    'base': BASE_HTML,
    'index.html': INDEX_HTML,
    'login.html': LOGIN_HTML,
    'register.html': REGISTER_HTML,
    'admin.html': ADMIN_HTML,
    '500.html': ERROR_500
}

# ========== ROUTES ==========
@app.route("/", methods=["GET"])
def index():
    user = None
    if "user_id" in session:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 20")
    msgs = cur.fetchall()
    return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'index.html')[0],
                                  user=user, messages=msgs, image_limit=IMAGE_DAILY_LIMIT)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        if not username or not password:
            return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'register.html')[0], error="Alanları doldurun", admin_username=ADMIN_USERNAME)
        if password != password2:
            return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'register.html')[0], error="Parolalar eşleşmiyor", admin_username=ADMIN_USERNAME)
        if get_user_by_username(username):
            return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'register.html')[0], error="Kullanıcı adı alınmış", admin_username=ADMIN_USERNAME)
        uid = create_user(username, password, 0)
        if not uid:
            return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'register.html')[0], error="Kayıt başarısız", admin_username=ADMIN_USERNAME)
        log_event("INFO", f"Kayıt: {username}")
        # auto login
        session["user_id"] = uid
        return redirect(url_for("index"))
    return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'register.html')[0], error=None, admin_username=ADMIN_USERNAME)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user_by_username(username)
        if not user or not check_password_hash(user["password_hash"], password):
            return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'login.html')[0], error="Kullanıcı adı veya şifre hatalı")
        session["user_id"] = user["id"]
        log_event("INFO", f"Giriş: {username}")
        return redirect(url_for("index"))
    return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'login.html')[0], error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/chat", methods=["POST"])
@require_login
def chat():
    prompt = request.form.get("prompt", "").strip()
    if not prompt:
        return redirect(url_for("index"))
    user = g.user
    # save user message
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)", (user["id"], user["username"], prompt))
    db.commit()

    # process prompt for certain modes (if starts with "mod:..."), simple example
    try:
        # If user requests "ödev" mode keywords, we can augment prompt
        response_text = ai_chat(prompt)
    except Exception as e:
        response_text = f"Hata: {str(e)}"
    # store assistant response
    cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)", (user["id"], "KralZeka", response_text))
    db.commit()
    return redirect(url_for("index"))

@app.route("/feature_request", methods=["POST"])
@require_login
def feature_request():
    txt = request.form.get("request_text", "").strip()
    tag = request.form.get("tag", "").strip()
    if txt:
        log_event("FEATURE", txt, {"tag": tag, "user": g.user["username"]})
    return redirect(url_for("index"))

# ========== Admin routes ==========
@app.route("/admin", methods=["GET"])
@require_admin
def admin_panel():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.execute("SELECT level, message, meta, created_at FROM logs ORDER BY id DESC LIMIT 100")
    logs = cur.fetchall()
    return render_template_string(app.jinja_loader.get_source(app.jinja_env, 'admin.html')[0],
                                  users=users, logs=logs, admin_username=ADMIN_USERNAME)

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
@require_admin
def make_admin(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return "Kullanıcı yok", 404
    target = row["username"]
    if not protected_admin_modify(target, g.user["username"]):
        return f"{ADMIN_USERNAME} üzerinde değişiklik yapamazsın.", 403
    cur.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{g.user['username']} -> {target} admin yapıldı")
    return redirect(url_for("admin_panel"))

@app.route("/admin/revoke_admin/<int:user_id>", methods=["POST"])
@require_admin
def revoke_admin(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return "Kullanıcı yok", 404
    target = row["username"]
    if not protected_admin_modify(target, g.user["username"]):
        return f"{ADMIN_USERNAME} üzerinde değişiklik yapamazsın.", 403
    cur.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{g.user['username']} -> {target} adminlığını kaldırdı")
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@require_admin
def delete_user(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    r = cur.fetchone()
    if not r:
        return "Kullanıcı yok", 404
    target = r["username"]
    if not protected_admin_modify(target, g.user["username"]):
        return f"{ADMIN_USERNAME} üzerinde değişiklik yapamazsın.", 403
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{g.user['username']} -> {target} silindi")
    return redirect(url_for("admin_panel"))

@app.route("/admin/code_tool", methods=["POST"])
@require_admin
def admin_code_tool():
    prompt = request.form.get("prompt", "").strip()
    if not prompt:
        return redirect(url_for("admin_panel"))
    # For admin-only code generation: ask AI (Groq/HF)
    try:
        # simple guard: require explicit confirmation? We use direct generation as requested
        ai_response = ai_chat(f"Admin kod üretme asistanı: {prompt}")
    except Exception as e:
        ai_response = f"Hata: {e}"
    # log and show in admin logs
    log_event("CODE", ai_response, {"admin": g.user["username"], "prompt": prompt})
    return redirect(url_for("admin_panel"))

# ========== Image generation endpoint ==========
@app.route("/api/generate_image", methods=["POST"])
@require_login
def api_generate_image():
    data = request.get_json() or {}
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "prompt gerekli"}), 400
    user = g.user
    # limit check (if not admin)
    if not user["is_admin"]:
        used = get_image_usage_for_today(user["id"])
        if used >= IMAGE_DAILY_LIMIT:
            return jsonify({"error": f"Günlük limit aşıldı ({IMAGE_DAILY_LIMIT})"}), 403
    # try HF
    try:
        img_bytes = generate_image_hf(prompt)
        # increment usage
        if not user["is_admin"]:
            increment_image_usage(user["id"], 1)
        b64 = base64.b64encode(img_bytes).decode("utf-8")
        # store message log
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)", (user["id"], "KralZeka (görsel)", f"data:image/png;base64,{b64[:180]}...")))
        db.commit()
        return jsonify({"image_base64": b64}), 200
    except Exception as e:
        logger.exception("image generation error")
        return jsonify({"error": f"Görsel üretilemedi: {str(e)}"}), 500

# ========== Error handling ==========
@app.errorhandler(500)
def handle_500(e):
    try:
        log_event("ERROR", str(e), {"path": request.path})
    except Exception:
        pass
    return render_template_string(app.jinja_loader.get_source(app.jinja_env, '500.html')[0], user=None), 500

# ========== Başlat / init ==========
def start_app():
    # Ensure DB exists & initial admin present
    init_db()
    logger.info("KralZeka v1 starting...")
    # Do not run Flask built-in server in production; use gunicorn as start command.
    # But allow local debug run
    if os.environ.get("FLASK_RUN_LOCAL", "").lower() in ("1", "true"):
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

# WSGI app variable for gunicorn
if __name__ == "__main__":
    start_app()
