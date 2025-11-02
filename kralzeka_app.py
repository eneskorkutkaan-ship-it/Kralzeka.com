#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Tek dosyalık Flask uygulaması
Kullanım:
  - Ortam değişkenleri:
      HF_API_KEY   -> Hugging Face token
      GROQ_API_KEY -> Groq API token
      SECRET_KEY   -> Flask session secret (önerilir)
  - Çalıştır: python kralzeka_app.py
"""

import os
import sqlite3
import json
import time
import hashlib
import hmac
import traceback
from functools import wraps
from datetime import datetime, timedelta

import requests
from flask import (
    Flask, request, g, session, redirect, url_for, render_template_string,
    flash, jsonify, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------
# Ayarlar / Sabitler
# ----------------------------
DATABASE = os.environ.get("DATABASE", "kralzeka.db")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
HF_API_KEY = os.environ.get("HF_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "change_this_secret_in_env")
PORT = int(os.environ.get("PORT", 5000))

# Groq settings (primary)
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3-8b-instruct")  # örnek model ismi
GROQ_ENDPOINT = os.environ.get("GROQ_ENDPOINT", "https://api.groq.com/v1")  # varsayılan, gerekiyorsa değiştir

# Hugging Face fall-back model (text)
HF_TEXT_MODEL = os.environ.get("HF_TEXT_MODEL", "meta-llama/Llama-3-8b-instruct")

# Hugging Face image model (örnek)
HF_IMAGE_MODEL = os.environ.get("HF_IMAGE_MODEL", "stabilityai/stable-diffusion-2")  # örnek

# Limits
DAILY_QUALITY_LIMIT = 5  # normal kullanıcı başına günlük
ADMIN_USER = "enes"
ADMIN_PASS = "enes1357924680"

# ----------------------------
# Basit Flask app oluşturma
# ----------------------------
app = Flask(__name__)
app.config.update(
    DATABASE=DATABASE,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SECRET_KEY=SECRET_KEY,
)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ----------------------------
# Yardımcı DB fonksiyonları
# ----------------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        g._db = db
    return db

def close_db(e=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()
        g._db = None

app.teardown_appcontext(close_db)

def init_db(force=False):
    """Veritabanını başlat. force=True ise tabloyu yeniden oluştur."""
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
        # users: id, username, password_hash, is_admin (0/1), quota_quality_daily, created_at, last_seen, protected (0/1)
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            quota_quality_daily INTEGER NOT NULL DEFAULT ?,
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
        """, (DAILY_QUALITY_LIMIT,))
        db.commit()
        # create initial admin if not exists
        cur.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,))
        if not cur.fetchone():
            pw_hash = generate_password_hash(ADMIN_PASS)
            now = datetime.utcnow().isoformat()
            cur.execute("INSERT INTO users (username, password_hash, is_admin, quota_quality_daily, created_at, protected) VALUES (?, ?, 1, ?, ?, 1)",
                        (ADMIN_USER, pw_hash, DAILY_QUALITY_LIMIT, now))
            db.commit()

# ----------------------------
# Auth yardımcıları
# ----------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return redirect(url_for("login", next=request.path))
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT is_admin FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
        if not row or row["is_admin"] != 1:
            abort(403)
        return f(*args, **kwargs)
    return decorated

def user_obj_from_session():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    return cur.fetchone()

# ----------------------------
# Utility helpers
# ----------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def now_iso():
    return datetime.utcnow().isoformat()

def log_request(username, endpoint, payload, response, status):
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO requests_log (username, endpoint, payload, response, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (username, endpoint, json.dumps(payload, ensure_ascii=False), json.dumps(response, ensure_ascii=False), status, now_iso()))
    db.commit()

def record_message(user_id, username, role, content, response):
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO messages (user_id, username, role, content, response, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, username, role, content, response, now_iso()))
    db.commit()

def add_admin_action(admin_user, action, target_user=None, extra=None):
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO admin_actions (admin_user, action, target_user, extra, created_at) VALUES (?, ?, ?, ?, ?)",
                (admin_user, action, target_user, extra or "", now_iso()))
    db.commit()

# ----------------------------
# Model / API integration
# ----------------------------
def call_groq_chat(prompt, model=GROQ_MODEL, max_tokens=512, temperature=0.2):
    """Try calling Groq API. Returns (success_bool, response_text_or_error)."""
    if not GROQ_API_KEY:
        return False, "Groq API anahtarı tanımlı değil."
    # NOTE: gerçek Groq endpoint ve payload formatı farklı olabilir; burada örnek bir POST kullanıyoruz.
    url = f"{GROQ_ENDPOINT}/models/{model}/generate"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "prompt": prompt,
        "max_output_tokens": max_tokens,
        "temperature": temperature,
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        text = r.text
        if r.status_code == 200:
            # Geri dönen json yapısına göre parse etmek gerekebilir.
            try:
                j = r.json()
                # farklı providerlarda farklı alanlar olur; mantıklı yerleri dene
                if isinstance(j, dict):
                    if "text" in j:
                        return True, j["text"]
                    # örnek: "output" : [{"content": "..."}]
                    if "outputs" in j and isinstance(j["outputs"], list):
                        content = ""
                        for o in j["outputs"]:
                            if isinstance(o, dict):
                                if "content" in o:
                                    content += o.get("content", "")
                                elif "text" in o:
                                    content += o.get("text", "")
                        if content:
                            return True, content
                # fallback: düz metin
                return True, text
            except Exception:
                return True, text
        else:
            # return error detail
            try:
                err = r.json()
                return False, f"Groq hata {r.status_code}: {err}"
            except Exception:
                return False, f"Groq hata {r.status_code}: {r.text}"
    except Exception as e:
        return False, f"Groq isteği başarısız: {str(e)}"

def call_hf_text(prompt, model=HF_TEXT_MODEL):
    """Call Hugging Face text model via inference API (requires HF_API_KEY)."""
    if not HF_API_KEY:
        return False, "Hugging Face API anahtarı tanımlı değil."
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        if r.status_code == 200:
            try:
                j = r.json()
                # HF usual structure: [{"generated_text":"..."}] or {"error":...}
                if isinstance(j, list) and len(j) > 0 and isinstance(j[0], dict):
                    if "generated_text" in j[0]:
                        return True, j[0]["generated_text"]
                if isinstance(j, dict) and "generated_text" in j:
                    return True, j["generated_text"]
                # fallback plain text
                return True, r.text
            except Exception:
                return True, r.text
        else:
            try:
                return False, f"HF hata {r.status_code}: {r.json()}"
            except Exception:
                return False, f"HF hata {r.status_code}: {r.text}"
    except Exception as e:
        return False, f"HF isteği başarısız: {str(e)}"

def generate_image_hf(prompt, model=HF_IMAGE_MODEL):
    """Simple wrapper to call HF image generation (inference API)"""
    if not HF_API_KEY:
        return False, "Hugging Face API anahtarı tanımlı değil."
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=120)
        if r.status_code == 200:
            # HF may return image bytes or a link. Here we expect base64 or bytes; handle generically.
            # For simplicity, we'll save bytes if present.
            content_type = r.headers.get("Content-Type", "")
            if "image" in content_type:
                # return raw bytes
                return True, r.content
            else:
                # maybe JSON with 'generated_image' or 'image_base64'
                try:
                    j = r.json()
                    return True, j
                except Exception:
                    return True, r.text
        else:
            try:
                return False, f"HF image hata {r.status_code}: {r.json()}"
            except Exception:
                return False, f"HF image hata {r.status_code}: {r.text}"
    except Exception as e:
        return False, f"HF image isteği başarısız: {str(e)}"

# ----------------------------
# Chat logic: önce Groq, sonra HF fall-back
# ----------------------------
def ask_king(prompt, username):
    """Ana chat function: önce Groq dene, başarısızsa HF'ye geç."""
    g_success, g_resp = call_groq_chat(prompt)
    if g_success:
        return True, g_resp, "groq"
    # log groq hata
    fallback_note = f"Groq başarısız: {g_resp}"
    # Try Hugging Face
    hf_success, hf_resp = call_hf_text(prompt)
    if hf_success:
        return True, hf_resp, "huggingface"
    # both failed
    return False, f"{fallback_note}\nHuggingFace başarısız: {hf_resp}", "none"

# ----------------------------
# Routes / Views (HTML inline templates)
# ----------------------------
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KralZeka v1</title>
  <style>
    :root{
      --bg:#071017;
      --card:#042224;
      --muted:#90a4a4;
      --accent:#16a085;
      --danger:#e74c3c;
      --panel:#032424;
      --text:#e6f7f5;
    }
    body{background:var(--bg);color:var(--text);font-family:Inter, system-ui, Arial;margin:0;padding:0;}
    .container{max-width:980px;margin:20px auto;padding:20px;}
    header{display:flex;justify-content:space-between;align-items:center;padding:10px 0;}
    .brand{font-size:22px;font-weight:700}
    .small{font-size:13px;color:var(--muted)}
    .card{background:linear-gradient(180deg,var(--card),#001818);padding:18px;border-radius:10px;box-shadow:0 6px 18px rgba(0,0,0,0.6);margin-bottom:16px}
    input[type=text], input[type=password], textarea{width:100%;padding:10px;border-radius:6px;border:1px solid rgba(255,255,255,0.05);background:transparent;color:var(--text)}
    button{background:var(--accent);color:#fff;border:0;padding:10px 14px;border-radius:8px;cursor:pointer}
    .muted{color:var(--muted)}
    .row{display:flex;gap:8px}
    .col{flex:1}
    .chat-box{max-height:360px;overflow:auto;padding:10px}
    .msg{padding:12px;border-radius:8px;margin-bottom:8px}
    .msg.user{background:rgba(255,255,255,0.03);text-align:left}
    .msg.kbot{background:rgba(0,0,0,0.15);border-left:4px solid var(--accent);text-align:left}
    footer{padding:20px;text-align:center;color:var(--muted)}
    a{color:var(--accent)}
    .danger{background:var(--danger)}
    nav a{margin-left:12px;color:var(--muted)}
    .badge{background:#222;padding:6px 10px;border-radius:50px;color:var(--muted);font-size:13px}
    .admin-link{color:#ffd166}
  </style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <div class="brand">KralZeka v1</div>
      <div class="small">KralZeka, Enes'in zekasıyla hayat buldu.</div>
    </div>
    <div>
      {% if current_user %}
        <span class="badge">Merhaba, {{ current_user['username'] }} {% if current_user['is_admin'] %}[ADMIN]{% endif %}</span>
        <nav>
          <a href="{{ url_for('logout') }}">Çıkış yap</a>
          {% if current_user['is_admin'] %}
            <a href="{{ url_for('admin_panel') }}" class="admin-link">Admin Panel</a>
          {% endif %}
        </nav>
      {% else %}
        <a href="{{ url_for('login') }}"><button>Giriş</button></a>
        <a href="{{ url_for('register') }}"><button style="background:#1b6f5c">Kayıt</button></a>
      {% endif %}
    </div>
  </header>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="card">
        {% for m in messages %}
          <div class="small">{{ m }}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  {% block body %}{% endblock %}

  <footer>
    © KralZeka v1 — KralZeka, Enes'in zekasıyla hayat buldu.
  </footer>
</div>
</body>
</html>
"""

INDEX_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Modlar</h3>
    <div class="row" style="margin-top:10px">
      <div class="col card" style="min-width:180px">
        <h4>Ödev Modu</h4>
        <div class="small">Ders, çalışma kağıtları, sınav hazırlığı ve görselleri çözümle.</div>
        <button onclick="selectMode('homework')">Seç</button>
      </div>
      <div class="col card">
        <h4>Espri Modu</h4>
        <div class="small">Rastgele şakalar, hafif sohbetler.</div>
        <button onclick="selectMode('joke')">Seç</button>
      </div>
      <div class="col card">
        <h4>Sohbet Modu</h4>
        <div class="small">Normal sohbet modu.</div>
        <button onclick="selectMode('chat')">Seç</button>
      </div>
    </div>
  </div>

  <div class="card">
    <h3>Konuşma</h3>
    <div class="small">Sol üstten bir mod seç (veya otomatik bırak) — cevaplar Groq ile alınır, sorun olursa HuggingFace ile devam edilir.</div>
    <div style="margin-top:12px">
      <div class="row">
        <input id="prompt" type="text" placeholder="Nasılsın? Bugün bana bir soru sor..." />
        <button onclick="sendPrompt()">Gönder</button>
      </div>
      <div class="chat-box card" id="chatbox" style="margin-top:12px"></div>
    </div>
  </div>

  <script>
    let mode = 'chat';
    function selectMode(m){
      mode = m;
      alert("Mod seçildi: " + m);
    }
    async function sendPrompt(){
      const p = document.getElementById('prompt').value;
      if(!p) return;
      addMsg('Sen', p, 'user');
      document.getElementById('prompt').value = '';
      // send to /api/chat
      const res = await fetch('/api/chat', {
        method:'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({prompt:p, mode:mode})
      });
      const j = await res.json();
      if(j.ok){
        addMsg('KralZeka', j.response, 'kbot');
      } else {
        addMsg('KralZeka', 'Hata: '+j.error, 'kbot');
      }
    }
    function addMsg(who, text, cls){
      const box = document.getElementById('chatbox');
      const d = document.createElement('div');
      d.className = 'msg ' + (cls || 'user');
      d.innerHTML = '<strong>' + who + ':</strong> '+ text;
      box.appendChild(d);
      box.scrollTop = box.scrollHeight;
    }
  </script>
{% endblock %}
"""

LOGIN_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card" style="max-width:480px;margin:auto">
    <h3>Giriş</h3>
    <form method="post">
      <label>Kullanıcı adı</label>
      <input type="text" name="username" required />
      <label>Şifre</label>
      <input type="password" name="password" required />
      <div style="margin-top:10px"><button type="submit">Giriş</button></div>
    </form>
    <div class="small" style="margin-top:12px">Henüz hesabın yok mu? <a href="{{ url_for('register') }}">Kayıt ol</a></div>
  </div>
{% endblock %}
"""

REGISTER_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card" style="max-width:480px;margin:auto">
    <h3>Kayıt</h3>
    <form method="post">
      <label>Kullanıcı adı</label>
      <input type="text" name="username" required />
      <label>Şifre</label>
      <input type="password" name="password" required />
      <label>Şifre (tekrar)</label>
      <input type="password" name="password2" required />
      <div style="margin-top:10px"><button type="submit">Kayıt ol</button></div>
    </form>
  </div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Admin Panel</h3>
    <div class="small">Buradan kullanıcı yönetimi, limit ayarı, istekleri görüntüleme ve otomatik hata düzeltme işlemleri yapılır.</div>
    <hr>
    <h4>Kullanıcılar</h4>
    <div>
      <table style="width:100%; border-collapse: collapse;">
        {% for u in users %}
        <tr>
          <td style="padding:8px;background:#011515;border-bottom:1px solid rgba(255,255,255,0.02)"><strong>{{u['username']}}</strong> {% if u['protected'] %}<span class="small">[KORUNMUŞ]</span>{% endif %}</td>
          <td style="padding:8px;background:#011515;text-align:right">
            {% if not u['protected'] %}
              {% if not u['is_admin'] %}
                <button onclick="adminAction('promote','{{u['username']}}')">Admin Yap</button>
              {% else %}
                <button onclick="adminAction('demote','{{u['username']}}')">Adminlıktan Al</button>
              {% endif %}
              <button style="background:var(--danger)" onclick="adminAction('delete','{{u['username']}}')">Sil</button>
            {% else %}
              <span class="small">İlk admin korumalı</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </table>
    </div>
    <hr>
    <h4>İstek kaydı</h4>
    <div class="small">Son 20 istek</div>
    <div style="margin-top:8px">
      {% for r in requests %}
        <div class="card small" style="margin-bottom:8px">
          <div><strong>{{ r['username'] or 'anon' }}</strong> - {{ r['endpoint'] }} - {{ r['created_at'] }}</div>
          <div>{{ r['payload'] }}</div>
        </div>
      {% endfor %}
    </div>

    <hr>
    <h4>Otomatik hata düzeltme (Admin özel)</h4>
    <div class="small">Sistemi analiz edip onarım önerileri üretecek (onay gerektirir).</div>
    <div style="margin-top:8px">
      <button onclick="selfInspect()">Sistemi İncele</button>
      <div id="inspectResult" style="margin-top:8px"></div>
    </div>
  </div>

  <script>
    async function adminAction(action, username){
      if(!confirm(action + ' işlemini onaylıyor musunuz?')) return;
      const res = await fetch('/admin/action', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({action:action, username:username})
      });
      const j = await res.json();
      alert(j.message || JSON.stringify(j));
      if(j.ok) location.reload();
    }
    async function selfInspect(){
      const btn = event.target;
      btn.disabled = true;
      const res = await fetch('/admin/inspect', {method:'POST'});
      const j = await res.json();
      document.getElementById('inspectResult').innerText = JSON.stringify(j, null, 2);
      btn.disabled = false;
    }
  </script>
{% endblock %}
"""

# ----------------------------
# Template rendering helper
# ----------------------------
@app.context_processor
def inject_user():
    user = None
    uid = session.get("user_id")
    if uid:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
        if row:
            user = dict(row)
    return dict(current_user=user)

from jinja2 import Template
# Preload templates
TEMPLATES = {
    "base": Template(BASE_HTML),
    "index": Template(INDEX_HTML),
    "login": Template(LOGIN_HTML),
    "register": Template(REGISTER_HTML),
    "admin": Template(ADMIN_HTML),
}

def render(name, **ctx):
    # Render nested templates by providing base as a template inheritance root.
    # Our TEMPLATES are naive, so implement simple replacement: the child extends "base" -> we render base with child block.
    if name == "base":
        return TEMPLATES["base"].render(**ctx)
    base_src = TEMPLATES["base"].source
    # Use jinja built-in: render from child template that extends base is complex; simpler: render child's body into base.
    # Our child templates use {% extends "base" %} and blocks — we bypass and replace block marker.
    # Get child's body by rendering child without the extends tag:
    child_src = TEMPLATES[name].source
    # Remove the extends line if present and extract block content between {% block body %} ... {% endblock %}
    body = ""
    import re
    m = re.search(r'\{%\s*block\s+body\s*%}(.+?)\{%\s*endblock\s*%}', child_src, flags=re.S)
    if m:
        body = m.group(1)
    # Now render base with block replaced
    return TEMPLATES["base"].render(**ctx).replace("{% block body %}{% endblock %}", body)

# ----------------------------
# Web routes
# ----------------------------
@app.route("/")
def index():
    # homepage
    return render("index")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            cur.execute("UPDATE users SET last_seen=? WHERE id=?", (now_iso(), row["id"]))
            db.commit()
            flash("Giriş başarılı.")
            return redirect(url_for("index"))
        else:
            flash("Kullanıcı adı veya şifre hatalı.")
    return render("login")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        password2 = request.form.get("password2","")
        if password != password2:
            flash("Şifreler uyuşmuyor.")
            return render("register")
        db = get_db()
        cur = db.cursor()
        try:
            pw_hash = generate_password_hash(password)
            now = now_iso()
            cur.execute("INSERT INTO users (username, password_hash, is_admin, quota_quality_daily, created_at) VALUES (?, ?, 0, ?, ?)",
                        (username, pw_hash, DAILY_QUALITY_LIMIT, now))
            db.commit()
            flash("Kayıt başarılı. Giriş yapabilirsiniz.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Bu kullanıcı adı zaten alınmış.")
    return render("register")

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.")
    return redirect(url_for("index"))

# API: chat
@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json() or {}
    prompt = data.get("prompt","").strip()
    mode = data.get("mode","chat")
    if not prompt:
        return jsonify(ok=False, error="Boş prompt.")
    user = user_obj_from_session()
    username = user['username'] if user else "anon"
    # Optionally extend prompt with mode-specific system instruction
    mode_prompt = prompt
    if mode == "homework":
        mode_prompt = "Ödev modu. Adım adım açıkla ve öğrenci dostu cevap ver. Soru: " + prompt
    elif mode == "joke":
        mode_prompt = "Espri yap, kısa ve eğlenceli ol: " + prompt
    elif mode == "presentation":
        mode_prompt = "Sunum modu: madde madde ve slayt notları şeklinde hazırla: " + prompt
    # Query
    success, response_text, engine = ask_king(mode_prompt, username)
    # Log
    record_message(user_id=user['id'] if user else None, username=username, role="user", content=prompt, response=response_text if success else "")
    log_request(username, "/api/chat", {"prompt":prompt, "mode":mode}, {"ok":success, "engine":engine, "resp":response_text}, 200 if success else 500)
    if success:
        return jsonify(ok=True, engine=engine, response=response_text)
    else:
        return jsonify(ok=False, error=response_text), 500

# Image upload endpoint
@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        return jsonify(ok=False, error="Dosya gönderilmedi."), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify(ok=False, error="Dosya adı boş."), 400
    if f and allowed_file(f.filename):
        filename = secure_filename(f.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(path)
        # Optionally process the image (e.g., OCR, HF image understanding) - placeholder
        response_note = "Görsel yüklendi."
        return jsonify(ok=True, filename=filename, note=response_note)
    else:
        return jsonify(ok=False, error="Geçersiz dosya tipi."), 400

# Admin panel
@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, is_admin, quota_quality_daily, created_at, protected FROM users ORDER BY created_at DESC")
    users = [dict(r) for r in cur.fetchall()]
    # requests log: latest 20
    cur.execute("SELECT username, endpoint, payload, created_at FROM requests_log ORDER BY id DESC LIMIT 20")
    requests_log = [dict(r) for r in cur.fetchall()]
    return render("admin", users=users, requests=requests_log)

@app.route("/admin/action", methods=["POST"])
@admin_required
def admin_action():
    payload = request.get_json() or {}
    action = payload.get("action")
    target = payload.get("username")
    admin = user_obj_from_session()
    if not action or not target:
        return jsonify(ok=False, message="Eksik parametre"), 400
    db = get_db()
    cur = db.cursor()
    # Don't allow altering protected user (first admin)
    cur.execute("SELECT id, protected, is_admin FROM users WHERE username=?", (target,))
    trow = cur.fetchone()
    if not trow:
        return jsonify(ok=False, message="Kullanıcı bulunamadı."), 404
    if trow["protected"] == 1:
        # Log attempt
        add_admin_action(admin['username'], f"attempted_{action}_protected", target_user=target, extra="attempt_denied")
        return jsonify(ok=False, message="Bu kullanıcı korunmaktadır; işlem reddedildi."), 403
    if action == "promote":
        cur.execute("UPDATE users SET is_admin=1 WHERE username=?", (target,))
        db.commit()
        add_admin_action(admin['username'], "promote", target_user=target)
        return jsonify(ok=True, message="Kullanıcı admin yapıldı.")
    if action == "demote":
        cur.execute("UPDATE users SET is_admin=0 WHERE username=?", (target,))
        db.commit()
        add_admin_action(admin['username'], "demote", target_user=target)
        return jsonify(ok=True, message="Kullanıcı adminlikten alındı.")
    if action == "delete":
        cur.execute("DELETE FROM users WHERE username=?", (target,))
        db.commit()
        add_admin_action(admin['username'], "delete_user", target_user=target)
        return jsonify(ok=True, message="Kullanıcı silindi.")
    return jsonify(ok=False, message="Bilinmeyen işlem."), 400

@app.route("/admin/inspect", methods=["POST"])
@admin_required
def admin_inspect():
    """Basit sistem kontrolü (placeholder). Admin onayı ile hata düzeltme önerileri üretir."""
    # Basit checks:
    problems = []
    # chk db size
    try:
        db_path = app.config['DATABASE']
        if os.path.exists(db_path):
            size = os.path.getsize(db_path)
            if size > 50 * 1024 * 1024:
                problems.append(f"DB büyük: {size/1024/1024:.2f}MB")
        else:
            problems.append("DB dosyası yok.")
    except Exception as e:
        problems.append(f"DB kontrolü hata: {e}")
    # check HF/GROQ keys
    if not HF_API_KEY:
        problems.append("HF_API_KEY tanımlı değil.")
    if not GROQ_API_KEY:
        problems.append("GROQ_API_KEY tanımlı değil.")
    # produce suggestions
    suggestions = []
    if "HF_API_KEY tanımlı değil." in problems:
        suggestions.append("Hugging Face API anahtarını environment'a ekleyin: HF_API_KEY")
    if "GROQ_API_KEY tanımlı değil." in problems:
        suggestions.append("Groq API anahtarını environment'a ekleyin: GROQ_API_KEY")
    # return result
    res = {"ok": True, "problems": problems, "suggestions": suggestions}
    add_admin_action(user_obj_from_session()['username'], "inspect", extra=json.dumps(res, ensure_ascii=False))
    return jsonify(res)

# Simple route to serve uploaded files
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

# Healthcheck
@app.route("/health")
def health():
    return jsonify(status="ok", time=now_iso())

# ----------------------------
# Startup
# ----------------------------
def start_app():
    # Create DB if not exists
    init_db(force=False)
    # start Flask
    app.run(host="0.0.0.0", port=PORT, debug=False)

if __name__ == "__main__":
    start_app()
