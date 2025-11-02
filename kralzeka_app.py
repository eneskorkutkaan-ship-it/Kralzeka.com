#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka Full — tek dosya Flask uygulaması
- Admin-only Kod Öğretmeni modu dahil
- Modlar: sohbet, ödev, espri, sunum, görsel
- Groq model adı kod içinde sabitlenmiştir
- Ortam değişkenleri:
    GROQ_API_KEY, HF_API_KEY, FLASK_SECRET
Çalıştırma: python3 kralzeka_full.py
"""

import os
import io
import re
import time
import json
import sqlite3
import base64
import uuid
import traceback
from datetime import datetime, date, timedelta
from functools import wraps

import requests
from flask import (
    Flask, g, render_template_string, request, redirect, url_for, session,
    flash, jsonify, send_file, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- Config ----------------
APP_NAME = "KralZeka Full"
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "kralzeka_full.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Env keys (must be set by user)
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
HF_API_KEY = os.environ.get("HF_API_KEY", "")
FLASK_SECRET = os.environ.get("FLASK_SECRET", "change_this_randomly")

# Groq model (hardcoded as requested)
GROQ_MODEL = "llama-3.1-8b-instant"

# Default HF image model (can be changed in code later)
HF_IMAGE_MODEL = os.environ.get("HF_IMAGE_MODEL", "stabilityai/stable-diffusion-2")

# Limits
DAILY_IMAGE_LIMIT = 5
RATE_MIN_SECONDS = 0.8

ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}
MAX_UPLOAD_MB = 20

# initial admin
INITIAL_ADMIN_USERNAME = "enes"
INITIAL_ADMIN_PASSWORD = "enes1357924680"

# Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = FLASK_SECRET
app.config["DATABASE"] = DB_PATH
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# ---------------- DB Helpers ----------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      mode TEXT,
      content TEXT,
      reply TEXT,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS feature_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      text TEXT,
      status TEXT DEFAULT 'open',
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS uploads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      filename TEXT,
      path TEXT,
      kind TEXT,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      date TEXT,
      images_used INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS admin_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_user TEXT,
      action TEXT,
      target TEXT,
      meta TEXT,
      created_at TEXT
    );
    """)
    db.commit()
    # ensure initial admin exists
    row = db.execute("SELECT * FROM users WHERE username = ?", (INITIAL_ADMIN_USERNAME,)).fetchone()
    if not row:
        db.execute("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)",
                   (INITIAL_ADMIN_USERNAME, generate_password_hash(INITIAL_ADMIN_PASSWORD), datetime.utcnow().isoformat()))
        db.commit()

# ---------------- Auth Helpers ----------------
def login_user(user_row):
    session['user_id'] = user_row['id']
    session['username'] = user_row['username']
    session['is_admin'] = bool(user_row['is_admin'])
    session.permanent = True

def logout_user():
    session.clear()

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def require_login(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            abort(403)
        return f(*a, **kw)
    return wrapper

# ---------------- Rate limit (simple) ----------------
_last_request_time = {}

def rate_ok(key, min_seconds=RATE_MIN_SECONDS):
    now = time.time()
    prev = _last_request_time.get(key)
    if prev and now - prev < min_seconds:
        return False
    _last_request_time[key] = now
    return True

# ---------------- Utilities ----------------
def save_upload_file(fileobj, filename_prefix="file"):
    ext = filename_prefix.rsplit('.', 1)[-1] if '.' in filename_prefix else 'dat'
    fn = f"{filename_prefix}_{int(time.time())}_{uuid.uuid4().hex[:8]}.{ext}"
    fn = secure_filename(fn)
    path = os.path.join(app.config['UPLOAD_FOLDER'], fn)
    fileobj.save(path)
    return fn, path

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.',1)[1].lower()
    return ext in ALLOWED_IMAGE_EXT

# ---------------- External APIs ----------------
def call_groq_chat(prompt, system_prompt=None, model=None, temperature=0.2, max_tokens=800):
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY yok. Ortam değişkenine ekle.")
    url = "https://api.groq.com/openai/v1/chat/completions"
    model_name = model or GROQ_MODEL
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    payload = {"model": model_name, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"Groq hata {resp.status_code}: {resp.text}")
    data = resp.json()
    # robust parsing
    if isinstance(data, dict) and "choices" in data and data["choices"]:
        c = data["choices"][0]
        msg = c.get("message") or c
        if isinstance(msg, dict):
            return msg.get("content") or str(msg)
        return str(msg)
    return str(data)

def call_hf_image(model_id, prompt, wait_for_model=True):
    if not HF_API_KEY:
        raise RuntimeError("HF_API_KEY yok. Ortam değişkenine ekle.")
    url = f"https://api-inference.huggingface.co/models/{model_id}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt, "options": {"wait_for_model": wait_for_model}}
    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"HF hata {resp.status_code}: {resp.text}")
    ct = resp.headers.get("content-type","")
    if "application/json" in ct:
        j = resp.json()
        # check for base64 in json
        # some models return {'generated_images': [b64,...]}
        if isinstance(j, dict):
            # try common keys
            for k in ("image_base64","generated_image","generated_images","images"):
                if k in j:
                    v = j[k]
                    if isinstance(v, list) and v:
                        b64 = v[0]
                        return base64.b64decode(b64) if isinstance(b64, str) and b64.startswith("data:") else base64.b64decode(b64)
            # fallback search strings
            s = json.dumps(j)
            b64match = re.search(r"data:image/[^;]+;base64,([A-Za-z0-9+/=]+)", s)
            if b64match:
                return base64.b64decode(b64match.group(1))
        raise RuntimeError("HF: beklenmeyen JSON format")
    else:
        # binary image bytes
        return resp.content

# ---------------- Simple web search fallback ----------------
DUCKHTML = "https://html.duckduckgo.com/html/"

def duckduckgo_search(query, max_results=4):
    try:
        r = requests.post(DUCKHTML, data={"q": query}, headers={"User-Agent":"Mozilla/5.0"}, timeout=12)
        if r.status_code != 200:
            return []
        text = r.text
        items = []
        link_re = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.S|re.I)
        snippet_re = re.compile(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.S|re.I)
        links = link_re.findall(text)
        snippets = snippet_re.findall(text)
        for i,(href, title) in enumerate(links[:max_results]):
            title = re.sub('<[^>]+>', '', title).strip()
            sn = snippets[i] if i<len(snippets) else ""
            sn = re.sub('<[^>]+>', '', sn).strip()
            items.append((title, href, sn))
        return items
    except Exception:
        return []

def fetch_page_text(url, max_chars=2000):
    try:
        r = requests.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=10)
        if r.status_code != 200:
            return ""
        html = r.text
        html = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', html, flags=re.S|re.I)
        text = re.sub('<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', text).strip()
        if len(text) > max_chars:
            return text[:max_chars]
        return text
    except Exception:
        return ""

def synthesize_from_pages(question, pages):
    qtokens = [t for t in re.findall(r'\w+', question.lower()) if len(t)>3]
    cand = []
    for p in pages:
        for sent in re.split(r'(?<=[\.\?\!])\s+', p):
            s = sent.strip()
            if len(s) < 40: continue
            score = sum(1 for t in qtokens if t in s.lower())
            if score>0:
                cand.append((score, s))
    cand.sort(key=lambda x:(-x[0], -len(x[1])))
    if not cand:
        return None
    out = " ".join([c[1] for c in cand[:3]])
    return out

# ---------------- Answer flow ----------------
def answer_question_flow(user, question, mode="chat"):
    # 1) Try Groq
    try:
        sys_prompt = None
        if mode == "homework":
            sys_prompt = "Ödev yardımcısı: detaylı, adım adım açıkla, örnek çözüm ver."
        elif mode == "jokes":
            sys_prompt = "Kısa ve etik şaka üret."
        elif mode == "presentation":
            sys_prompt = "Sunum modu: başlıklar ve maddeler halinde sun."
        else:
            sys_prompt = "Türkçe, kibar, yardımcı cevap ver."
        if GROQ_API_KEY:
            try:
                text = call_groq_chat(question, system_prompt=sys_prompt)
                return text
            except Exception as e:
                # log admin action
                get_db().execute("INSERT INTO admin_logs (admin_user, action, target, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                                 (user['username'] if user else 'anon', "GROQ_FAIL", question, str(e), datetime.utcnow().isoformat()))
                get_db().commit()
        # 2) Fallback: web search + synth
        hits = duckduckgo_search(question, max_results=4)
        pages = []
        for t,href,sn in hits:
            txt = fetch_page_text(href)
            if txt:
                pages.append(txt)
            elif sn:
                pages.append(sn)
            time.sleep(RATE_MIN_SECONDS)
        if pages:
            synth = synthesize_from_pages(question, pages)
            if synth:
                return synth
        return "Bu konuda doğrudan bilgi bulamadım; daha spesifik sorar mısın?"
    except Exception as e:
        return "Cevap oluşturulamadı: " + str(e)

# ---------------- Routes & UI ----------------
# Basic templates (Bootstrap) - kept inline for single-file deployment
INDEX_HTML = """<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ app_name }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body { background:#071018; color:#e6f7f4; font-family:Inter,Arial; }
.sidebar { width:260px; }
.card-dark { background:#072827; color:#e6f7f4; }
.chat-user { background:#0b7f5f; color:#001; padding:10px;border-radius:8px; }
.chat-kral { background:#f3f5a7; color:#072; padding:10px;border-radius:8px; }
.small-muted { color:#98bfb6; font-size:0.9em; }
</style>
</head><body>
<div class="container py-3">
  <div class="d-flex justify-content-between mb-2">
    <div><h2>{{ app_name }}</h2><div class="small-muted">Merhaba {{ username }} {% if is_admin %}(ADMIN){% endif %}</div></div>
    <div>
      {% if logged_in %}
        <a class="btn btn-sm btn-outline-light" href="{{ url_for('logout') }}">Çıkış</a>
        {% if is_admin %}<a class="btn btn-sm btn-warning" href="{{ url_for('admin_panel') }}">Admin Panel</a>{% endif %}
      {% else %}
        <a class="btn btn-sm btn-success" href="{{ url_for('login') }}">Giriş</a>
        <a class="btn btn-sm btn-secondary" href="{{ url_for('register') }}">Kayıt</a>
      {% endif %}
    </div>
  </div>

  <div class="d-flex">
    <div class="sidebar me-3">
      <div class="card card-dark p-3 mb-3">
        <h5>Modlar</h5>
        <div class="list-group">
          <a href="#" class="list-group-item list-group-item-action mode-btn active" data-mode="chat">Sohbet</a>
          <a href="#" class="list-group-item list-group-item-action mode-btn" data-mode="homework">Ödev Yardımı</a>
          <a href="#" class="list-group-item list-group-item-action mode-btn" data-mode="jokes">Espri Modu</a>
          <a href="#" class="list-group-item list-group-item-action mode-btn" data-mode="presentation">Sunum Modu</a>
          <a href="#" class="list-group-item list-group-item-action mode-btn" data-mode="image">Görsel / Kalite</a>
        </div>
      </div>

      <div class="card card-dark p-3">
        <h6>Hızlı</h6>
        <p class="small-muted">Görsel kalite: normal kullanıcı günlük {{ daily_limit }} kullanım. Admin sınırsız.</p>
        <p class="small-muted">Model: <strong>{{ groq_model }}</strong></p>
      </div>
    </div>

    <div class="flex-fill">
      <div class="card card-dark p-3 mb-3">
        <div id="chatbox" style="height:360px;overflow:auto;">
          {% for m in messages %}
            {% if m.username != 'KralZeka' %}
              <div class="mb-3"><div class="chat-user">{{ m.content }}</div><div class="small-muted mt-1">{{ m.created_at }} - {{ m.username }}</div></div>
            {% else %}
              <div class="mb-3"><div class="chat-kral">{{ m.reply or m.content }}</div><div class="small-muted mt-1">{{ m.created_at }} - KralZeka</div></div>
            {% endif %}
          {% endfor %}
        </div>

        <div class="mt-3 d-flex">
          <input id="prompt" class="form-control me-2" placeholder="Sorunu yaz...">
          <button id="sendBtn" class="btn btn-success">Gönder</button>
        </div>
        <div class="mt-2 small-muted">Not: Web araması gösterilmeyecek; doğrudan son cevabı göreceksin.</div>
      </div>

      <div id="panel" class="card card-dark p-3">
        <h5>Son İşlemler</h5>
        <div class="small-muted">Buraya son işlemler yansır.</div>
      </div>
    </div>
  </div>

  <div class="mt-3 small-muted">KralZeka © — Kurucu: Enes</div>
</div>

<script>
let curMode = 'chat';
document.querySelectorAll('.mode-btn').forEach(btn=>{
  btn.addEventListener('click', function(e){
    e.preventDefault();
    document.querySelectorAll('.mode-btn').forEach(x=>x.classList.remove('active'));
    this.classList.add('active');
    curMode = this.dataset.mode;
    alert('Mod seçildi: ' + curMode + ' (Örnek arayüz)');
  });
});
document.getElementById('sendBtn').addEventListener('click', send);
document.getElementById('prompt').addEventListener('keydown', function(e){ if(e.key==='Enter') send(); });
async function send(){
  const q = document.getElementById('prompt').value.trim();
  if(!q) return;
  document.getElementById('prompt').value='';
  const resp = await fetch('/api/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({q:q,mode:curMode})});
  const j = await resp.json();
  if(j.ok){
    // append message and reply
    const cb = document.getElementById('chatbox');
    cb.innerHTML += '<div class="mb-3"><div class="chat-user">' + q + '</div><div class="small-muted mt-1">' + new Date().toLocaleString() + ' - Sen</div></div>';
    cb.innerHTML += '<div class="mb-3"><div class="chat-kral">' + j.answer + '</div><div class="small-muted mt-1">' + new Date().toLocaleString() + ' - KralZeka</div></div>';
    cb.scrollTop = cb.scrollHeight;
  } else {
    alert('Hata: ' + (j.error || 'bilinmeyen'));
  }
}
</script>
</body></html>
"""

# ---------------- Routes ----------------
@app.before_request
def before_request():
    init_db()
    g.user = None
    if 'user_id' in session:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()

@app.route('/')
def index():
    rows = query_db("SELECT * FROM messages ORDER BY id DESC LIMIT 20")
    msgs = [dict(r) for r in rows][::-1]
    u = current_user()
    return render_template_string(INDEX_HTML,
                                  app_name=APP_NAME,
                                  username=(u['username'] if u else 'ziyaretçi'),
                                  logged_in=bool(u),
                                  is_admin=bool(u['is_admin']) if u else False,
                                  messages=msgs,
                                  daily_limit=DAILY_IMAGE_LIMIT,
                                  groq_model=GROQ_MODEL)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        uname = (request.form.get('username') or '').strip()
        pw = request.form.get('password') or ''
        pw2 = request.form.get('password2') or ''
        if not uname or not pw:
            flash("Kullanıcı adı ve şifre gerekli.", "warn")
            return redirect(url_for('register'))
        if pw != pw2:
            flash("Şifreler eşleşmiyor.", "warn")
            return redirect(url_for('register'))
        existing = query_db("SELECT * FROM users WHERE username = ?", (uname,), one=True)
        if existing:
            flash("Kullanıcı adı alınmış.", "warn")
            return redirect(url_for('register'))
        db = get_db()
        db.execute("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                   (uname, generate_password_hash(pw), datetime.utcnow().isoformat()))
        db.commit()
        flash("Kayıt başarılı. Giriş yapabilirsin.", "info")
        return redirect(url_for('login'))
    return render_template_string("""
    <!doctype html><html><head><meta charset='utf-8'><title>Kayıt</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-dark text-light p-4">
    <div class="container"><h3>Kayıt Ol</h3>
    <form method="post">
      <input name="username" class="form-control mb-2" placeholder="Kullanıcı adı">
      <input name="password" type="password" class="form-control mb-2" placeholder="Şifre">
      <input name="password2" type="password" class="form-control mb-2" placeholder="Şifre tekrar">
      <button class="btn btn-success">Kayıt</button>
    </form>
    <a href="{{ url_for('login') }}" class="text-light">Giriş yap</a>
    </div></body></html>
    """)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        uname = (request.form.get('username') or '').strip()
        pw = request.form.get('password') or ''
        row = query_db("SELECT * FROM users WHERE username = ?", (uname,), one=True)
        if not row or not check_password_hash(row['password_hash'], pw):
            flash("Kullanıcı adı veya şifre hatalı.", "warn")
            return redirect(url_for('login'))
        login_user(row)
        flash("Giriş yapıldı.", "info")
        return redirect(url_for('index'))
    return render_template_string("""
    <!doctype html><html><head><meta charset='utf-8'><title>Giriş</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-dark text-light p-4">
    <div class="container"><h3>Giriş</h3>
    <form method="post">
      <input name="username" class="form-control mb-2" placeholder="Kullanıcı">
      <input name="password" type="password" class="form-control mb-2" placeholder="Şifre">
      <button class="btn btn-success">Giriş</button>
    </form>
    <a href="{{ url_for('register') }}" class="text-light">Kayıt ol</a>
    </div></body></html>
    """)

@app.route('/logout')
def logout():
    logout_user()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for('index'))

# ---------------- Helper DB query wrapper ----------------
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# ---------------- Chat API ----------------
@app.route('/api/chat', methods=['POST'])
def api_chat():
    data = request.get_json() or {}
    q = (data.get('q') or '').strip()
    mode = data.get('mode') or 'chat'
    if not q:
        return jsonify(ok=False, error="Boş soru"), 400
    user = current_user()
    uname = user['username'] if user else 'anon'
    uid = user['id'] if user else None
    # store
    db = get_db()
    db.execute("INSERT INTO messages (user_id, username, mode, content, created_at) VALUES (?, ?, ?, ?, ?)",
               (uid, uname, mode, q, datetime.utcnow().isoformat()))
    db.commit()
    # generate
    try:
        answer = answer_question_flow(user, q, mode=mode)
    except Exception as e:
        answer = "Cevap oluşturulamadı: " + str(e)
    # update last message
    last = db.execute("SELECT id FROM messages ORDER BY id DESC LIMIT 1").fetchone()
    if last:
        db.execute("UPDATE messages SET reply = ? WHERE id = ?", (answer, last['id']))
        db.commit()
    return jsonify(ok=True, answer=answer)

# ---------------- Upload endpoint ----------------
@app.route('/upload', methods=['POST'])
@require_login
def upload():
    if 'file' not in request.files:
        flash("Dosya seçilmedi.", "warn")
        return redirect(url_for('index'))
    f = request.files['file']
    if f.filename == '':
        flash("Dosya adı boş.", "warn")
        return redirect(url_for('index'))
    if not allowed_file(f.filename):
        flash("Geçersiz dosya türü.", "warn")
        return redirect(url_for('index'))
    fn = secure_filename(f"{session.get('username')}_{int(time.time())}_{f.filename}")
    path = os.path.join(app.config['UPLOAD_FOLDER'], fn)
    f.save(path)
    db = get_db()
    db.execute("INSERT INTO uploads (user_id, username, filename, path, kind, created_at) VALUES (?, ?, ?, ?, ?, ?)",
               (session.get('user_id'), session.get('username'), fn, path, 'user_upload', datetime.utcnow().isoformat()))
    db.commit()
    flash("Yüklendi.", "info")
    return redirect(url_for('index'))

@app.route('/uploads/<filename>')
@require_login
def serve_upload(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        abort(404)
    return send_file(path)

# ---------------- Image generation (HF) ----------------
@app.route('/admin/generate_image', methods=['POST'])
@require_admin
def admin_generate_image():
    # Admin-only interface to generate images with HF (for testing / preview)
    body = request.form
    prompt = (body.get('prompt') or '').strip()
    model = (body.get('model') or HF_IMAGE_MODEL).strip()
    if not prompt:
        flash("Prompt boş.", "warn")
        return redirect(url_for('admin_panel'))
    try:
        img_bytes = call_hf_image(model, prompt)
        fn, path = save_image_bytes(img_bytes, prefix=f"admin_{session.get('username')}")
        get_db().execute("INSERT INTO uploads (user_id, username, filename, path, kind, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                         (session.get('user_id'), session.get('username'), fn, path, 'hf_generated', datetime.utcnow().isoformat()))
        get_db().commit()
        flash("Görsel oluşturuldu.", "info")
        return redirect(url_for('serve_upload', filename=fn))
    except Exception as e:
        flash("Görsel oluşturulamadı: " + str(e), "warn")
        return redirect(url_for('admin_panel'))

# ---------------- Admin panel & Code Teacher ----------------
@app.route('/admin', methods=['GET','POST'])
@require_admin
def admin_panel():
    db = get_db()
    # POST handles actions: promote / delete / resolve request / code teacher / autofix
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'promote':
            uid = request.form.get('user_id')
            user = query_db("SELECT * FROM users WHERE id = ?", (uid,), one=True)
            if user:
                if user['username'] == INITIAL_ADMIN_USERNAME:
                    flash("Enes adminliği korunuyor.", "warn")
                else:
                    db.execute("UPDATE users SET is_admin=1 WHERE id = ?", (uid,))
                    db.execute("INSERT INTO admin_logs (admin_user, action, target, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                               (session.get('username'), "PROMOTE", user['username'], None, datetime.utcnow().isoformat()))
                    db.commit()
                    flash("Kullanıcı admin yapıldı.", "info")
        elif action == 'delete':
            uid = request.form.get('user_id')
            user = query_db("SELECT * FROM users WHERE id = ?", (uid,), one=True)
            if user:
                if user['username'] == INITIAL_ADMIN_USERNAME:
                    flash("Enes silinemez!", "warn")
                else:
                    db.execute("DELETE FROM users WHERE id = ?", (uid,))
                    db.execute("INSERT INTO admin_logs (admin_user, action, target, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                               (session.get('username'), "DELETE", user['username'], None, datetime.utcnow().isoformat()))
                    db.commit()
                    flash("Kullanıcı silindi.", "info")
        elif action == 'code_teacher':
            # Admin requests coded tutorial
            topic = (request.form.get('topic') or '').strip()
            lang = (request.form.get('lang') or 'python').strip()
            level = (request.form.get('level') or 'beginner').strip()
            extra = (request.form.get('extra') or '').strip()
            if not topic:
                flash("Konu boş.", "warn")
                return redirect(url_for('admin_panel'))
            prompt = f"Türkçe olarak bir {lang} öğreticisi hazırla. Seviye: {level}. Konu: {topic}. Ek: {extra}. Açıklama, örnek kod ve kısa alıştırma ver."
            try:
                out = call_groq_chat(prompt, system_prompt="KralZeka Kod Öğretmeni - Türkçe")
            except Exception as e:
                out = "Groq çağrısı başarısız: " + str(e)
            # Render inline result
            return render_template_string("""
            <!doctype html><html><head><meta charset="utf-8"><title>Kod Öğretmeni</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body class="bg-dark text-light p-4">
            <div class="container">
              <h3>Kod Öğretmeni - Sonuç</h3>
              <pre style="white-space:pre-wrap;background:#071; padding:12px;border-radius:8px;">{{ out }}</pre>
              <a href="{{ url_for('admin_panel') }}" class="btn btn-primary">Geri</a>
            </div></body></html>
            """, out=out)
        elif action == 'autofix':
            # perform a small set of safe fixes (only examples)
            fix = request.form.get('fix_action')
            ok,msg = perform_auto_fix_safe(fix)
            db.execute("INSERT INTO admin_logs (admin_user, action, target, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                       (session.get('username'), "AUTOFIX", fix, msg, datetime.utcnow().isoformat()))
            db.commit()
            flash("Otomatik düzeltme: " + msg, "info")
            return redirect(url_for('admin_panel'))
    # GET: render admin page
    users = query_db("SELECT id, username, is_admin, created_at FROM users ORDER BY id DESC")
    reqs = query_db("SELECT * FROM feature_requests ORDER BY created_at DESC LIMIT 50")
    logs = query_db("SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT 200")
    uploads = query_db("SELECT * FROM uploads ORDER BY created_at DESC LIMIT 50")
    return render_template_string("""
    <!doctype html><html><head><meta charset="utf-8"><title>Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-dark text-light p-4">
    <div class="container">
      <h2>Admin Panel</h2>
      <a href="{{ url_for('index') }}" class="btn btn-outline-light mb-3">Ana Sayfa</a>

      <div class="row">
        <div class="col-md-6">
          <h4>Kullanıcılar</h4>
          <table class="table table-dark">
            <thead><tr><th>ID</th><th>Kullanıcı</th><th>Admin</th><th>Oluşturma</th><th>İşlem</th></tr></thead>
            <tbody>
              {% for u in users %}
                <tr>
                  <td>{{ u.id }}</td>
                  <td>{{ u.username }}</td>
                  <td>{{ 'Evet' if u.is_admin else 'Hayır' }}</td>
                  <td>{{ u.created_at }}</td>
                  <td>
                    <form method="post" style="display:inline">
                      <input type="hidden" name="user_id" value="{{ u.id }}">
                      <button name="action" value="promote" class="btn btn-sm btn-warning">Admin Yap</button>
                    </form>
                    <form method="post" style="display:inline">
                      <input type="hidden" name="user_id" value="{{ u.id }}">
                      <button name="action" value="delete" class="btn btn-sm btn-danger">Sil</button>
                    </form>
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>

        <div class="col-md-6">
          <h4>Güncelleme İstekleri</h4>
          <div class="list-group mb-3">
            {% for r in reqs %}
              <div class="list-group-item bg-secondary text-light mb-2">
                <div><strong>{{ r.username }}</strong> - <small>{{ r.created_at }}</small></div>
                <div>{{ r.text }}</div>
              </div>
            {% endfor %}
          </div>

          <h4>Kod Öğretmeni</h4>
          <form method="post">
            <input name="topic" class="form-control mb-2" placeholder="Konu (ör: Flask route oluşturma)">
            <select name="lang" class="form-select mb-2"><option>python</option><option>javascript</option></select>
            <select name="level" class="form-select mb-2"><option value="beginner">Başlangıç</option><option value="intermediate">Orta</option></select>
            <input name="extra" class="form-control mb-2" placeholder="Ek not">
            <button name="action" value="code_teacher" class="btn btn-success">Çalıştır</button>
          </form>

          <h4 class="mt-3">Otomatik Düzeltmeler</h4>
          <form method="post">
            <select name="fix_action" class="form-select mb-2">
              <option value="recreate_db">DB yeniden oluştur</option>
              <option value="ensure_uploads">Upload klasörünü oluştur</option>
            </select>
            <button name="action" value="autofix" class="btn btn-primary">Uygula</button>
          </form>
        </div>
      </div>

      <h4 class="mt-4">Admin Log</h4>
      <ul>
        {% for l in logs %}
          <li><strong>{{ l.admin_user }}</strong> - {{ l.action }} - {{ l.target }} - {{ l.meta }} - <small>{{ l.created_at }}</small></li>
        {% endfor %}
      </ul>

      <h4 class="mt-4">Son Yüklemeler</h4>
      <div class="row">
        {% for up in uploads %}
          <div class="col-md-3">
            <div class="card bg-secondary text-light p-2 mb-2">
              <div>{{ up.filename }}</div>
              <div><a class="btn btn-sm btn-light" href="{{ url_for('serve_upload', filename=up.filename) }}">Görüntüle</a></div>
            </div>
          </div>
        {% endfor %}
      </div>

    </div></body></html>
    """, users=users, reqs=reqs, logs=logs, uploads=uploads)

# ---------------- Auto-fix helper ----------------
def perform_auto_fix_safe(action):
    try:
        if action == "recreate_db":
            init_db()
            return True, "DB yeniden initedildi."
        if action == "ensure_uploads":
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            return True, "Upload klasörü oluşturuldu/var."
        return False, "Bilinmeyen eylem."
    except Exception as e:
        return False, str(e)

# ---------------- Feature requests ----------------
@app.route('/request_feature', methods=['POST'])
@require_login
def request_feature():
    text = (request.form.get('text') or '').strip()
    if not text:
        flash("İstek boş.", "warn")
        return redirect(url_for('index'))
    db = get_db()
    db.execute("INSERT INTO feature_requests (user_id, username, text, created_at) VALUES (?, ?, ?, ?)",
               (session.get('user_id'), session.get('username'), text, datetime.utcnow().isoformat()))
    db.commit()
    flash("İstek gönderildi.", "info")
    return redirect(url_for('index'))

# ---------------- Admin-only simple endpoints for testing ----------------
@app.route('/api/health')
@require_admin
def api_health():
    issues = []
    if not os.path.isdir(app.config['UPLOAD_FOLDER']):
        issues.append("Upload folder missing")
    if not GROQ_API_KEY:
        issues.append("GROQ_API_KEY missing")
    if not HF_API_KEY:
        issues.append("HF_API_KEY missing")
    return jsonify({"issues": issues, "time": datetime.utcnow().isoformat()})

# ---------------- Utilities for saving image bytes ----------------
def save_image_bytes(bytes_data, prefix="img"):
    fn = f"{prefix}_{int(time.time())}_{uuid.uuid4().hex[:8]}.png"
    path = os.path.join(app.config['UPLOAD_FOLDER'], fn)
    with open(path, "wb") as f:
        f.write(bytes_data)
    return fn, path

# ---------------- Startup ----------------
def start():
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

if __name__ == "__main__":
    start()
