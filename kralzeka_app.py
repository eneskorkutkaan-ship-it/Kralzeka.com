#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Tam özellikli tek-dosya Flask uygulaması
- Tek dosya: kralzeka_v1.py
- DB: SQLite (kralzeka_v1.db)
- Env vars required:
    GROQ_API_KEY  - (sohbet modeline bağlanmak için; yoksa fallback mantığı çalışır)
    HF_API_KEY    - (Hugging Face image api / model kullanımı için)
    FLASK_SECRET  - Flask secret key
- Admin default: username=enes password=enes1357924680 (ilk çalıştırma yaratılır)
"""

import os
import re
import json
import time
import uuid
import base64
import hashlib
import pathlib
import sqlite3
import threading
from datetime import datetime, timedelta
from functools import wraps

import requests
from flask import (
    Flask, request, session, redirect, url_for, render_template_string,
    jsonify, send_from_directory, abort, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, \
    logout_user, current_user
import bcrypt

# -----------------------
# Config
# -----------------------
BASE_DIR = pathlib.Path(__file__).parent.resolve()
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "kralzeka_v1.db"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_FLASK_SECRET = os.environ.get("FLASK_SECRET") or "please_set_FLASK_SECRET_env_var_for_prod_use"
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")   # may be None
HF_API_KEY = os.environ.get("HF_API_KEY")       # may be None

# Limits and defaults
IMAGE_QUALITY_DAILY_LIMIT = 5   # normal users daily limit for quality-upgrade
MAX_MESSAGE_HISTORY = 200

# -----------------------
# Create app
# -----------------------
def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = DEFAULT_FLASK_SECRET
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB uploads
    return app

app = create_app()
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# -----------------------
# Database models
# -----------------------
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # memory fields
    daily_image_upgrades = db.Column(db.Integer, default=0)
    last_reset = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, pw):
        try:
            return bcrypt.checkpw(pw.encode("utf-8"), self.password_hash.encode("utf-8"))
        except Exception:
            return False

    def set_password(self, pw):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(pw.encode("utf-8"), salt).decode("utf-8")

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(150))
    role = db.Column(db.String(50))  # user/system/kralzeka
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Audit(db.Model):
    __tablename__ = "audit"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.Text)
    actor = db.Column(db.String(150))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------------
# Utilities
# -----------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin yetkisi gerekiyor.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

def audit(action, actor="system", details=""):
    a = Audit(action=action, actor=actor, details=details)
    db.session.add(a)
    db.session.commit()

def init_db_and_admin():
    """Ensure DB exists and initial admin present."""
    db.create_all()
    admin = User.query.filter_by(username="enes").first()
    if not admin:
        u = User(username="enes", is_admin=True)
        u.set_password("enes1357924680")
        db.session.add(u)
        db.session.commit()
        audit("init_admin_created", actor="system", details="Initial admin 'enes' created")
    return

# Run init on start with application context
with app.app_context():
    init_db_and_admin()

# -----------------------
# Simple helpers
# -----------------------
def safe_filename(filename):
    # very simple sanitize
    return re.sub(r'[^A-Za-z0-9_.-]', '_', filename)

def user_daily_reset_if_needed(user: User):
    if not user:
        return
    now = datetime.utcnow()
    if not user.last_reset or (now - user.last_reset) > timedelta(days=1):
        user.daily_image_upgrades = 0
        user.last_reset = now
        db.session.commit()

# -----------------------
# External service clients (simplified)
# -----------------------

# 1) Groq / Chat fallback function
def ask_groq_model(prompt, user_id=None):
    """
    Ask Groq (or fallback) for an answer. This function expects GROQ_API_KEY env var.
    Returns (success_bool, reply_text_or_error).
    """
    api_key = GROQ_API_KEY
    if not api_key:
        return False, "Sohbet servisine erişim anahtarı yok (GROQ_API_KEY)."
    # Example request structure for Groq — adapt as needed to actual API.
    url = "https://api.groq.com/openai/v1/chat/completions"  # note: adapt provider's endpoint if different
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "gpt-4o-mini",  # placeholder model name; replace with available model in your Groq account
        "messages": [
            {"role": "system", "content": "Türkçe, kibar ve kısa cevap ver. Kullanıcıya yardımcı ol."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 600,
        "temperature": 0.4,
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code != 200:
            return False, f"Hata {r.status_code}: {r.text}"
        j = r.json()
        # Very generic extraction — adapt to actual provider response shape
        # Try few variants:
        if "choices" in j and len(j["choices"])>0 and "message" in j["choices"][0]:
            return True, j["choices"][0]["message"].get("content","")
        if "result" in j:
            return True, str(j["result"])
        return True, json.dumps(j)
    except Exception as e:
        return False, f"Groq isteği hata: {str(e)}"

# 2) Hugging Face image generation / upscaling (simplified)
def hf_generate_image(prompt, size="512x512"):
    """
    Use Hugging Face Inference API or specific model to generate an image.
    Requires HF_API_KEY env var.
    Returns (success, image_bytes or error_message)
    """
    token = HF_API_KEY
    if not token:
        return False, "Hugging Face anahtarı (HF_API_KEY) ayarlı değil."
    # We'll call the text-to-image inference endpoint for a public model (e.g. stability or diffusers)
    # This is an example using the inference API (but actual endpoint & headers vary).
    model = "stabilityai/stable-diffusion-2"  # placeholder; may require specific path or options
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        if r.status_code == 200:
            return True, r.content
        else:
            # If returns json with error
            try:
                j = r.json()
                return False, f"HF hata {r.status_code}: {j.get('error','')}"
            except Exception:
                return False, f"HF hata {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, f"HF istemci hatası: {str(e)}"

def hf_upscale_image(image_bytes):
    """
    Placeholder upscale with HF — this function is a simplified call.
    """
    token = HF_API_KEY
    if not token:
        return False, "HF API anahtarı eksik."
    # Example: call a super-resolution model if available
    model = "stabilityai/esrgan"  # placeholder
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {token}"}
    files = {"file": image_bytes}
    try:
        # Some HF endpoints expect raw bytes POST; here we post as binary
        r = requests.post(url, headers=headers, data=image_bytes, timeout=60)
        if r.status_code == 200:
            return True, r.content
        else:
            try:
                return False, f"Hata {r.status_code}: {r.json().get('error','')}"
            except Exception:
                return False, f"Hata {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, f"Hata: {str(e)}"

# -----------------------
# Auto-fix / self-heal helper (admin-only action)
# -----------------------
def self_diagnose_and_suggest():
    """
    Simple heuristic diagnostic: check environment variables, connectivity, DB access.
    Returns list of issues and suggested fixes.
    """
    issues = []
    # Check env
    if not GROQ_API_KEY:
        issues.append(("GROQ_API_KEY missing", "Set GROQ_API_KEY in environment variables (Render -> Environment)"))
    if not HF_API_KEY:
        issues.append(("HF_API_KEY missing", "Set HF_API_KEY in environment variables (Render -> Environment)"))
    # Check DB
    try:
        _ = User.query.first()
    except Exception as e:
        issues.append(("DB error", f"DB access error: {str(e)}"))
    # Check internet connection to key endpoints
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=6)
        if r.status_code != 200:
            issues.append(("Internet check failed", "Cannot reach api.ipify.org"))
    except Exception as e:
        issues.append(("Internet check exception", str(e)))
    # Simplified suggestions
    suggestions = []
    for k, reason in issues:
        suggestions.append({"issue": k, "fix": reason})
    if not suggestions:
        suggestions.append({"issue": "ok", "fix": "No obvious issue found. If problems persist, check provider quotas and logs."})
    return suggestions

# -----------------------
# Frontend Template (single-file)
# -----------------------
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KralZeka v1</title>
  <style>
    :root{
      --bg:#050505; --panel:#062020; --accent:#1e8a4b; --muted:#9aa7a7; --card:#042525;
      color-scheme: dark;
    }
    body{background:var(--bg);font-family:Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;color:#e2f0f0;margin:0;padding:0}
    header{padding:28px 40px;text-align:left}
    .container{max-width:1000px;margin:0 auto;padding:10px 20px}
    .card{background:linear-gradient(180deg, rgba(2,30,30,0.45), rgba(2,20,20,0.45));border-radius:10px;padding:18px;margin-bottom:18px;box-shadow:0 6px 18px rgba(0,0,0,0.6)}
    .topbar{display:flex;justify-content:space-between;align-items:center}
    h1{margin:0;font-size:28px}
    .small{color:var(--muted);font-size:14px}
    .chat-input{display:flex;gap:8px;align-items:center}
    input[type=text], input[type=password]{flex:1;padding:12px;border-radius:8px;background:#0a1c1c;border:1px solid rgba(255,255,255,0.03);color:#eaf6f6}
    button{padding:10px 14px;border-radius:8px;background:var(--accent);border:none;color:white;cursor:pointer}
    .msg{padding:14px;border-radius:8px;margin:8px 0;background:#082b2b}
    .msg.user{background:#08303a}
    .admin-link{color:#ffd100;text-decoration:underline}
    .modes{display:flex;gap:8px;margin-top:10px}
    .mode-btn{padding:8px 12px;border-radius:8px;background:#0b2323;border:1px solid rgba(255,255,255,0.02);cursor:pointer}
    .uploads{margin-top:8px}
    .small-muted{font-size:12px;color:var(--muted)}
    .admin-box{background:#131313;padding:12px;border-radius:8px;color:#fff}
    footer{padding:18px;text-align:center;color:var(--muted)}
    .danger{color:#ff8a8a}
    .success{color:#9bffcf}
  </style>
</head>
<body>
  <header>
    <div class="container">
      <div class="topbar">
        <div>
          <h1>KralZeka v1 <span style="color:#ffd100">({{ current_user.username if current_user.is_authenticated else 'Guest' }})</span></h1>
          <div class="small">Gerçek zamanlı internet destekli Türkçe asistan — v1</div>
        </div>
        <div>
          {% if current_user.is_authenticated %}
            <a href="{{ url_for('logout') }}" class="small" style="color:#d6c2ff">Çıkış yap</a>
            {% if current_user.is_admin %}
              &nbsp; | &nbsp; <a href="{{ url_for('admin') }}" class="admin-link">Admin Panel</a>
            {% endif %}
          {% else %}
            <a href="{{ url_for('login') }}" class="small" style="color:#d6c2ff">Giriş / Kayıt</a>
          {% endif %}
        </div>
      </div>
    </div>
  </header>

  <div class="container">
    <div class="card">
      <div style="display:flex;align-items:flex-start;gap:18px">
        <div style="flex:1">
          <form id="chatForm" method="post" action="{{ url_for('chat') }}">
            <div class="chat-input">
              <input id="q" name="q" type="text" placeholder="Bir şey yaz..." autocomplete="off" />
              <button type="submit">Gönder</button>
            </div>
            <div style="margin-top:8px">
              <div class="modes">
                <button class="mode-btn" type="button" onclick="setMode('chat')">Sohbet</button>
                <button class="mode-btn" type="button" onclick="setMode('homework')">Ödeve Yardımcı</button>
                <button class="mode-btn" type="button" onclick="setMode('jokes')">Espri Modu</button>
                <button class="mode-btn" type="button" onclick="setMode('presentation')">Sunum Modu</button>
              </div>
            </div>
          </form>

          <div id="messages" style="margin-top:14px">
            {% for m in messages %}
              <div class="msg {% if m.role=='user' %}user{% endif %}">
                <strong>{{ m.user }}:</strong> {{ m.content }}
                <div class="small-muted">{{ m.created_at.strftime('%Y-%m-%d %H:%M') }}</div>
              </div>
            {% endfor %}
          </div>
        </div>

        <div style="width:320px">
          <div class="admin-box">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <div><strong>Hızlı Bilgiler</strong></div>
            </div>
            <div class="small-muted" style="margin-top:8px">
              <div>Kullanıcı: <strong>{{ current_user.username if current_user.is_authenticated else 'Giriş Yapınız' }}</strong></div>
              <div>Modlar: Sohbet / Ödev / Espri / Sunum</div>
              <div style="margin-top:8px">Görsel yükle: + simgesinden yapın.</div>
              <hr style="border:none;border-top:1px solid rgba(255,255,255,0.03);margin:10px 0" />
              <div class="small-muted">Güncellemeler & Öneriler (admin):</div>
              <div id="updates" style="margin-top:8px;max-height:120px;overflow:auto;color:#cfe9e9">
                {% for u in updates %}
                  <div style="margin-bottom:6px">• {{ u }}</div>
                {% else %}
                  <div class="small-muted">Güncelleme yok.</div>
                {% endfor %}
              </div>
            </div>
          </div>

          <div style="margin-top:12px" class="card">
            <form id="uploadForm" method="post" action="{{ url_for('upload_image') }}" enctype="multipart/form-data">
              <div style="display:flex;gap:8px;align-items:center">
                <input type="file" name="image" accept="image/*" />
                <button type="submit">Yükle</button>
              </div>
              <div class="small-muted" style="margin-top:6px">Görsel yükle (sınır 16MB). Adminlerin sınırsız, kullanıcıların günlük limitleri var.</div>
            </form>
          </div>
        </div>

      </div>
    </div>

    <div class="card">
      <div class="small-muted">Son işlemler / hata mesajları</div>
      <div id="logarea" style="margin-top:8px">
        {% for a in audits %}
          <div class="small-muted">[{{ a.created_at.strftime('%Y-%m-%d %H:%M') }}] {{ a.actor }} → {{ a.action }} - {{ a.details }}</div>
        {% endfor %}
      </div>
    </div>

    <footer>
      <div class="small-muted">KralZeka v1 — Geliştirici: Enes. "Beni Enes yarattı" — (isteğe bağlı profil bilgisi)</div>
    </footer>
  </div>

<script>
  const MODE_KEY = "kz_mode";
  function setMode(m){
    localStorage.setItem(MODE_KEY, m);
    alert("Mod: " + m + " seçildi.");
  }

  document.getElementById('chatForm').addEventListener('submit', async function(ev){
    ev.preventDefault();
    const q = document.getElementById('q').value.trim();
    if(!q) return;
    const mode = localStorage.getItem(MODE_KEY) || 'chat';
    const resp = await fetch("{{ url_for('chat_api') }}", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({q, mode})
    });
    const j = await resp.json();
    if(j.ok){
      // reload page to show message simply
      location.reload();
    } else {
      alert("Hata: " + j.error);
    }
  });
</script>
</body>
</html>
"""

# -----------------------
# Routes: UI pages
# -----------------------
@app.route("/", methods=["GET"])
def index():
    # show last messages
    messages = Message.query.order_by(Message.created_at.desc()).limit(20).all()
    messages = list(reversed(messages))
    updates = ["Modlar: Sohbet, Ödev Yardımcısı, Espri, Sunum. Admin panel ile kullanıcıları yönet."]  # placeholder
    audits = Audit.query.order_by(Audit.created_at.desc()).limit(8).all()
    return render_template_string(BASE_HTML, messages=messages, updates=updates, audits=audits)

# -----------------------
# Authentication
# -----------------------
AUTH_HTML = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Giriş - KralZeka</title>
<style>body{background:#050505;color:#eaf6f6;font-family:Inter, sans-serif;padding:24px}.card{background:#071818;padding:18px;border-radius:10px;max-width:520px;margin:20px auto}</style>
</head><body>
  <div class="card">
    <h2>{{ 'Kayıt Ol' if register else 'Giriş Yap' }}</h2>
    <form method="post">
      <div style="margin:8px 0"><input name="username" placeholder="Kullanıcı adı" required></div>
      <div style="margin:8px 0"><input name="password" type="password" placeholder="Şifre" required></div>
      {% if register %}
        <div style="margin:8px 0"><input name="password2" type="password" placeholder="Şifre tekrar" required></div>
      {% endif %}
      <div style="margin-top:8px">
        <button type="submit">{{ 'Kayıt Ol' if register else 'Giriş Yap' }}</button>
      </div>
    </form>
    <div style="margin-top:10px">
      {% if register %}
        Zaten hesabın var mı? <a href="{{ url_for('login') }}">Giriş Yap</a>
      {% else %}
        Hesap yok mu? <a href="{{ url_for('register') }}">Kayıt Ol</a>
      {% endif %}
    </div>
  </div>
</body></html>
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        user = User.query.filter_by(username=u).first()
        if user and user.check_password(p):
            login_user(user)
            audit("login", actor=user.username, details="User logged in")
            return redirect(url_for("index"))
        else:
            flash("Kullanıcı adı veya şifre hatalı.", "danger")
    return render_template_string(AUTH_HTML, register=False)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        p2 = request.form.get("password2", "")
        if not u or not p or not p2 or p != p2:
            flash("Eksik veya uyumsuz bilgiler.", "danger")
            return render_template_string(AUTH_HTML, register=True)
        if User.query.filter_by(username=u).first():
            flash("Bu kullanıcı adı alınmış.", "danger")
            return render_template_string(AUTH_HTML, register=True)
        new = User(username=u, is_admin=False)
        new.set_password(p)
        db.session.add(new)
        db.session.commit()
        audit("user_registered", actor=u, details="New user registered")
        login_user(new)
        return redirect(url_for("index"))
    return render_template_string(AUTH_HTML, register=True)

@app.route("/logout")
@login_required
def logout():
    audit("logout", actor=current_user.username, details="User logged out")
    logout_user()
    return redirect(url_for("index"))

# -----------------------
# Chat endpoints
# -----------------------
@app.route("/chat", methods=["POST"])
@login_required
def chat():
    # Form post from UI — fallback to API route
    q = request.form.get("q") or request.json.get("q")
    mode = request.form.get("mode") or (request.json.get("mode") if request.is_json else "chat")
    if not q:
        flash("Boş mesaj gönderemezsiniz.", "danger")
        return redirect(url_for("index"))
    # Save user message
    m = Message(user=current_user.username, role="user", content=q)
    db.session.add(m)
    db.session.commit()
    audit("user_message", actor=current_user.username, details=q)
    # Ask model in background? We'll call synchronously for simplicity
    success, reply = ask_groq_model(f"[MODE:{mode}] {q}", user_id=current_user.id)
    if not success:
        # fallback: produce heuristic or inform user
        # store as system reply
        content = f"Hata: {reply}"
        mm = Message(user="KralZeka", role="kralzeka", content=content)
        db.session.add(mm)
        db.session.commit()
        audit("chat_error", actor="system", details=reply)
    else:
        mm = Message(user="KralZeka", role="kralzeka", content=reply)
        db.session.add(mm)
        db.session.commit()
        audit("chat_ok", actor="system", details=f"Answered in mode {mode}")
    return redirect(url_for("index"))

@app.route("/api/chat", methods=["POST"])
@login_required
def chat_api():
    try:
        data = request.get_json() or {}
        q = data.get("q", "").strip()
        mode = data.get("mode", "chat")
        if not q:
            return jsonify({"ok": False, "error": "Boş istek"}), 400
        m = Message(user=current_user.username, role="user", content=q)
        db.session.add(m); db.session.commit()
        audit("user_message_api", actor=current_user.username, details=q)
        ok, reply = ask_groq_model(f"[MODE:{mode}] {q}", user_id=current_user.id)
        if not ok:
            mm = Message(user="KralZeka", role="kralzeka", content=f"Hata: {reply}")
            db.session.add(mm); db.session.commit()
            audit("chat_api_error", actor="system", details=reply)
            return jsonify({"ok": False, "error": reply}), 500
        mm = Message(user="KralZeka", role="kralzeka", content=reply)
        db.session.add(mm); db.session.commit()
        audit("chat_api_ok", actor="system", details="reply saved")
        return jsonify({"ok": True, "reply": reply})
    except Exception as e:
        audit("chat_api_exception", actor="system", details=str(e))
        return jsonify({"ok": False, "error": str(e)}), 500

# -----------------------
# Image upload & generation routes
# -----------------------
@app.route("/upload_image", methods=["POST"])
@login_required
def upload_image():
    if 'image' not in request.files:
        flash("Dosya bulunamadı.", "danger")
        return redirect(url_for("index"))
    f = request.files['image']
    if f.filename == "":
        flash("İsim yok.", "danger")
        return redirect(url_for("index"))
    filename = safe_filename(f.filename)
    save_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}"
    f.save(save_path)
    audit("image_uploaded", actor=current_user.username, details=str(save_path))
    # Optionally process the image: run OCR / question extraction when in homework mode — placeholder
    flash("Görsel yüklendi.", "success")
    return redirect(url_for("index"))

@app.route("/generate_image", methods=["POST"])
@login_required
def generate_image():
    data = request.get_json() or {}
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"ok": False, "error": "Prompt boş"}), 400
    # Check daily limits for quality-upgrades if requested
    want_quality = data.get("quality_upgrade", False)
    user_daily_reset_if_needed(current_user)
    if want_quality and not current_user.is_admin:
        if current_user.daily_image_upgrades >= IMAGE_QUALITY_DAILY_LIMIT:
            return jsonify({"ok": False, "error": "Günlük kalite yükseltme limitiniz doldu"}), 403
        current_user.daily_image_upgrades += 1
        db.session.commit()
    ok, res = hf_generate_image(prompt)
    if not ok:
        audit("image_generate_failed", actor=current_user.username, details=res)
        return jsonify({"ok": False, "error": res}), 500
    # Save image
    fn = f"gen_{uuid.uuid4().hex}.png"
    p = UPLOAD_DIR / fn
    with open(p, "wb") as fh:
        fh.write(res)
    audit("image_generated", actor=current_user.username, details=fn)
    return jsonify({"ok": True, "url": url_for('uploaded_file', filename=fn)})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# -----------------------
# Admin panel (single page)
# -----------------------
ADMIN_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Admin - KralZeka</title>
<style>body{background:#050505;color:#f0f8f8;font-family:Inter, sans-serif;padding:20px}.card{background:#081818;padding:16px;border-radius:10px;}</style>
</head><body>
  <h2>Admin Panel</h2>
  <div class="card">
    <h3>Kullanıcılar</h3>
    <ul>
      {% for u in users %}
        <li>
          {{ u.username }} - Admin: {{ 'Evet' if u.is_admin else 'Hayır' }}
          {% if u.username!='enes' %}
            <form style="display:inline" method="post" action="{{ url_for('toggle_admin', uid=u.id) }}">
              <button type="submit">{{ 'Adminlikten çıkar' if u.is_admin else 'Admin yap' }}</button>
            </form>
            <form style="display:inline" method="post" action="{{ url_for('delete_user', uid=u.id) }}">
              <button type="submit">Sil</button>
            </form>
          {% else %}
            <span style="color:#ffd100"> (Baş admin korunur)</span>
          {% endif %}
        </li>
      {% endfor %}
    </ul>
  </div>

  <div class="card" style="margin-top:12px">
    <h3>İstekler / Mesajlar</h3>
    <ul>
      {% for m in messages %}
        <li><strong>{{ m.user }}</strong>: {{ m.content }} — <em>{{ m.created_at }}</em></li>
      {% endfor %}
    </ul>
  </div>

  <div class="card" style="margin-top:12px">
    <h3>Otomatik Düzeltme / Tanı</h3>
    <form method="post" action="{{ url_for('run_self_heal') }}">
      <button type="submit">Tanı çalıştır ve öneri al</button>
    </form>
    {% if diag %}
      <div style="margin-top:8px">
        <h4>Durum</h4>
        <ul>
        {% for d in diag %}
          <li>{{ d.issue }} — öneri: {{ d.fix }}</li>
        {% endfor %}
        </ul>
      </div>
    {% endif %}
  </div>

  <div style="margin-top:12px"><a href="{{ url_for('index') }}">Geri dön</a></div>
</body></html>
"""

@app.route("/admin", methods=["GET"])
@login_required
@admin_required
def admin():
    users = User.query.order_by(User.username).all()
    messages = Message.query.order_by(Message.created_at.desc()).limit(40).all()
    messages = [ {"user":m.user,"content":m.content,"created_at":m.created_at} for m in messages ]
    diag = None
    return render_template_string(ADMIN_HTML, users=users, messages=messages, diag=diag)

@app.route("/admin/toggle_admin/<int:uid>", methods=["POST"])
@login_required
@admin_required
def toggle_admin(uid):
    target = User.query.get(uid)
    if not target:
        flash("Kullanıcı bulunamadı.", "danger")
        return redirect(url_for("admin"))
    if target.username == "enes":
        flash("Baş admin silinemez veya yetkisi kaldırılamaz.", "danger")
        return redirect(url_for("admin"))
    target.is_admin = not target.is_admin
    db.session.commit()
    action = "admin_granted" if target.is_admin else "admin_revoked"
    audit(action, actor=current_user.username, details=target.username)
    return redirect(url_for("admin"))

@app.route("/admin/delete_user/<int:uid>", methods=["POST"])
@login_required
@admin_required
def delete_user(uid):
    target = User.query.get(uid)
    if not target:
        flash("Kullanıcı bulunamadı.", "danger")
        return redirect(url_for("admin"))
    if target.username == "enes":
        flash("Baş admin silinemez.", "danger")
        return redirect(url_for("admin"))
    db.session.delete(target)
    db.session.commit()
    audit("user_deleted", actor=current_user.username, details=target.username)
    return redirect(url_for("admin"))

@app.route("/admin/self_heal", methods=["POST"])
@login_required
@admin_required
def run_self_heal():
    diag = self_diagnose_and_suggest()
    # present diag on admin page (we'll store in audit as well)
    audit("self_diagnose_run", actor=current_user.username, details=json.dumps(diag))
    users = User.query.order_by(User.username).all()
    messages = Message.query.order_by(Message.created_at.desc()).limit(40).all()
    messages = [ {"user":m.user,"content":m.content,"created_at":m.created_at} for m in messages ]
    return render_template_string(ADMIN_HTML, users=users, messages=messages, diag=diag)

# -----------------------
# Error handling and helper endpoints
# -----------------------
@app.errorhandler(413)
def file_too_large(e):
    return "Dosya çok büyük (16MB sınırı).", 413

@app.route("/healthz")
def healthz():
    return jsonify({"status":"ok","time":datetime.utcnow().isoformat()})

# -----------------------
# Run block for local dev
# -----------------------
if __name__ == "__main__":
    # Safety: ensure DB & admin exists
    with app.app_context():
        init_db_and_admin()
    # Use host 0.0.0.0 for deployed container environments
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
