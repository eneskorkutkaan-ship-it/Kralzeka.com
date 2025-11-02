#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Tam özellikli tek-dosya Flask uygulaması
Çalıştırma: gunicorn kralzeka_app:app
Render start command: gunicorn kralzeka_app:app
Environment variables required:
 - HF_API_KEY      (Hugging Face API key)  -- fallback for models
 - GROQ_API_KEY    (Groq API key)          -- primary model usage (if available)
 - ADMIN_KEY       (secret admin key used to protect admin-only endpoints/actions)
 - FLASK_SECRET    (Flask secret key, optional)
"""

import os
import time
import json
import sqlite3
import threading
import traceback
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, g, render_template_string, request, redirect, url_for,
    session, jsonify, send_from_directory, abort, flash
)
import requests

# -------------------- Ayarlar --------------------
APP_NAME = "KralZeka v1"
DB_PATH = "kralzeka.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}
MAX_DAILY_QUALITY_USES = 5  # normal kullanıcı günlük kalite yükseltme limiti

HF_API_KEY = os.environ.get("HF_API_KEY", "")    # set in Render -> Environment
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")  # primary model key
ADMIN_KEY = os.environ.get("ADMIN_KEY", "enes1357924680")  # default first admin (enes)
FLASK_SECRET = os.environ.get("FLASK_SECRET", "change_me_please")
PORT = int(os.environ.get("PORT", 10000))

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------- Flask app --------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = FLASK_SECRET

# -------------------- DB helpers --------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        g._db = conn
    return g._db

def close_db(e=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

def init_db(force=False):
    db = get_db()
    if force:
        try:
            db.execute("DROP TABLE IF EXISTS users")
            db.execute("DROP TABLE IF EXISTS messages")
            db.execute("DROP TABLE IF EXISTS limits")
            db.commit()
        except Exception:
            pass
    # create tables if not exist
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        role TEXT,
        content TEXT,
        timestamp TEXT
    );
    CREATE TABLE IF NOT EXISTS limits (
        user_id INTEGER PRIMARY KEY,
        quality_used INTEGER DEFAULT 0,
        last_reset TEXT
    );
    CREATE TABLE IF NOT EXISTS admin_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user INTEGER,
        action TEXT,
        target_user INTEGER,
        timestamp TEXT
    );
    """)
    db.commit()
    # ensure initial admin exists
    cur = db.execute("SELECT id FROM users WHERE username = ?", ("enes",))
    if cur.fetchone() is None:
        db.execute(
            "INSERT INTO users (username,password,is_admin,created_at) VALUES (?,?,?,?)",
            ("enes", ADMIN_KEY, 1, datetime.utcnow().isoformat())
        )
        db.commit()

# init DB at import time (safe)
with app.app_context():
    init_db(force=False)

# -------------------- Auth helpers --------------------
def login_user(username):
    session['username'] = username

def logout_user():
    session.pop('username', None)

def current_user():
    username = session.get('username')
    if not username:
        return None
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["is_admin"] != 1:
            return jsonify({"error":"Bu işlem için admin yetkisi gerekiyor."}), 403
        return fn(*args, **kwargs)
    return wrapper

# -------------------- Rate limit / limits --------------------
def check_quality_limit(user_id):
    db = get_db()
    cur = db.execute("SELECT quality_used, last_reset FROM limits WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    today = datetime.utcnow().date()
    if not row:
        # insert
        db.execute("INSERT OR REPLACE INTO limits (user_id, quality_used, last_reset) VALUES (?,?,?)",
                   (user_id, 0, today.isoformat()))
        db.commit()
        return True, 0
    used = row["quality_used"]
    last_reset = datetime.fromisoformat(row["last_reset"]).date() if row["last_reset"] else today
    if last_reset < today:
        db.execute("UPDATE limits SET quality_used=0, last_reset=? WHERE user_id=?", (today.isoformat(), user_id))
        db.commit()
        return True, 0
    return (used < MAX_DAILY_QUALITY_USES), used

def increment_quality(user_id):
    db = get_db()
    cur = db.execute("SELECT quality_used FROM limits WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        db.execute("INSERT INTO limits (user_id, quality_used, last_reset) VALUES (?,?,?)",
                   (user_id, 1, datetime.utcnow().date().isoformat()))
    else:
        db.execute("UPDATE limits SET quality_used = quality_used + 1 WHERE user_id = ?", (user_id,))
    db.commit()

# -------------------- Utility / Logging --------------------
def log_message(user_id, role, content):
    db = get_db()
    db.execute(
        "INSERT INTO messages (user_id, role, content, timestamp) VALUES (?,?,?,?)",
        (user_id, role, content, datetime.utcnow().isoformat())
    )
    db.commit()

def record_admin_action(admin_user, action, target_user=None):
    db = get_db()
    db.execute("INSERT INTO admin_actions (admin_user, action, target_user, timestamp) VALUES (?,?,?,?)",
               (admin_user, action, target_user, datetime.utcnow().isoformat()))
    db.commit()

# -------------------- Model wrappers --------------------
def call_groq_model(prompt):
    """
    Call Groq API (primary). Return string or raise Exception on failure.
    Note: fill GROQ_API_KEY in env.
    """
    key = GROQ_API_KEY
    if not key:
        raise RuntimeError("Groq API key yok")
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        data = {
            "model": "gpt-4o-mini" if False else "llama-3-8-8192",  # placeholder — actual model must match Groq offering
            "messages": [{"role":"user","content": prompt}],
            "max_tokens": 800
        }
        r = requests.post(url, headers=headers, json=data, timeout=30)
        r.raise_for_status()
        js = r.json()
        # Attempt to extract text
        if "choices" in js and len(js["choices"])>0:
            content = js["choices"][0].get("message", {}).get("content", "")
            return content
        return js.get("text") or json.dumps(js)
    except Exception as e:
        raise

def call_hf_model(prompt):
    """
    Call Hugging Face text generation as fallback.
    Use HF_API_KEY in env.
    """
    key = HF_API_KEY
    if not key:
        raise RuntimeError("HF API key yok")
    try:
        model_id = "gpt2"  # lightweight fallback example; you can change to a hosted conversational model
        url = f"https://api-inference.huggingface.co/models/{model_id}"
        headers = {"Authorization": f"Bearer {key}"}
        payload = {"inputs": prompt, "parameters": {"max_new_tokens": 400}}
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        js = r.json()
        if isinstance(js, list) and len(js)>0 and "generated_text" in js[0]:
            return js[0]["generated_text"]
        if isinstance(js, dict) and "generated_text" in js:
            return js["generated_text"]
        return str(js)
    except Exception as e:
        raise

def generate_text(prompt):
    """
    Try Groq first, fallback to HF.
    Returns tuple (result_text, backend_used, error_if_any)
    """
    # Try Groq
    if GROQ_API_KEY:
        try:
            t = call_groq_model(prompt)
            return t, "groq", None
        except Exception as e:
            # record error and fallback
            err = str(e)
    else:
        err = "Groq key yok"
    # fallback to HF
    if HF_API_KEY:
        try:
            t = call_hf_model(prompt)
            return t, "huggingface", None
        except Exception as e2:
            return None, None, f"HF Hata: {e2} | Groq hata: {err}"
    return None, None, f"Model bulunumadı. Groq: {err}"

# -------------------- Image generation (tokensız as request) --------------------
def generate_image_from_hf(prompt, size="512x512"):
    """
    Uses Hugging Face image-generation if HF_API_KEY exists.
    Returns filename on success
    """
    if not HF_API_KEY:
        raise RuntimeError("HF API key yok")
    try:
        # Many HF image models require different endpoints; here we call a generic text-to-image endpoint
        api_url = "https://api-inference.huggingface.co/models/stabilityai/stable-diffusion-2"  # example
        headers = {"Authorization": f"Bearer {HF_API_KEY}"}
        payload = {"inputs": prompt}
        r = requests.post(api_url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        # HF may return image bytes or base64; handle common case with bytes
        content_type = r.headers.get("Content-Type", "")
        if "application/json" in content_type:
            body = r.json()
            # try interpret
            if isinstance(body, dict) and "error" in body:
                raise RuntimeError("HF image error: " + str(body["error"]))
            # If base64 included:
            b64 = body.get("b64_json") or body.get("image_base64")
            if b64:
                import base64
                img_data = base64.b64decode(b64)
            else:
                raise RuntimeError("HF returned JSON but no image")
        else:
            img_data = r.content
        fname = f"{int(time.time())}.png"
        fpath = os.path.join(UPLOAD_FOLDER, fname)
        with open(fpath, "wb") as f:
            f.write(img_data)
        return fname
    except Exception as e:
        raise

# -------------------- Templates (inline for single-file) --------------------
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{app_name}}</title>
  <style>
    /* Basit, sade stil - gerektiğinde Tailwind ile değiştirilebilir */
    body{background:#071017;color:#d7efe8;font-family:Inter,Arial,Helvetica,sans-serif;margin:0;padding:0}
    header{background:#0b1b22;padding:18px 28px;display:flex;justify-content:space-between;align-items:center}
    .brand{font-size:20px;font-weight:700;color:#e6d75e}
    .container{max-width:980px;margin:30px auto;padding:20px}
    .chatbox{background:#071f1b;padding:18px;border-radius:10px}
    input,textarea,button,select{font-size:16px;padding:8px;border-radius:6px;border:1px solid #2e3b3a;background:#071f1b;color:#e7f0eb}
    .msg{background:#072a26;padding:14px;border-radius:8px;margin:10px 0}
    .admin-badge{color:#ffd36c;font-weight:700;margin-left:8px}
    .top-actions{display:flex;gap:10px}
    .panel{background:#051515;padding:14px;border-radius:8px;margin-top:18px}
    a{color:#9ee1c8}
    .small{font-size:13px;color:#9ac9b6}
    .muted{color:#6f8c81}
    .danger{color:#ff8b8b}
    .success{color:#9be59b}
    .modes{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
    .mode-btn{background:#0f3831;padding:8px 12px;border-radius:6px;cursor:pointer}
  </style>
</head>
<body>
  <header>
    <div class="brand">{{app_name}}</div>
    <div class="top-actions">
      {% if user %}
        <div>Merhaba, <strong>{{user.username}}</strong> {% if user.is_admin %}<span class="admin-badge">[ADMIN]</span>{% endif %}</div>
        <a href="{{url_for('logout')}}">Çıkış yap</a>
        {% if user.is_admin %}<a href="{{url_for('admin_panel')}}">Admin Panel</a>{% endif %}
      {% else %}
        <a href="{{url_for('login')}}">Giriş</a>
        <a href="{{url_for('register')}}">Kayıt</a>
      {% endif %}
    </div>
  </header>
  <div class="container">
    {% block body %}{% endblock %}
    <footer style="text-align:center;margin-top:40px" class="small muted">© {{app_name}} — KralZeka, Enes'in zekâsıyla hayat buldu.</footer>
  </div>
</body>
</html>
"""

INDEX_HTML = """
{% extends base %}
{% block body %}
  <div class="chatbox">
    <form id="chat-form" method="post" action="{{url_for('chat_submit')}}">
      <div style="display:flex;gap:8px;">
        <input name="message" placeholder="Bir şey yaz..." style="flex:1" />
        <button type="submit">Gönder</button>
      </div>
    </form>

    <div class="modes">
      <!-- Modlar -->
      <div class="mode-btn" onclick="location.href='?mode=sohbet'">Sohbet</div>
      <div class="mode-btn" onclick="location.href='?mode=odev'">Ödev Yardımcısı</div>
      <div class="mode-btn" onclick="location.href='?mode=espri'">Espri Modu</div>
      <div class="mode-btn" onclick="location.href='?mode=sun'">Sunum / Slayt</div>
      <div class="mode-btn" onclick="location.href='?mode=gorsel'">Görsel Oluşturma</div>
      <div class="mode-btn" onclick="location.href='?mode=kalite'">Kalite Yükseltme</div>
      {% if user and user.is_admin %}
        <div class="mode-btn" onclick="location.href='?mode=kod'">Kod Yazma (Admin)</div>
      {% endif %}
    </div>

    <div class="panel">
      <h3>Son mesajlar</h3>
      {% for m in messages %}
        <div class="msg">
          <div><strong>{{m.role|capitalize}}:</strong> {{m.content}}</div>
          <div class="small muted">{{m.timestamp}}</div>
        </div>
      {% else %}
        <div class="small muted">Henüz mesaj yok.</div>
      {% endfor %}
    </div>

    <div class="panel">
      <h4>Model Durumu</h4>
      <div class="small">Ana model: Groq {% if groq_ok %}<span class="success"> (aktif)</span>{% else %}<span class="danger"> (inaktif)</span>{% endif %}</div>
      <div class="small">Yedek: Hugging Face {% if hf_ok %}<span class="success"> (aktif)</span>{% else %}<span class="danger"> (inaktif)</span>{% endif %}</div>
    </div>
  </div>
{% endblock %}
"""

LOGIN_HTML = """
{% extends base %}
{% block body %}
  <div style="max-width:420px;margin:20px auto" class="panel">
    <h3>Giriş</h3>
    <form method="post">
      <div style="margin-bottom:8px"><input name="username" placeholder="Kullanıcı adı" /></div>
      <div style="margin-bottom:8px"><input name="password" placeholder="Şifre" type="password" /></div>
      <button type="submit">Giriş yap</button>
    </form>
    <div class="small muted" style="margin-top:8px">İlk admin: kullanıcı <strong>enes</strong>, şifre <strong>enes1357924680</strong></div>
  </div>
{% endblock %}
"""

REGISTER_HTML = """
{% extends base %}
{% block body %}
  <div style="max-width:420px;margin:20px auto" class="panel">
    <h3>Kayıt Ol</h3>
    <form method="post">
      <div style="margin-bottom:8px"><input name="username" placeholder="Kullanıcı adı" /></div>
      <div style="margin-bottom:8px"><input name="password" placeholder="Şifre" type="password" /></div>
      <div style="margin-bottom:8px"><input name="password2" placeholder="Şifre tekrar" type="password" /></div>
      <button type="submit">Kayıt ol</button>
    </form>
  </div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends base %}
{% block body %}
  <div class="panel">
    <h3>Admin Panel</h3>
    <div class="small">Kullanıcı listesi</div>
    <ul>
      {% for u in users %}
        <li>
          {{u.username}} {% if u.is_admin %}<span class="admin-badge">[ADMIN]</span>{% endif %}
          {% if u.username != 'enes' %}
            {% if not u.is_admin %}
              <button onclick="fetch('{{url_for('make_admin',user_id=u.id)}}',{method:'POST'}).then(()=>location.reload())">Admin yap</button>
            {% else %}
              <button onclick="fetch('{{url_for('revoke_admin',user_id=u.id)}}',{method:'POST'}).then(()=>location.reload())">Adminlıktan al</button>
            {% endif %}
            <button onclick="fetch('{{url_for('delete_user',user_id=u.id)}}',{method:'POST'}).then(()=>location.reload())" class="danger">Sil</button>
          {% else %}
            <span class="small muted">İlk admin silinemez</span>
          {% endif %}
        </li>
      {% endfor %}
    </ul>
    <hr />
    <h4>Admin istekleri (son)</h4>
    <ul>
      {% for a in admin_actions %}
        <li class="small">{{a.timestamp}} — admin_id:{{a.admin_user}} action:{{a.action}} target:{{a.target_user}}</li>
      {% endfor %}
    </ul>
  </div>
{% endblock %}
"""

# -------------------- Routes --------------------
@app.route("/")
def index():
    user = current_user()
    db = get_db()
    msgs = []
    cur = db.execute("SELECT m.*, u.username FROM messages m LEFT JOIN users u ON u.id = m.user_id ORDER BY m.id DESC LIMIT 20")
    for r in cur.fetchall():
        msgs.append({"role": r["role"], "content": r["content"], "timestamp": r["timestamp"], "username": r["username"]})
    # check model status
    groq_ok = bool(GROQ_API_KEY)
    hf_ok = bool(HF_API_KEY)
    return render_template_string(INDEX_HTML, base=BASE_HTML, app_name=APP_NAME, user=user, messages=msgs, groq_ok=groq_ok, hf_ok=hf_ok)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row and row["password"] == password:
            login_user(username)
            return redirect(url_for("index"))
        else:
            return render_template_string(LOGIN_HTML, base=BASE_HTML, app_name=APP_NAME, user=None, error="Hatalı giriş")
    return render_template_string(LOGIN_HTML, base=BASE_HTML, app_name=APP_NAME, user=None)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        password2 = request.form.get("password2","").strip()
        if not username or not password or password != password2:
            return render_template_string(REGISTER_HTML, base=BASE_HTML, app_name=APP_NAME, user=None, error="Hata")
        db = get_db()
        try:
            db.execute("INSERT INTO users (username,password,is_admin,created_at) VALUES (?,?,?,?)",
                       (username, password, 0, datetime.utcnow().isoformat()))
            db.commit()
            login_user(username)
            return redirect(url_for("index"))
        except sqlite3.IntegrityError:
            return render_template_string(REGISTER_HTML, base=BASE_HTML, app_name=APP_NAME, user=None, error="Kullanıcı zaten var")
    return render_template_string(REGISTER_HTML, base=BASE_HTML, app_name=APP_NAME, user=None)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/chat", methods=["POST"])
def chat_submit():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    msg = request.form.get("message","").strip()
    if not msg:
        return redirect(url_for("index"))
    # determine mode param (basic)
    mode = request.args.get("mode","sohbet")
    # Save user message
    log_message(user["id"], "user", msg)
    # Build prompt based on mode
    prompt = build_prompt_for_mode(mode, user, msg)
    # call model
    try:
        out, backend, err = generate_text(prompt)
        if err:
            response_text = f"Hata: {err}"
        else:
            response_text = out
    except Exception as e:
        response_text = f"KralZeka hata: {str(e)}"
    # Save assistant message
    log_message(user["id"], "assistant", response_text)
    return redirect(url_for("index"))

def build_prompt_for_mode(mode, user, msg):
    # Build contextual prompt according to modes the user selected. Turkish texts.
    header = "KralZeka — Türkçe zeka. Kullanıcı isteği: "
    if mode == "odev":
        # If image attached, instruct to narrate and solve; simplified here.
        return header + f"Ödev yardım modu. Kullanıcının sorusu: {msg} Lütfen açık, adım adım çözüm ve kısa test soruları ver."
    if mode == "espri":
        return header + f"Espri modu. Kullanıcı: {msg} Cevabı şakacı ve eğlenceli olsun."
    if mode == "sun":
        return header + f"Sunum modu. Kullanıcının verdiği konu: {msg} 5 slaytlık özet hazırla, madde madde."
    if mode == "gorsel":
        return header + f"Görsel oluşturma isteği: {msg} (sadece kısa prompt üret)"
    if mode == "kalite":
        return header + f"Kalite yükseltme: {msg} Görsel/çeviri iyileştirme önerileri ver."
    if mode == "kod":
        # Admin code helper: ask clarifying if needed (but only admin uses)
        return header + f"Admin kod yardım modu. Kullanıcı: {msg} Çalıştırılabilir kod örneği ve açıklama ver."
    # default: sohbet
    return header + msg

# -------------------- Admin endpoints --------------------
@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("SELECT id,username,is_admin FROM users ORDER BY id ASC").fetchall()
    admin_actions = db.execute("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 30").fetchall()
    return render_template_string(ADMIN_HTML, base=BASE_HTML, app_name=APP_NAME, user=current_user(), users=users, admin_actions=admin_actions)

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
@admin_required
def make_admin(user_id):
    cur_user = current_user()
    db = get_db()
    # prevent making 'enes' admin-change by others? rule: enes cannot be removed; but making admin is allowed
    db.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
    db.commit()
    record_admin_action(cur_user["id"], "make_admin", user_id)
    return jsonify({"ok":True})

@app.route("/admin/revoke_admin/<int:user_id>", methods=["POST"])
@admin_required
def revoke_admin(user_id):
    cur_user = current_user()
    # cannot revoke enes (first admin)
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if row and row["username"] == "enes":
        # record attempt
        record_admin_action(cur_user["id"], "attempt_revoke_enes", user_id)
        return jsonify({"error":"İlk admin (enes) adminlikten alınamaz. Deneme kaydedildi."}), 403
    db.execute("UPDATE users SET is_admin=0 WHERE id=?", (user_id,))
    db.commit()
    record_admin_action(cur_user["id"], "revoke_admin", user_id)
    return jsonify({"ok":True})

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    cur_user = current_user()
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if row and row["username"] == "enes":
        record_admin_action(cur_user["id"], "attempt_delete_enes", user_id)
        return jsonify({"error":"İlk admin silinemez"}), 403
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    record_admin_action(cur_user["id"], "delete_user", user_id)
    return jsonify({"ok":True})

# -------------------- Image upload and retrieval --------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_IMAGE_EXT

@app.route("/upload_image", methods=["POST"])
def upload_image():
    user = current_user()
    if not user:
        return jsonify({"error":"Giriş yapın"}), 403
    if 'image' not in request.files:
        return jsonify({"error":"No file"}), 400
    f = request.files['image']
    if f.filename == "":
        return jsonify({"error":"No selected"}), 400
    if not allowed_file(f.filename):
        return jsonify({"error":"Type not allowed"}), 400
    fn = f"{int(time.time())}_{f.filename}"
    path = os.path.join(UPLOAD_FOLDER, fn)
    f.save(path)
    # We might perform OCR or image parsing here — placeholder
    log_message(user["id"], "user", f"[Görsel yüklendi] {fn}")
    return jsonify({"ok":True, "filename":fn})

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# -------------------- Simple API endpoints --------------------
@app.route("/api/chat", methods=["POST"])
def api_chat():
    api_key = request.headers.get("X-API-KEY")
    # allow logged-in session or provide API key for third-party use (simplified)
    user = current_user()
    if not user and not api_key:
        return jsonify({"error":"Yetkisiz"}), 401
    msg = request.json.get("message","")
    mode = request.json.get("mode","sohbet")
    # if admin-only mode requested but user not admin -> deny
    if mode == "kod" and (not user or user["is_admin"]!=1):
        return jsonify({"error":"Kod modu sadece adminler için"}), 403
    prompt = build_prompt_for_mode(mode, user or {"username":"api"}, msg)
    out, backend, err = generate_text(prompt)
    if err:
        return jsonify({"error":err}), 500
    # log
    if user:
        log_message(user["id"], "user", msg)
        log_message(user["id"], "assistant", out)
    return jsonify({"response":out, "backend":backend})

@app.route("/api/image", methods=["POST"])
def api_image():
    user = current_user()
    if not user:
        return jsonify({"error":"Giriş gerekli"}), 401
    prompt = request.json.get("prompt","")
    try:
        fname = generate_image_from_hf(prompt)
        log_message(user["id"], "assistant", f"[Görsel oluşturuldu] {fname}")
        return jsonify({"file":url_for("uploaded_file", filename=fname)})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# -------------------- Health check route --------------------
@app.route("/health")
def health():
    return jsonify({"status":"ok","time":datetime.utcnow().isoformat()})

# -------------------- Error handlers --------------------
@app.errorhandler(404)
def not_found(e):
    return "Not Found", 404

@app.errorhandler(500)
def internal_error(e):
    tb = traceback.format_exc()
    return f"Internal Error: {str(e)}\n\n{tb}", 500

# -------------------- Run server (for local debug) --------------------
def start_app():
    # init DB context within app
    with app.app_context():
        init_db(force=False)
    # If running via gunicorn, this won't execute.
    app.run(host="0.0.0.0", port=PORT, debug=False)

if __name__ == "__main__":
    start_app()
