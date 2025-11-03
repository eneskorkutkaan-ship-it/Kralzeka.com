"""
Aurion - Tek dosyalık Flask uygulaması
Tüm ana özellikler: kullanıcı, roller(admin/mod), admin panel, moderasyon,
arama, sohbet (OpenAI opsiyonel), tema, yüklemeler, geçmiş, logs.
"""

import os
import sqlite3
import uuid
import datetime
from functools import wraps
from flask import (
    Flask, g, render_template_string, request, redirect, url_for,
    session, send_from_directory, flash, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests  # optional for external API usage

# ---- CONFIG ----
APP_NAME = "Aurion"
DB_PATH = os.path.join(os.path.dirname(__file__), "aurion.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SECRET_KEY = os.environ.get("AURION_SECRET_KEY") or "change-this-secret-in-prod"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")  # optional for chat
ADMIN_INIT_PASS = os.environ.get("AURION_ADMIN_PASS") or "adminpass"

# Flask init
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB upload limit
)

# ---- DB HELPERS ----
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    # users: id, username, password_hash, role (user/mod/admin), created_at, banned
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        banned INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        moderated INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS searches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        query TEXT,
        results_count INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        filepath TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.commit()

    # ensure initial admin exists
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if cur.fetchone() is None:
        # create default admin
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash(ADMIN_INIT_PASS), "admin")
        )
        db.commit()
        log("INFO", "Initial admin created (username='admin').")

def log(level, message):
    db = get_db()
    db.execute("INSERT INTO logs (level, message) VALUES (?, ?)", (level, message))
    db.commit()

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

# ---- AUTH HELPERS ----
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    cur = get_db().execute("SELECT * FROM users WHERE id=? LIMIT 1", (uid,))
    return cur.fetchone()

def login_user(user_row):
    session["user_id"] = user_row["id"]
    session["username"] = user_row["username"]
    session["role"] = user_row["role"]

def logout_user():
    session.pop("user_id", None)
    session.pop("username", None)
    session.pop("role", None)

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*a, **kw):
            user = current_user()
            if not user:
                flash("Giriş yapmalısın.", "warning")
                return redirect(url_for("login"))
            if user["banned"]:
                flash("Hesabınız engellenmiş.", "danger")
                return redirect(url_for("index"))
            if user["role"] not in roles:
                flash("Erişim reddedildi.", "danger")
                return redirect(url_for("index"))
            return f(*a, **kw)
        return wrapped
    return decorator

# ---- AI / CHAT STUB ----
def chat_response(prompt, user=None):
    """
    Eğer OPENAI_API_KEY varsa, OpenAI'nın chat endpointini kullan.
    Aksi halde basit echo + timestamp döner.
    """
    if OPENAI_API_KEY:
        try:
            # example using OpenAI Chat Completions v1 (adjust if API changes)
            headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
            payload = {
                "model": "gpt-4o-mini",  # change as desired/available
                "messages": [
                    {"role": "system", "content": "You are Aurion, a helpful assistant."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 400
            }
            resp = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=10)
            if resp.ok:
                data = resp.json()
                # safe extraction
                if "choices" in data and len(data["choices"])>0:
                    return data["choices"][0]["message"]["content"].strip()
            log("WARN", f"OpenAI returned non-ok: {resp.status_code}")
        except Exception as e:
            log("ERROR", f"OpenAI request failed: {str(e)}")
    # fallback
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds")
    return f"[Aurion offline-mode response at {ts}] {prompt[:300]}"

# ---- TEMPLATES (render_template_string kullanacağız) ----
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{ title or APP_NAME }}</title>
  <style>
    :root {
      --bg: #0f1720; --card: #111827; --text: #e6eef6; --accent: #00bcd4;
    }
    [data-theme="light"] {
      --bg: #f4f7fb; --card: #ffffff; --text: #111827; --accent: #0b74ff;
    }
    body { background: radial-gradient(circle at 10% 10%, #071426, var(--bg)); color:var(--text); font-family:Inter,Segoe UI,Arial; margin:0; padding:0; }
    header{background:var(--card); padding:12px 20px; display:flex; align-items:center; gap:12px; box-shadow:0 2px 8px rgba(0,0,0,0.3);}
    header .logo{font-weight:700; color:var(--accent)}
    nav a{margin-right:12px; color:var(--text); text-decoration:none}
    .wrap{max-width:1100px; margin:28px auto; padding:12px;}
    .grid{display:grid; grid-template-columns: 1fr 320px; gap:16px; align-items:start;}
    .card{background:var(--card); padding:16px; border-radius:10px; box-shadow:0 6px 20px rgba(0,0,0,0.4);}
    .messages{max-height:360px; overflow:auto;}
    .msg{padding:8px; margin-bottom:8px; border-radius:6px; background:rgba(255,255,255,0.02)}
    .controls{display:flex; gap:8px; margin-top:8px;}
    .small{font-size:13px; color: #9aa7b2;}
    footer{padding:12px; text-align:center; color:#9aa7b2;}
    .danger{color:#ff6b6b;}
    .ok{color:#7ef9b7;}
    input, textarea, button, select{font-family:inherit;}
    .search-results{max-height:300px; overflow:auto;}
    .topbar-right{margin-left:auto; display:flex; gap:8px; align-items:center;}
    .btn{background:var(--accent); border:none; color:#fff; padding:8px 12px; border-radius:6px; cursor:pointer;}
    .btn.ghost{background:transparent; border:1px solid rgba(255,255,255,0.06);}
    .muted{opacity:0.7}
    @media(max-width:900px){ .grid{grid-template-columns:1fr;} }
  </style>
  <script>
    // Theme toggle with localStorage
    function setTheme(t){ document.documentElement.setAttribute('data-theme', t); localStorage.setItem('aurion_theme', t); }
    document.addEventListener('DOMContentLoaded', ()=> {
      let t = localStorage.getItem('aurion_theme') || 'dark';
      setTheme(t);
      document.getElementById('theme-toggle')?.addEventListener('click', ()=>{
        t = (document.documentElement.getAttribute('data-theme')=='dark')? 'light':'dark';
        setTheme(t);
      });
      // Speech synthesis play for elements with data-tts
      document.querySelectorAll('[data-tts-play]').forEach(btn=>{
        btn.addEventListener('click', ()=> {
          let text = btn.getAttribute('data-tts-play');
          if ('speechSynthesis' in window) {
            const u = new SpeechSynthesisUtterance(text);
            speechSynthesis.speak(u);
          } else {
            alert('TTS desteklenmiyor tarayıcınızda.');
          }
        });
      });
    });
  </script>
</head>
<body>
<header>
  <div class="logo">{{ APP_NAME }}</div>
  <nav>
    <a href="{{ url_for('index') }}">Home</a>
    <a href="{{ url_for('search_page') }}">Ara</a>
    <a href="{{ url_for('chat_page') }}">Chat</a>
    {% if user and user['role'] in ('admin','mod') %}
      <a href="{{ url_for('mod_panel') }}">Mod Panel</a>
    {% endif %}
    {% if user and user['role']=='admin' %}
      <a href="{{ url_for('admin_panel') }}">Admin</a>
    {% endif %}
  </nav>
  <div class="topbar-right">
    <button id="theme-toggle" class="btn ghost">Tema</button>
    {% if user %}
      <div class="small">Merhaba, <strong>{{ user['username'] }}</strong> ({{ user['role'] }})</div>
      <a class="btn" href="{{ url_for('logout') }}">Çıkış</a>
    {% else %}
      <a class="btn" href="{{ url_for('login') }}">Giriş</a>
      <a class="btn ghost" href="{{ url_for('register') }}">Kayıt</a>
    {% endif %}
  </div>
</header>

<div class="wrap">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for cat, msg in messages %}
        <div class="card" style="background:rgba(0,0,0,0.4); margin-bottom:12px;">
          <strong class="{{ 'danger' if cat=='danger' else '' }}">{{ msg }}</strong>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}
</div>

<footer>
  © {{ APP_NAME }} — Tüm gizli anahtarlar ENV'de saklanır.
</footer>
</body>
</html>
"""

# ---- ROUTES ----

@app.route("/")
def index():
    user = current_user()
    # show recent messages and uploads summary
    db = get_db()
    recent_msgs = db.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 8").fetchall()
    recent_uploads = db.execute("SELECT * FROM uploads ORDER BY created_at DESC LIMIT 6").fetchall()
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="grid">
        <div>
          <div class="card">
            <h3>Hoş geldin, {{ user['username'] if user else 'ziyaretçi' }}</h3>
            <p class="small">Aurion genel panosu. Hızlı eylemler ve son etkinlikler aşağıda.</p>
            <div style="margin-top:12px;">
              <a class="btn" href="{{ url_for('chat_page') }}">Sohbet Başlat</a>
              <a class="btn ghost" href="{{ url_for('search_page') }}">Ara</a>
            </div>
          </div>

          <div class="card" style="margin-top:12px;">
            <h4>Son Mesajlar</h4>
            <div class="messages">
            {% for m in recent_msgs %}
              <div class="msg"><strong>{{ m['username'] or 'Anon' }}</strong> <span class="small">— {{ m['created_at'] }}</span>
                <div>{{ m['content'] }}</div>
              </div>
            {% else %}
              <div class="small muted">Henüz mesaj yok.</div>
            {% endfor %}
            </div>
          </div>
        </div>

        <div>
          <div class="card">
            <h4>Uploadlar</h4>
            <div>
            {% for u in recent_uploads %}
              <div class="small"><a href="{{ url_for('download_file', filename=u['filepath'].split('/')[-1]) }}">{{ u['filename'] }}</a> — {{ u['created_at'] }}</div>
            {% else %}
              <div class="small muted">Dosya yok.</div>
            {% endfor %}
            </div>
          </div>

          <div class="card" style="margin-top:12px;">
            <h4>Hızlı Eylemler</h4>
            <div class="controls">
              <a class="btn" href="{{ url_for('register') }}">Kayıt Ol</a>
              <a class="btn ghost" href="{{ url_for('login') }}">Giriş Yap</a>
            </div>
          </div>
        </div>
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=user, recent_msgs=recent_msgs, recent_uploads=recent_uploads)

# ---- REGISTER / LOGIN / LOGOUT ----
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Kullanıcı adı ve şifre gerekli.", "danger")
            return redirect(url_for("register"))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, generate_password_hash(password)))
            db.commit()
            flash("Kayıt başarılı. Giriş yapabilirsiniz.", "ok")
            log("INFO", f"New user registered: {username}")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Bu kullanıcı adı alınmış.", "danger")
            return redirect(url_for("register"))
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="card">
        <h3>Kayıt Ol</h3>
        <form method="post">
          <div><input name="username" placeholder="Kullanıcı adı" required></div>
          <div style="margin-top:8px;"><input type="password" name="password" placeholder="Şifre" required></div>
          <div style="margin-top:12px;"><button class="btn">Kayıt Ol</button></div>
        </form>
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=current_user())

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username=? LIMIT 1", (username,))
        row = cur.fetchone()
        if row and check_password_hash(row["password_hash"], password):
            if row["banned"]:
                flash("Hesabınız banlı.", "danger")
                return redirect(url_for("login"))
            login_user(row)
            flash("Giriş başarılı.", "ok")
            log("INFO", f"User logged in: {username}")
            return redirect(url_for("index"))
        flash("Kullanıcı adı veya şifre yanlış.", "danger")
        return redirect(url_for("login"))
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="card">
        <h3>Giriş</h3>
        <form method="post">
          <div><input name="username" placeholder="Kullanıcı adı" required></div>
          <div style="margin-top:8px;"><input type="password" name="password" placeholder="Şifre" required></div>
          <div style="margin-top:12px;"><button class="btn">Giriş</button></div>
        </form>
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=current_user())

@app.route("/logout")
def logout():
    logout_user()
    flash("Çıkış yapıldı.", "ok")
    return redirect(url_for("index"))

# ---- CHAT ----
@app.route("/chat", methods=["GET","POST"])
def chat_page():
    user = current_user()
    db = get_db()
    if request.method=="POST":
        prompt = request.form.get("prompt","").strip()
        if not prompt:
            flash("Mesaj boş olamaz.", "danger")
            return redirect(url_for("chat_page"))
        # record message by user
        uid = user["id"] if user else None
        username = user["username"] if user else "Anon"
        db.execute("INSERT INTO messages (user_id, username, content) VALUES (?, ?, ?)", (uid, username, prompt))
        db.commit()
        # get response from AI
        resp = chat_response(prompt, user)
        db.execute("INSERT INTO messages (user_id, username, content) VALUES (?, ?, ?)", (None, APP_NAME, resp))
        db.commit()
        log("INFO", f"Chat used by {username}")
        return redirect(url_for("chat_page"))
    # show last 30 messages
    msgs = db.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 60").fetchall()[::-1]
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="grid">
        <div>
          <div class="card">
            <h3>Sohbet</h3>
            <div class="messages">
              {% for m in msgs %}
                <div class="msg"><strong>{{ m['username'] }}</strong> <span class="small">— {{ m['created_at'] }}</span>
                  <div>{{ m['content'] }}</div>
                </div>
              {% endfor %}
            </div>

            <form method="post" style="margin-top:12px;">
              <textarea name="prompt" placeholder="Sorunu yaz..." rows="3" style="width:100%"></textarea>
              <div style="display:flex; gap:8px; margin-top:8px;">
                <button class="btn">Gönder</button>
                <button type="button" class="btn ghost" onclick="document.querySelector('textarea[name=prompt]').value='';">Temizle</button>
              </div>
            </form>
          </div>
        </div>

        <div>
          <div class="card">
            <h4>Özellikler</h4>
            <p class="small">TTS için her yanıtın yanında oynatma düğmesi vardır.</p>
            <div style="margin-top:8px;">
              <button class="btn" onclick="document.getElementById('tts-demo').click();">Örnek TTS</button>
            </div>
            <div style="display:none;">
              <button id="tts-demo" data-tts-play="Merhaba, Aurion sizinle konuşuyor.">TTS</button>
            </div>
          </div>

          <div class="card" style="margin-top:12px;">
            <h4>Geçmiş / Yönetim</h4>
            <div class="small">Mesaj geçmişi saklanır. Moderatörler içeriği düzenleyebilir/engelleyebilir.</div>
            <div style="margin-top:8px;">
              <a class="btn ghost" href="{{ url_for('view_logs') }}">Logs</a>
              <a class="btn" href="{{ url_for('search_history') }}">Arama Geçmişi</a>
            </div>
          </div>
        </div>
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=user, msgs=msgs)

# ---- SEARCH ----
@app.route("/search", methods=["GET","POST"])
def search_page():
    user = current_user()
    db = get_db()
    results = []
    q = ""
    if request.method=="POST":
        q = request.form.get("q","").strip()
        if q:
            # simple LIKE search over messages and uploads
            res_msgs = db.execute("SELECT id, 'message' as type, content as text, created_at FROM messages WHERE content LIKE ? ORDER BY created_at DESC LIMIT 50", ('%'+q+'%',)).fetchall()
            res_files = db.execute("SELECT id, 'file' as type, filename as text, created_at FROM uploads WHERE filename LIKE ? ORDER BY created_at DESC LIMIT 50", ('%'+q+'%',)).fetchall()
            results = list(res_msgs) + list(res_files)
            db.execute("INSERT INTO searches (user_id, query, results_count) VALUES (?, ?, ?)", (user["id"] if user else None, q, len(results)))
            db.commit()
            log("INFO", f"Search performed: {q}")
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="card">
        <h3>Ara</h3>
        <form method="post">
          <input name="q" placeholder="Arama..." value="{{ q }}" style="width:70%; padding:8px;">
          <button class="btn">Ara</button>
        </form>
        <div class="search-results" style="margin-top:12px;">
          {% if results %}
            {% for r in results %}
              <div style="padding:8px; border-bottom:1px solid rgba(255,255,255,0.03);">
                <strong>{{ r['type'] }}</strong> — {{ r['text'] }} <span class="small">({{ r['created_at'] }})</span>
              </div>
            {% endfor %}
          {% else %}
            <div class="small muted">Sonuç yok.</div>
          {% endif %}
        </div>
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=user, results=results, q=q)

@app.route("/history/search")
def search_history():
    user = current_user()
    db = get_db()
    rows = db.execute("SELECT * FROM searches ORDER BY created_at DESC LIMIT 200").fetchall()
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="card">
        <h3>Arama Geçmişi</h3>
        <div class="small">
          {% for r in rows %}
            <div style="padding:6px;">[{{ r['created_at'] }}] {{ r['query'] }} — sonuç: {{ r['results_count'] }}</div>
          {% else %}
            <div class="muted">Geçmiş boş.</div>
          {% endfor %}
        </div>
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=user, rows=rows)

# ---- UPLOADS ----
ALLOWED_EXT = {'png','jpg','jpeg','gif','webp','pdf','txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

@app.route("/upload", methods=["GET","POST"])
def upload():
    user = current_user()
    if not user:
        flash("Yükleme için giriş yapmalısınız.", "danger")
        return redirect(url_for("login"))
    if request.method=="POST":
        f = request.files.get("file")
        if not f or f.filename=="":
            flash("Dosya seçin.", "danger")
            return redirect(url_for("upload"))
        if not allowed_file(f.filename):
            flash("Bu dosya türüne izin verilmiyor.", "danger")
            return redirect(url_for("upload"))
        # save
        sec = str(uuid.uuid4())
        ext = f.filename.rsplit(".",1)[1].lower()
        fname = f"{sec}.{ext}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
        f.save(path)
        db = get_db()
        db.execute("INSERT INTO uploads (user_id, filename, filepath) VALUES (?, ?, ?)", (user["id"], f.filename, path))
        db.commit()
        flash("Yüklendi.", "ok")
        return redirect(url_for("index"))
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="card">
        <h3>Dosya Yükle</h3>
        <form method="post" enctype="multipart/form-data">
          <input type="file" name="file">
          <div style="margin-top:8px;"><button class="btn">Yükle</button></div>
        </form>
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=user)

@app.route("/uploads/<path:filename>")
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# ---- MODERATION PANEL ----
@app.route("/mod", methods=["GET","POST"])
@require_role('admin','mod')
def mod_panel():
    user = current_user()
    db = get_db()
    # moderate message (POST)
    if request.method=="POST":
        action = request.form.get("action")
        target_id = request.form.get("target_id")
        if action=="delete_msg":
            db.execute("DELETE FROM messages WHERE id=?", (target_id,))
            db.commit()
            flash("Mesaj silindi.", "ok")
            log("INFO", f"{user['username']} deleted message {target_id}")
        elif action=="moderate_msg":
            db.execute("UPDATE messages SET moderated=1 WHERE id=?", (target_id,))
            db.commit()
            flash("Mesaj moderasyona alındı.", "ok")
            log("INFO", f"{user['username']} moderated message {target_id}")
        elif action=="ban_user":
            db.execute("UPDATE users SET banned=1 WHERE id=?", (target_id,))
            db.commit()
            flash("Kullanıcı banlandı.", "ok")
            log("INFO", f"{user['username']} banned user {target_id}")
        return redirect(url_for("mod_panel"))
    msgs = db.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 200").fetchall()
    users = db.execute("SELECT id, username, role, banned FROM users ORDER BY created_at DESC LIMIT 200").fetchall()
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="card">
        <h3>Moderasyon Paneli</h3>
        <div class="small">Mesajları düzenle/sil, kullanıcıları banla.</div>

        <h4 style="margin-top:10px;">Kullanıcılar</h4>
        {% for u in users %}
          <div style="padding:6px; border-bottom:1px solid rgba(255,255,255,0.03);">
            {{ u['id'] }} — {{ u['username'] }} ({{ u['role'] }}) {% if u['banned'] %}<span class="danger">BANNED</span>{% endif %}
            <form method="post" style="display:inline;">
              <input type="hidden" name="target_id" value="{{ u['id'] }}">
              <button name="action" value="ban_user" class="btn ghost" style="margin-left:6px;">Ban</button>
            </form>
          </div>
        {% endfor %}

        <h4 style="margin-top:10px;">Mesajlar</h4>
        {% for m in msgs %}
          <div style="padding:6px;border-bottom:1px solid rgba(255,255,255,0.03);">
            <strong>{{ m['username'] }}</strong> — {{ m['created_at'] }}<div>{{ m['content'] }}</div>
            <form method="post" style="margin-top:6px;">
              <input type="hidden" name="target_id" value="{{ m['id'] }}">
              <button name="action" value="delete_msg" class="btn ghost">Sil</button>
              <button name="action" value="moderate_msg" class="btn">Moderate</button>
            </form>
          </div>
        {% endfor %}
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=user, msgs=msgs, users=users)

# ---- ADMIN PANEL ----
@app.route("/admin", methods=["GET","POST"])
@require_role('admin')
def admin_panel():
    user = current_user()
    db = get_db()
    if request.method=="POST":
        # change user roles, system logs view, clear logs
        if request.form.get("action")=="set_role":
            uid = request.form.get("user_id")
            role = request.form.get("role")
            db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
            db.commit()
            flash("Rol güncellendi.", "ok")
            log("INFO", f"Admin {user['username']} set role {uid} -> {role}")
        if request.form.get("action")=="clear_logs":
            db.execute("DELETE FROM logs")
            db.commit()
            flash("Logs temizlendi.", "ok")
            log("INFO", f"Admin {user['username']} cleared logs")
        return redirect(url_for("admin_panel"))
    users = db.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC").fetchall()
    logs = db.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 500").fetchall()
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="card">
        <h3>Admin Panel</h3>
        <h4>Kullanıcılar</h4>
        {% for u in users %}
          <div style="padding:8px; border-bottom:1px solid rgba(255,255,255,0.03);">
            {{ u['id'] }} — {{ u['username'] }} — {{ u['role'] }} — {{ u['created_at'] }}
            <form method="post" style="display:inline;">
              <input type="hidden" name="user_id" value="{{ u['id'] }}">
              <select name="role">
                <option value="user" {% if u['role']=='user' %}selected{% endif %}>user</option>
                <option value="mod" {% if u['role']=='mod' %}selected{% endif %}>mod</option>
                <option value="admin" {% if u['role']=='admin' %}selected{% endif %}>admin</option>
              </select>
              <button name="action" value="set_role" class="btn">Set Role</button>
            </form>
          </div>
        {% endfor %}

        <h4 style="margin-top:12px;">Sistem Logs</h4>
        <form method="post"><button name="action" value="clear_logs" class="btn ghost">Clear Logs</button></form>
        <div style="max-height:300px; overflow:auto; margin-top:8px;">
          {% for l in logs %}
            <div class="small">[{{ l['created_at'] }}] {{ l['level'] }} — {{ l['message'] }}</div>
          {% else %}
            <div class="muted small">Log yok.</div>
          {% endfor %}
        </div>
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=user, users=users, logs=logs)

# ---- LOGS VIEW (accessible to mods/admins) ----
@app.route("/logs")
@require_role('admin','mod')
def view_logs():
    db = get_db()
    rows = db.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 500").fetchall()
    return render_template_string(BASE_HTML + """
    {% block content %}
      <div class="card">
        <h3>Logs</h3>
        {% for r in rows %}
          <div class="small">[{{ r['created_at'] }}] {{ r['level'] }} — {{ r['message'] }}</div>
        {% else %}
          <div class="muted">Log yok.</div>
        {% endfor %}
      </div>
    {% endblock %}
    """, APP_NAME=APP_NAME, user=current_user(), rows=rows)

# ---- Simple health / status endpoint ----
@app.route("/.well-known/status")
def status():
    return jsonify({"app": APP_NAME, "status": "ok", "time": datetime.datetime.utcnow().isoformat()}), 200

# ---- STATIC HELPERS ----
@app.errorhandler(413)
def too_large(e):
    flash("Dosya çok büyük.", "danger")
    return redirect(url_for("upload"))

# ---- STARTUP ----
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
else:
    # when run as WSGI (gunicorn), ensure DB init once
    with app.app_context():
        init_db()
