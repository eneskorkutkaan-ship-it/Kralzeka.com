#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Tam Sürüm (tek dosya)
- İlk admin: enes / enes1357924680 (otomatik oluşturulur)
- Admin üzerinde işlem yapılmaya çalışılırsa kaydedilir; enes girişte uyarı görür
- Admin-only otomatik kod yazıcı (sohbet benzeri)
- Tüm arayüz Türkçe
- SQLite ile depolama
"""

import os
import re
import sqlite3
import hashlib
import uuid
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, g, render_template_string, request, redirect, url_for, session, flash,
    send_from_directory, jsonify, abort
)
from werkzeug.utils import secure_filename

# ---------------- Config ----------------
APP_NAME = "KralZeka v1"
DB_FILE = os.environ.get("KZ_DB", "kralzeka_v1_full.db")
UPLOAD_FOLDER = os.environ.get("KZ_UPLOADS", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

FLASK_SECRET = os.environ.get("FLASK_SECRET", "change_this_secret_for_prod")
FIRST_ADMIN_USERNAME = "enes"
FIRST_ADMIN_PASSWORD = "enes1357924680"
SALT = "KralZekaSalt_v1"  # for password hashing (sha256). change in prod.

# Limits
USER_DAILY_QUALITY_LIMIT = 5
ALLOWED_EXT = {"png","jpg","jpeg","webp","gif"}
MAX_UPLOAD_MB = 12

# Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = FLASK_SECRET
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# ---------------- DB helpers ----------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT,
    daily_quality_limit INTEGER DEFAULT ?,
    last_reset_date TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    role TEXT,
    content TEXT,
    created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action TEXT,
    target TEXT,
    meta TEXT,
    created_at TEXT,
    FOREIGN KEY(admin_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS quality_uses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    used_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS suggestions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    text TEXT,
    status TEXT DEFAULT 'pending',
    admin_id INTEGER,
    created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS code_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    session_key TEXT,
    state TEXT,
    data TEXT,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY(admin_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filename TEXT,
    path TEXT,
    created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
"""

def init_db():
    db = get_db()
    # sqlite3's executescript doesn't accept parameters; so replace placeholder with number
    sql = SCHEMA_SQL.replace("?", str(USER_DAILY_QUALITY_LIMIT))
    db.executescript(sql)
    db.commit()
    # ensure first admin
    cur = db.execute("SELECT * FROM users WHERE username = ?", (FIRST_ADMIN_USERNAME,))
    row = cur.fetchone()
    if not row:
        ph = hash_password(FIRST_ADMIN_PASSWORD)
        db.execute("INSERT INTO users (username, password_hash, is_admin, created_at, daily_quality_limit) VALUES (?, ?, 1, ?, ?)",
                   (FIRST_ADMIN_USERNAME, ph, datetime.utcnow().isoformat(), 9999))
        db.commit()
    # ensure last_reset_date for all users
    cur = db.execute("SELECT id, last_reset_date FROM users")
    for r in cur.fetchall():
        if r["last_reset_date"] is None:
            db.execute("UPDATE users SET last_reset_date = ? WHERE id = ?", (datetime.utcnow().date().isoformat(), r["id"]))
    db.commit()

# ---------------- Utilities ----------------
def hash_password(password: str) -> str:
    return hashlib.sha256((SALT + password).encode("utf-8")).hexdigest()

def verify_password(stored_hash: str, password: str) -> bool:
    return stored_hash == hash_password(password)

def query_one(query, args=()):
    cur = get_db().execute(query, args)
    r = cur.fetchone()
    cur.close()
    return r

def query_all(query, args=()):
    cur = get_db().execute(query, args)
    r = cur.fetchall()
    cur.close()
    return r

def login_user_row(row):
    session["user_id"] = row["id"]
    session["username"] = row["username"]
    session["is_admin"] = bool(row["is_admin"])

def logout_user():
    session.clear()

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return dict(query_one("SELECT * FROM users WHERE id = ?", (uid,)))

def require_login(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return wrapped

def require_admin(f):
    @wraps(f)
    def wrapped(*a, **kw):
        u = current_user()
        if not u or not u.get("is_admin"):
            return abort(403)
        return f(*a, **kw)
    return wrapped

def record_message(user_id, role, content):
    db = get_db()
    db.execute("INSERT INTO messages (user_id, role, content, created_at) VALUES (?, ?, ?, ?)",
               (user_id, role, content, datetime.utcnow().isoformat()))
    db.commit()

def record_admin_log(admin_id, action, target="", meta=""):
    db = get_db()
    db.execute("INSERT INTO admin_logs (admin_id, action, target, meta, created_at) VALUES (?, ?, ?, ?, ?)",
               (admin_id, action, target, meta, datetime.utcnow().isoformat()))
    db.commit()

def record_suggestion(user_id, text):
    db = get_db()
    db.execute("INSERT INTO suggestions (user_id, text, created_at) VALUES (?, ?, ?)",
               (user_id, text, datetime.utcnow().isoformat()))
    db.commit()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXT

def reset_daily_if_needed(user):
    # If last_reset_date older than today, reset counts
    db = get_db()
    last = user.get("last_reset_date")
    today = datetime.utcnow().date().isoformat()
    if last != today:
        db.execute("UPDATE users SET last_reset_date=?, daily_quality_limit=? WHERE id=?",
                   (today, USER_DAILY_QUALITY_LIMIT, user["id"]))
        db.commit()

def user_waiting_quality_uses(user_id):
    db = get_db()
    today = datetime.utcnow().date().isoformat()
    cur = db.execute("SELECT COUNT(*) as cnt FROM quality_uses WHERE user_id=? AND date(used_at)=date(?)", (user_id, today))
    r = cur.fetchone()
    return r["cnt"] if r else 0

def use_quality_upgrade(user_id):
    db = get_db()
    db.execute("INSERT INTO quality_uses (user_id, used_at) VALUES (?, ?)", (user_id, datetime.utcnow().isoformat()))
    db.commit()

# ---------------- Code session helpers (admin-only interactive generator) ----------------
def start_code_session(admin_id):
    key = uuid.uuid4().hex
    now = datetime.utcnow().isoformat()
    db = get_db()
    db.execute("INSERT INTO code_sessions (admin_id, session_key, state, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
               (admin_id, key, "init", "{}", now, now))
    db.commit()
    return key

def get_code_session(key):
    row = query_one("SELECT * FROM code_sessions WHERE session_key = ?", (key,))
    return dict(row) if row else None

def update_code_session(key, state=None, data=None):
    db = get_db()
    now = datetime.utcnow().isoformat()
    if state is not None and data is not None:
        db.execute("UPDATE code_sessions SET state=?, data=?, updated_at=? WHERE session_key=?", (state, data, now, key))
    elif state is not None:
        db.execute("UPDATE code_sessions SET state=?, updated_at=? WHERE session_key=?", (state, now, key))
    elif data is not None:
        db.execute("UPDATE code_sessions SET data=?, updated_at=? WHERE session_key=?", (data, now, key))
    db.commit()

# Simple generator: produce code text from collected data
def synthesize_code_from_data(data):
    """
    data: dict with keys like 'title','language','features' (list), 'output'
    Return: code string
    """
    lang = data.get("language","python").lower()
    title = data.get("title","KralZekaYeni")
    features = data.get("features", [])
    output = data.get("output", "console")
    # Very simple templates for demonstration — can be extended
    if lang in ("python","py"):
        lines = []
        lines.append("# Auto-generated by KralZeka v1 - örnek kod")
        lines.append(f"# Başlık: {title}")
        lines.append("")
        lines.append("def main():")
        if "chat" in features:
            lines.append("    # Basit sohbet döngüsü (örnek)")
            lines.append("    while True:")
            lines.append("        q = input('Soru: ').strip()")
            lines.append("        if q.lower() in ('çık','exit','quit'): break")
            lines.append("        print('Bu bir örnek yanıttır:', q)")
        elif "classify" in features:
            lines.append("    # Basit sınıflandırma örneği")
            lines.append("    print('Sınıflandırma özelliği için örnek kod')")
        else:
            lines.append("    print('Bu, KralZeka tarafından üretilmiş örnek bir Python programıdır.')")
        lines.append("")
        lines.append("if __name__ == '__main__':")
        lines.append("    main()")
        return "\n".join(lines)
    elif lang in ("javascript","js"):
        lines = []
        lines.append("// Auto-generated by KralZeka v1 - örnek kod")
        lines.append(f"// Başlık: {title}")
        lines.append("function main(){")
        lines.append("  console.log('KralZeka örnek JS programı');")
        lines.append("}")
        lines.append("main();")
        return "\n".join(lines)
    else:
        return f"/* Auto-generated skeleton for language {lang} */\n// Title: {title}\n"

# ---------------- Views / Templates ----------------
# Basic base template using Bootstrap CDN, fully Turkish; small JS for interactivity.
BASE_TEMPLATE = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{app_name}}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body{background:#071018;color:#e6f7f4}
    .card-dark{background:#072827;border:0}
    .muted{color:#98bfb6}
    .admin-badge{background:#ffd700;color:#000;padding:3px 8px;border-radius:6px;font-weight:700}
    .footer{font-size:0.9rem;color:#93bfb5;margin-top:18px}
    pre.code-box{background:#021212;color:#dff7ef;padding:12px;border-radius:8px;white-space:pre-wrap}
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg" style="background:#042626">
  <div class="container-fluid">
    <a class="navbar-brand text-light" href="{{ url_for('index') }}">{{ app_name }}</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        {% if user %}
          <li class="nav-item"><a class="nav-link text-light" href="{{ url_for('index') }}">Panel</a></li>
          <li class="nav-item"><a class="nav-link text-light" href="{{ url_for('modes') }}">Modlar</a></li>
          <li class="nav-item"><a class="nav-link text-light" href="{{ url_for('uploads_page') }}">Görseller</a></li>
          <li class="nav-item"><a class="nav-link text-light" href="{{ url_for('about') }}">Hakkında</a></li>
          {% if user.is_admin %}
            <li class="nav-item"><a class="nav-link text-warning" href="{{ url_for('admin_panel') }}">Yönetici Paneli</a></li>
          {% endif %}
        {% endif %}
      </ul>
      <div class="d-flex">
        {% if user %}
          <div class="me-2 small muted">Merhaba, <strong>{{ user.username }}</strong> {% if user.is_admin %}<span class="admin-badge">Yönetici</span>{% endif %}</div>
          <a class="btn btn-sm btn-outline-light" href="{{ url_for('logout') }}">Çıkış</a>
        {% else %}
          <a class="btn btn-sm btn-success me-2" href="{{ url_for('login') }}">Giriş</a>
          <a class="btn btn-sm btn-secondary" href="{{ url_for('register') }}">Kayıt</a>
        {% endif %}
      </div>
    </div>
  </div>
</nav>

<div class="container py-4">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for cat,msg in messages %}
        <div class="alert alert-{{ 'danger' if cat=='error' else 'info' }} alert-sm">{{ msg }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}

  <div class="footer text-center">
    <div>© KralZeka v1 — KralZeka, Enes’in zekasıyla hayat buldu.</div>
  </div>
</div>

</body>
</html>
"""

# ---------------- Routes ----------------
@app.before_request
def before_request():
    init_db()
    g.user = None
    uid = session.get("user_id")
    if uid:
        row = query_one("SELECT * FROM users WHERE id = ?", (uid,))
        if row:
            g.user = row
            # reset daily if needed
            reset_daily_if_needed(dict(row))

@app.route("/")
@require_login
def index():
    user = current_user()
    # check for admin attempts logged on Enes (if user is enes)
    alerts = []
    if user and user["username"] == FIRST_ADMIN_USERNAME:
        # find any admin_logs where target contains enes or action attempted on enes and not yet acknowledged
        cur = query_all("SELECT * FROM admin_logs WHERE target = ? ORDER BY created_at DESC", (FIRST_ADMIN_USERNAME,))
        for r in cur:
            alerts.append(f"Yönetici eylemi kaydedildi: {r['action']} - meta: {r['meta']} - {r['created_at']}")
    # show recent messages
    msgs = query_all("SELECT m.*, u.username FROM messages m LEFT JOIN users u ON m.user_id=u.id WHERE m.user_id=? ORDER BY m.id DESC LIMIT 10", (user["id"],))
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=user, content_template="""
    {% block content %}
      <div class="row">
        <div class="col-md-8">
          <div class="card card-dark p-3 mb-3">
            <h5>Panel</h5>
            <p class="muted">Modlar, sohbet, görsel yükleme ve daha fazlasına sol menüden erişebilirsin.</p>
            {% if alerts %}
              <div class="alert alert-warning">
                <strong>Uyarılar:</strong>
                <ul>
                {% for a in alerts %}<li>{{a}}</li>{% endfor %}
                </ul>
              </div>
            {% endif %}

            <h6>Son Mesajların</h6>
            {% for m in msgs %}
              <div class="mb-2"><strong>{{ m['username'] or 'Sen' }}:</strong> {{ m['content'] }} <div class="small muted">{{ m['created_at'] }}</div></div>
            {% else %}
              <div class="muted">Henüz mesaj yok.</div>
            {% endfor %}
          </div>

          <div class="card card-dark p-3">
            <h5>Sohbet (Basit Demo)</h5>
            <form method="post" action="{{ url_for('chat') }}">
              <div class="input-group mb-2">
                <input name="q" class="form-control" placeholder="Sorunu yaz... (demo)" />
                <button class="btn btn-success" type="submit">Gönder</button>
              </div>
            </form>
            <div class="muted">Not: Bu demo yerel cevap üretir. Online model entegrasyonu opsiyoneldir.</div>
          </div>

        </div>

        <div class="col-md-4">
          <div class="card card-dark p-3 mb-3">
            <h6>Hızlı İşlemler</h6>
            <div class="mb-2"><a class="btn btn-sm btn-outline-light" href="{{ url_for('modes') }}">Modlar</a></div>
            <div class="mb-2"><a class="btn btn-sm btn-outline-light" href="{{ url_for('uploads_page') }}">Görsel Yükle</a></div>
            <div class="mb-2"><a class="btn btn-sm btn-outline-light" href="{{ url_for('suggest_page') }}">Güncelleme Öner</a></div>
            {% if user.is_admin %}
              <div class="mt-2"><a class="btn btn-warning btn-sm" href="{{ url_for('admin_panel') }}">Yönetici Paneli</a></div>
            {% endif %}
          </div>

          <div class="card card-dark p-3">
            <h6>Hakkında</h6>
            <div>KralZeka, Enes’in zekasıyla hayat buldu.</div>
          </div>
        </div>
      </div>
    {% endblock %}
    """, alerts=alerts)

# --------------- Auth routes ----------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        uname = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        pw2 = request.form.get("password2") or ""
        if not uname or not pw:
            flash("Kullanıcı adı ve şifre gerekli.", "error")
            return redirect(url_for("register"))
        if pw != pw2:
            flash("Şifreler eşleşmiyor.", "error")
            return redirect(url_for("register"))
        # don't allow registering as enes
        if uname == FIRST_ADMIN_USERNAME:
            flash("Bu kullanıcı adı kullanılamaz.", "error")
            return redirect(url_for("register"))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash, is_admin, created_at, last_reset_date) VALUES (?, ?, 0, ?, ?)",
                       (uname, hash_password(pw), datetime.utcnow().isoformat(), datetime.utcnow().date().isoformat()))
            db.commit()
            flash("Kayıt başarılı. Giriş yapabilirsin.", "info")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Bu kullanıcı adı zaten alınmış.", "error")
            return redirect(url_for("register"))
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=None, content_template="""
    {% block content %}
      <div class="card card-dark p-3">
        <h5>Kayıt Ol</h5>
        <form method="post">
          <div class="mb-2"><input class="form-control" name="username" placeholder="Kullanıcı adı"></div>
          <div class="mb-2"><input class="form-control" type="password" name="password" placeholder="Şifre"></div>
          <div class="mb-2"><input class="form-control" type="password" name="password2" placeholder="Şifre tekrar"></div>
          <button class="btn btn-success">Kayıt Ol</button>
        </form>
      </div>
    {% endblock %}
    """)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        uname = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        row = query_one("SELECT * FROM users WHERE username = ?", (uname,))
        if not row or not verify_password(row["password_hash"], pw):
            flash("Kullanıcı adı veya şifre hatalı.", "error")
            return redirect(url_for("login"))
        # login
        login_user_row(row)
        flash("Giriş başarılı.", "info")
        return redirect(url_for("index"))
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=None, content_template="""
    {% block content %}
      <div class="card card-dark p-3">
        <h5>Giriş Yap</h5>
        <form method="post">
          <div class="mb-2"><input class="form-control" name="username" placeholder="Kullanıcı adı"></div>
          <div class="mb-2"><input class="form-control" type="password" name="password" placeholder="Şifre"></div>
          <button class="btn btn-success">Giriş</button>
        </form>
      </div>
    {% endblock %}
    """)

@app.route("/logout")
def logout():
    logout_user()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("login"))

# ---------------- Chat demo route ----------------
@app.route("/chat", methods=["POST"])
@require_login
def chat():
    q = (request.form.get("q") or "").strip()
    if not q:
        flash("Boş mesaj gönderemezsiniz.", "error")
        return redirect(url_for("index"))
    user = current_user()
    # record user message
    record_message(user["id"], "user", q)
    # simple local reply generator (demo)
    reply = generate_local_reply(q)
    record_message(user["id"], "assistant", reply)
    flash("Cevap: " + (reply[:150] + ("..." if len(reply)>150 else "")), "info")
    return redirect(url_for("index"))

def generate_local_reply(q):
    # Very simple heuristics to reply in Turkish
    ql = q.lower()
    if "nasıl" in ql or "neden" in ql:
        return "Bu konuda birkaç faktör etkili olabilir; daha spesifik sorarsan detaylandırırım."
    if "merhaba" in ql or "selam" in ql:
        return "Merhaba! Sana nasıl yardımcı olabilirim?"
    if "görsel" in ql:
        return "Görsel işlemleri için Görseller bölümünü kullanabilirsin."
    return "Bunu anladım — fakat çevrimiçi model entegrasyonu yoksa genel bir cevap veriyorum. Daha özel sorarsan detaylandırırım."

# ---------------- Modes page ----------------
@app.route("/modlar")
@require_login
def modes():
    user = current_user()
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=user, content_template="""
    {% block content %}
      <div class="card card-dark p-3">
        <h5>Modlar</h5>
        <ul>
          <li><strong>Sohbet:</strong> Genel sohbet modu.</li>
          <li><strong>Ödev Yardımcı:</strong> Ders, çalışma kağıdı, soru çözümü (görsel destekli).</li>
          <li><strong>Espri Modu:</strong> Şaka ve eğlence.</li>
          <li><strong>Sunum Modu:</strong> Slayt, afiş taslağı üretme.</li>
          <li><strong>Görsel / Kalite:</strong> Görsel yükle ve kalite yükselt (admin sınırsız).</li>
        </ul>
      </div>
    {% endblock %}
    """)

# ---------------- Uploads ----------------
@app.route("/uploads", methods=["GET","POST"])
@require_login
def uploads_page():
    user = current_user()
    if request.method == "POST":
        if 'file' not in request.files:
            flash("Dosya seçilmedi.", "error")
            return redirect(url_for("uploads_page"))
        f = request.files['file']
        if f.filename == "":
            flash("Dosya adı boş.", "error")
            return redirect(url_for("uploads_page"))
        if not allowed_file(f.filename):
            flash("Geçersiz dosya türü.", "error")
            return redirect(url_for("uploads_page"))
        fname = secure_filename(f.filename)
        dest = os.path.join(app.config['UPLOAD_FOLDER'], f"{int(time.time())}_{fname}")
        f.save(dest)
        # record upload
        db = get_db()
        db.execute("INSERT INTO uploads (user_id, filename, path, created_at) VALUES (?, ?, ?, ?)",
                   (user["id"], fname, dest, datetime.utcnow().isoformat()))
        db.commit()
        flash("Görsel yüklendi.", "info")
        return redirect(url_for("uploads_page"))
    # list user uploads
    ups = query_all("SELECT * FROM uploads WHERE user_id=? ORDER BY id DESC LIMIT 30", (user["id"],))
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=user, content_template="""
    {% block content %}
      <div class="card card-dark p-3">
        <h5>Görsellerim</h5>
        <form method="post" enctype="multipart/form-data">
          <input type="file" name="file" class="form-control mb-2" />
          <button class="btn btn-success">Yükle</button>
        </form>
        <hr/>
        {% for u in ups %}
          <div class="mb-2"><strong>{{ u['filename'] }}</strong> <small class="muted">{{ u['created_at'] }}</small></div>
        {% else %}
          <div class="muted">Yükleme yok.</div>
        {% endfor %}
      </div>
    {% endblock %}
    """, ups=ups)

@app.route("/uploads/file/<int:uid>")
@require_login
def serve_upload(uid):
    row = query_one("SELECT * FROM uploads WHERE id = ?", (uid,))
    if not row:
        abort(404)
    path = row["path"]
    if os.path.exists(path):
        return send_from_directory(os.path.dirname(path), os.path.basename(path))
    abort(404)

# ---------------- Suggestions ----------------
@app.route("/suggest", methods=["GET","POST"])
@require_login
def suggest_page():
    user = current_user()
    if request.method == "POST":
        text = (request.form.get("text") or "").strip()
        if not text:
            flash("Boş öneri gönderilemez.", "error")
            return redirect(url_for("suggest_page"))
        record_suggestion(user["id"], text)
        flash("Öneri gönderildi. Teşekkürler!", "info")
        return redirect(url_for("suggest_page"))
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=user, content_template="""
    {% block content %}
      <div class="card card-dark p-3">
        <h5>Güncelleme / Öneri Gönder</h5>
        <form method="post">
          <textarea name="text" class="form-control mb-2" placeholder="Yeni özellik önerini yaz..."></textarea>
          <button class="btn btn-success">Gönder</button>
        </form>
      </div>
    {% endblock %}
    """)

# ---------------- Admin Panel ----------------
@app.route("/admin/panel", methods=["GET","POST"])
@require_login
@require_admin
def admin_panel():
    user = current_user()
    db = get_db()
    # handle actions: make_admin, remove_user, review suggestions, start code session
    if request.method == "POST":
        action = request.form.get("action")
        if action == "make_admin":
            uid = int(request.form.get("user_id"))
            # prevent making changes to FIRST_ADMIN_USERNAME
            target = query_one("SELECT * FROM users WHERE id = ?", (uid,))
            if target and target["username"] == FIRST_ADMIN_USERNAME:
                flash("Bu işlem yapılamaz: Baş admin korunuyor.", "error")
            else:
                db.execute("UPDATE users SET is_admin=1 WHERE id=?", (uid,))
                db.commit()
                record_admin_log(user["id"], "make_admin", target["username"] if target else str(uid))
                flash("Kullanıcı admin yapıldı.", "info")
        elif action == "remove_user":
            uid = int(request.form.get("user_id"))
            target = query_one("SELECT * FROM users WHERE id = ?", (uid,))
            if target and target["username"] == FIRST_ADMIN_USERNAME:
                # log attempt
                record_admin_log(user["id"], "attempt_remove_first_admin", FIRST_ADMIN_USERNAME, f"attempted by {user['username']}")
                flash("Bu işlem yasak: Baş admin kaldırılamaz. Deneme kaydedildi.", "error")
            else:
                db.execute("DELETE FROM users WHERE id=?", (uid,))
                db.commit()
                record_admin_log(user["id"], "remove_user", target["username"] if target else str(uid))
                flash("Kullanıcı silindi.", "info")
        elif action == "approve_suggestion":
            sid = int(request.form.get("suggestion_id"))
            db.execute("UPDATE suggestions SET status='approved', admin_id=? WHERE id=?", (user["id"], sid))
            db.commit()
            record_admin_log(user["id"], "approve_suggestion", str(sid))
            flash("Öneri onaylandı.", "info")
        elif action == "reject_suggestion":
            sid = int(request.form.get("suggestion_id"))
            db.execute("UPDATE suggestions SET status='rejected', admin_id=? WHERE id=?", (user["id"], sid))
            db.commit()
            record_admin_log(user["id"], "reject_suggestion", str(sid))
            flash("Öneri reddedildi.", "info")
        elif action == "start_code_session":
            sk = start_code_session(user["id"])
            flash("Kod yazma oturumu başlatıldı.", "info")
            return redirect(url_for("code_session", session_key=sk))

    users = query_all("SELECT id, username, is_admin, created_at FROM users ORDER BY id DESC")
    suggestions = query_all("SELECT s.*, u.username FROM suggestions s LEFT JOIN users u ON s.user_id=u.id ORDER BY s.id DESC")
    logs = query_all("SELECT a.*, u.username as adminname FROM admin_logs a LEFT JOIN users u ON a.admin_id=u.id ORDER BY a.id DESC LIMIT 200")
    uploads = query_all("SELECT * FROM uploads ORDER BY id DESC LIMIT 50")
    images = query_all("SELECT * FROM image_jobs ORDER BY id DESC LIMIT 20") if table_exists("image_jobs") else []
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=user, content_template="""
    {% block content %}
      <div class="card card-dark p-3">
        <h5>Yönetici Paneli</h5>
        <div class="row">
          <div class="col-md-6">
            <h6>Kullanıcılar</h6>
            {% for u in users %}
              <div class="mb-2">
                <strong>{{ u['username'] }}</strong> {% if u['is_admin'] %}<span class="muted">(admin)</span>{% endif %} <br/>
                <form style="display:inline" method="post">
                  <input type="hidden" name="user_id" value="{{ u['id'] }}">
                  {% if not u['is_admin'] %}
                    <button name="action" value="make_admin" class="btn btn-sm btn-warning">Admin Yap</button>
                  {% endif %}
                  <button name="action" value="remove_user" class="btn btn-sm btn-danger">Sil</button>
                </form>
              </div>
            {% endfor %}
          </div>

          <div class="col-md-6">
            <h6>Öneriler</h6>
            {% for s in suggestions %}
              <div class="mb-2">
                <strong>#{{ s['id'] }} - {{ s['username'] or 'Anon' }}</strong> <div class="muted">{{ s['created_at'] }}</div>
                <div>{{ s['text'] }}</div>
                {% if s['status'] == 'pending' %}
                  <form method="post" style="display:inline">
                    <input type="hidden" name="suggestion_id" value="{{ s['id'] }}">
                    <button name="action" value="approve_suggestion" class="btn btn-sm btn-success">Onayla</button>
                  </form>
                  <form method="post" style="display:inline">
                    <input type="hidden" name="suggestion_id" value="{{ s['id'] }}">
                    <button name="action" value="reject_suggestion" class="btn btn-sm btn-secondary">Reddet</button>
                  </form>
                {% else %}
                  <div class="muted">Durum: {{ s['status'] }}</div>
                {% endif %}
              </div>
            {% endfor %}
            <hr/>
            <form method="post">
              <button name="action" value="start_code_session" class="btn btn-primary">Otomatik Kod Yazıcıyı Başlat</button>
            </form>
          </div>
        </div>

        <hr/>
        <h6>Admin Loglar (son 200)</h6>
        {% for l in logs %}
          <div class="small muted mb-1">{{ l['created_at'] }} - {{ l['adminname'] or 'Anon' }} - {{ l['action'] }} - {{ l['target'] }} - {{ l['meta'] }}</div>
        {% endfor %}

      </div>
    {% endblock %}
    """, users=users, suggestions=suggestions, logs=logs, uploads=uploads)

# check table exists helper
def table_exists(name):
    cur = get_db().execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",(name,))
    exists = cur.fetchone() is not None
    cur.close()
    return exists

# ---------------- Code session view (admin only interactive) ----------------
@app.route("/admin/code/<session_key>", methods=["GET","POST"])
@require_login
@require_admin
def code_session(session_key):
    user = current_user()
    sess = get_code_session(session_key)
    if not sess or sess["admin_id"] != user["id"]:
        flash("Oturum bulunamadı veya yetkiniz yok.", "error")
        return redirect(url_for("admin_panel"))
    state = sess["state"]
    data = {}
    try:
        data = eval(sess["data"]) if sess["data"] else {}
    except Exception:
        data = {}
    # POST - admin sends input (like a chat message)
    if request.method == "POST":
        text = (request.form.get("text") or "").strip()
        if not text:
            flash("Boş mesaj gönderilemez.", "error")
            return redirect(url_for("code_session", session_key=session_key))
        # store incoming message as admin input (not in messages table)
        # simple state machine:
        if state == "init":
            # first admin prompt becomes title
            data["title"] = text
            # ask for language
            update_code_session(session_key, state="ask_language", data=str(data))
            flash("Hangi programlama dilinde olsun? (ör: python, javascript)", "info")
            return redirect(url_for("code_session", session_key=session_key))
        elif state == "ask_language":
            data["language"] = text.strip().lower()
            update_code_session(session_key, state="ask_features", data=str(data))
            flash("Hangi özellikleri istiyorsun? (virgülle ayır: chat, classify, api, gui vb.)", "info")
            return redirect(url_for("code_session", session_key=session_key))
        elif state == "ask_features":
            feats = [f.strip().lower() for f in text.split(",") if f.strip()]
            data["features"] = feats
            update_code_session(session_key, state="ask_output", data=str(data))
            flash("Çıktı türü ne olsun? (console, web, file)", "info")
            return redirect(url_for("code_session", session_key=session_key))
        elif state == "ask_output":
            data["output"] = text.strip().lower()
            # ready to synthesize
            update_code_session(session_key, state="ready", data=str(data))
            flash("Kod oluşturulmaya hazır. 'Oluştur' butonuna bas.", "info")
            return redirect(url_for("code_session", session_key=session_key))
        elif state == "ready":
            flash("Oturum zaten oluşturulmaya hazır. Oluştur butonuna bas.", "info")
            return redirect(url_for("code_session", session_key=session_key))
    # GET - render
    code_preview = None
    if sess["state"] == "ready":
        try:
            data = eval(sess["data"])
            code_preview = synthesize_code_from_data(data)
        except Exception as e:
            code_preview = f"# Kod üretilemedi: {e}"
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=user, content_template="""
    {% block content %}
      <div class="card card-dark p-3">
        <h5>Otomatik Kod Yazıcı - Oturum</h5>
        <div class="mb-2 small muted">Oturum anahtarı: {{ session_key }}</div>

        <div class="mb-2">
          <form method="post">
            <input name="text" class="form-control mb-2" placeholder="Yanıtınızı yazın (admin sohbeti)"/>
            <button class="btn btn-success">Gönder</button>
          </form>
        </div>

        <div class="mb-2">
          <strong>Durum:</strong> {{ state }} <br/>
          <strong>Veri:</strong> <pre class="code-box">{{ data }}</pre>
        </div>

        {% if code_preview %}
          <div class="mt-3">
            <h6>Oluşturulan Kod (önizleme)</h6>
            <pre class="code-box">{{ code_preview }}</pre>
            <form method="post" action="{{ url_for('finalize_code', session_key=session_key) }}">
              <button class="btn btn-primary">Kodu Kaydet ve Göster</button>
            </form>
          </div>
        {% endif %}

        <div class="mt-3"><a class="btn btn-outline-light" href="{{ url_for('admin_panel') }}">Geri</a></div>
      </div>
    {% endblock %}
    """, session_key=session_key, state=sess["state"], data=sess["data"], code_preview=code_preview)

@app.route("/admin/code/<session_key>/finalize", methods=["POST"])
@require_login
@require_admin
def finalize_code(session_key):
    user = current_user()
    sess = get_code_session(session_key)
    if not sess or sess["admin_id"] != user["id"]:
        flash("Oturum bulunamadı veya yetkiniz yok.", "error")
        return redirect(url_for("admin_panel"))
    if sess["state"] != "ready":
        flash("Oturum hazır değil.", "error")
        return redirect(url_for("code_session", session_key=session_key))
    data = eval(sess["data"])
    code = synthesize_code_from_data(data)
    # store as a message for admin (so can be viewed)
    record_message(user["id"], "assistant", f"--- OLUŞTURULAN KOD ---\n{code}")
    update_code_session(session_key, state="done", data=str(data))
    flash("Kod oluşturuldu ve mesajlara kaydedildi.", "info")
    return redirect(url_for("admin_panel"))

# ---------------- Admin ability to attempt action on enes (simulate prior problem) --------------
# This was addressed in admin_panel actions: if attempt remove enes, it's logged.
# Additionally, show a special alert when enes logs in: handled on index().

# ---------------- Helper endpoints ----------------
@app.route("/about")
def about():
    user = current_user()
    return render_template_string(BASE_TEMPLATE, app_name=APP_NAME, user=user, content_template="""
    {% block content %}
      <div class="card card-dark p-3">
        <h5>Hakkında</h5>
        <p>KralZeka, Enes’in zekasıyla hayat buldu.</p>
        <p>Bu sürüm: v1 — Tam özellikli demo.</p>
      </div>
    {% endblock %}
    """)

# ---------------- Utility simple functions ----------------
def table_exists(name):
    cur = get_db().execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    res = cur.fetchone() is not None
    cur.close()
    return res

# ---------------- Startup ----------------
if __name__ == "__main__":
    # initialize DB and default admin
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
