#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka - Tek dosyalık web uygulaması
Kurulum:
  - Ortam değişkenleri: GROQ_API_KEY, HF_API_KEY, FLASK_SECRET
  - pip install -r requirements.txt
Çalıştırma (local): FLASK_APP=kralzeka_app.py FLASK_ENV=development flask run
"""
import os
import json
import time
import sqlite3
import requests
import traceback
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import quote_plus

from flask import (
    Flask, request, render_template_string, redirect, url_for,
    session, g, flash, send_from_directory, jsonify
)
from werkzeug.utils import secure_filename

# ---------- Ayarlar ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "kralzeka.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

GROQ_KEY = os.environ.get("GROQ_API_KEY")  # chat için
HF_KEY = os.environ.get("HF_API_KEY")      # görsel için (Hugging Face)
FLASK_SECRET = os.environ.get("FLASK_SECRET", "change_this_secret_in_env")

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5MB
# -----------------------------

# -- Basit DB yardımcıları (sqlite) --
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def query_db(query, args=(), one=False, commit=False):
    cur = get_db().execute(query, args)
    if commit:
        get_db().commit()
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def init_db(app):
    with app.app_context():  # <--- uygulama bağlamı içinde çalıştır
        db = get_db()
        cur = db.cursor()
        # users table: id, username, password (plaintext for prototype; prod: hash!), is_admin, created_at
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT
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
        CREATE TABLE IF NOT EXISTS features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            daily_limit INTEGER DEFAULT 5
        );
        CREATE TABLE IF NOT EXISTS user_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            feature_id INTEGER,
            used_today INTEGER DEFAULT 0,
            last_reset TEXT
        );
        CREATE TABLE IF NOT EXISTS admin_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user_id INTEGER,
            action TEXT,
            target_user TEXT,
            note TEXT,
            created_at TEXT
        );
        """)
        db.commit()
        # default admin: enes / enes1357924680 (only create if not exists)
        row = query_db("SELECT * FROM users WHERE username = ?", ("enes",), one=True)
        if not row:
            cur.execute("INSERT INTO users (username, password, is_admin, created_at) VALUES (?, ?, ?, ?)",
                        ("enes", "enes1357924680", 1, datetime.utcnow().isoformat()))
            db.commit()

# ------------- Flask App Factory -------------
def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = FLASK_SECRET
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_BYTES

    # init db
    init_db(app)

    # ---------- basit kimlik decorator'ları ----------
    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated

    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            u = query_db("SELECT * FROM users WHERE id = ?", (session["user_id"],), one=True)
            if not u or not u["is_admin"]:
                flash("Bu sayfaya erişim için admin olmalısın.", "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated

    # ---------- küçük yardımcılar ----------
    def record_message(username, role, content, response=None):
        query_db("INSERT INTO messages (user_id, username, role, content, response, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                 (session.get("user_id"), username, role, content, response or "", datetime.utcnow().isoformat()), commit=True)

    def safe_response_text(t):
        if isinstance(t, dict):
            return json.dumps(t, ensure_ascii=False)
        return str(t)

    # ---------- chat backend: Groq çağır (varsa) ----------
    def call_groq_chat(prompt):
        if not GROQ_KEY:
            return None, "GROQ_KEY yok"
        try:
            # örnek Groq sohbet endpoint (kullanıcının API'sine göre değişebilir)
            # Burada en basit POST örneği: (Gerçek endpoint ve body Groq dokümantasyonuna göre düzenlenmeli)
            url = "https://api.groq.com/openai/v1/chat/completions"  # bazı kullanıcılar benzer endpoint kullandı
            headers = {"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"}
            payload = {
                "model": "gpt-4o-mini",  # modeli kendi konsolundan seç
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 512
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=20)
            if resp.status_code != 200:
                return None, f"Hata {resp.status_code}: {resp.text}"
            data = resp.json()
            # uyarlanabilir: farklı response formatı olabilir
            # try common places:
            if "choices" in data and len(data["choices"])>0:
                content = data["choices"][0].get("message", {}).get("content") or data["choices"][0].get("text")
                return content, None
            if "output" in data:
                return data["output"], None
            return str(data), None
        except Exception as e:
            return None, f"Groq çağrısında hata: {e}"

    # ---------- fallback local search/synth (basit) ----------
    def local_fallback_answer(q):
        # Basit heuristic cevap üretir: (geliştirilebilir)
        return f"Şu anda uzak model kullanılamıyor. Sorunu aldım: \"{q}\". Daha detaylı cevap istiyorsan 'araştır' yaz."

    # ---------- HuggingFace görsel üretim (varsa) ----------
    def hf_generate_image(prompt):
        if not HF_KEY:
            return None, "HF_KEY yok"
        try:
            # Kısa örnek: HuggingFace text-to-image inference
            url = "https://api-inference.huggingface.co/models/stabilityai/stable-diffusion-2"
            headers = {"Authorization": f"Bearer {HF_KEY}"}
            payload = {"inputs": prompt}
            r = requests.post(url, headers=headers, json=payload, timeout=60)
            if r.status_code != 200:
                return None, f"HF hata {r.status_code}: {r.text}"
            # Model döndüğünde genelde base64 veya blob gelebilir; burada örnek olarak image bytes beklenir
            return r.content, None
        except Exception as e:
            return None, f"HF çağrısında hata: {e}"

    # ---------- Routes ----------
    @app.before_request
    def load_user():
        g.user = None
        if "user_id" in session:
            g.user = query_db("SELECT * FROM users WHERE id = ?", (session["user_id"],), one=True)

    @app.route("/")
    def index():
        if g.user:
            username = g.user["username"]
            is_admin = bool(g.user["is_admin"])
            return render_template_string(PAGE_HOME, username=username, is_admin=is_admin)
        return redirect(url_for("login"))

    # ---------- Auth ----------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            u = request.form.get("username", "").strip()
            p = request.form.get("password", "").strip()
            if not u or not p:
                flash("Kullanıcı adı veya şifre boş olamaz.", "danger")
                return redirect(url_for("login"))
            row = query_db("SELECT * FROM users WHERE username = ? AND password = ?", (u, p), one=True)
            if not row:
                flash("Giriş başarısız.", "danger")
                return redirect(url_for("login"))
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            flash("Giriş başarılı.", "success")
            return redirect(url_for("index"))
        return render_template_string(PAGE_LOGIN)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            u = request.form.get("username", "").strip()
            p = request.form.get("password", "").strip()
            p2 = request.form.get("password2", "").strip()
            if not u or not p or p != p2:
                flash("Bilgiler hatalı veya şifreler eşleşmiyor.", "danger")
                return redirect(url_for("register"))
            try:
                query_db("INSERT INTO users (username, password, is_admin, created_at) VALUES (?, ?, ?, ?)",
                         (u, p, 0, datetime.utcnow().isoformat()), commit=True)
                flash("Kayıt başarılı. Giriş yapabilirsin.", "success")
                return redirect(url_for("login"))
            except Exception as e:
                flash(f"Kayıt hatası: {e}", "danger")
                return redirect(url_for("register"))
        return render_template_string(PAGE_REGISTER)

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Çıkış yapıldı.", "info")
        return redirect(url_for("login"))

    # ---------- Chat endpoint (AJAX) ----------
    @app.route("/api/chat", methods=["POST"])
    @login_required
    def api_chat():
        data = request.json or {}
        question = data.get("q") or data.get("question") or ""
        if not question:
            return jsonify({"ok": False, "error": "Boş soru"}), 400

        # kayıt
        record_message(session.get("username", "anon"), "user", question)

        # 1) öncelikle Groq ile dene
        content, err = call_groq_chat(question)
        if content:
            record_message("KralZeka", "assistant", question, safe_response_text(content))
            return jsonify({"ok": True, "source": "groq", "answer": content})
        # groq başarısızsa fallback: Hugging Face text model? (yoksa local)
        # (HF text generation endpoint farklı; burada basit fallback)
        fallback = local_fallback_answer(question)
        record_message("KralZeka", "assistant", question, fallback)
        return jsonify({"ok": True, "source": "fallback", "answer": fallback, "error": err})

    # ---------- Upload (image) ----------
    def allowed_file(filename):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

    @app.route("/upload", methods=["POST"])
    @login_required
    def upload():
        if "file" not in request.files:
            flash("Dosya yok.", "danger")
            return redirect(url_for("index"))
        f = request.files["file"]
        if f.filename == "":
            flash("Dosya seçilmedi.", "danger")
            return redirect(url_for("index"))
        if not allowed_file(f.filename):
            flash("Dosya türü desteklenmiyor.", "danger")
            return redirect(url_for("index"))
        filename = secure_filename(f.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        f.save(save_path)
        flash("Yükleme başarılı.", "success")
        # Görselde soru varsa (ör: OCR vs) burada işleyebilirsin; şu an sadece dosyayı kaydediyoruz.
        return redirect(url_for("index"))

    @app.route("/uploads/<path:filename>")
    def uploaded_file(filename):
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    # ---------- Admin panel ----------
    @app.route("/admin")
    @admin_required
    def admin_panel():
        users = query_db("SELECT id,username,is_admin,created_at FROM users ORDER BY id DESC")
        msgs = query_db("SELECT * FROM messages ORDER BY id DESC LIMIT 50")
        actions = query_db("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 50")
        return render_template_string(PAGE_ADMIN, users=users, messages=msgs, actions=actions)

    @app.route("/admin/do", methods=["POST"])
    @admin_required
    def admin_do():
        action = request.form.get("action")
        target = request.form.get("target")
        note = request.form.get("note", "")
        admin_id = session.get("user_id")
        # örnek: kullanıcıyı admin yap
        if action == "make_admin" and target:
            query_db("UPDATE users SET is_admin = 1 WHERE username = ?", (target,), commit=True)
            query_db("INSERT INTO admin_actions (admin_user_id, action, target_user, note, created_at) VALUES (?, ?, ?, ?, ?)",
                     (admin_id, "make_admin", target, note, datetime.utcnow().isoformat()), commit=True)
            flash(f"{target} admin yapıldı.", "success")
        elif action == "remove_user" and target:
            # enes adminini kimse silemez
            if target == "enes":
                flash("enes admini kaldırılamaz.", "danger")
            else:
                query_db("DELETE FROM users WHERE username = ?", (target,), commit=True)
                query_db("INSERT INTO admin_actions (admin_user_id, action, target_user, note, created_at) VALUES (?, ?, ?, ?, ?)",
                         (admin_id, "remove_user", target, note, datetime.utcnow().isoformat()), commit=True)
                flash(f"{target} silindi.", "info")
        else:
            flash("Bilinmeyen admin işlemi.", "warning")
        return redirect(url_for("admin_panel"))

    # ---------- Hata bildirim ve otomatik düzeltme öneri (admin onayı ile) ----------
    @app.route("/report_error", methods=["POST"])
    @login_required
    def report_error():
        err = request.form.get("error", "")
        # kaydet
        query_db("INSERT INTO admin_actions (admin_user_id, action, target_user, note, created_at) VALUES (?, ?, ?, ?, ?)",
                 (session.get("user_id"), "error_report", session.get("username"), err, datetime.utcnow().isoformat()), commit=True)
        flash("Hata bildirimi alındı. Admin onayı gerekecek.", "info")
        return redirect(url_for("index"))

    # ---------- Basit health check ----------
    @app.route("/health")
    def health():
        return jsonify({"ok": True, "time": datetime.utcnow().isoformat()})

    # ---------- Templates (HTML inline: PAGE_HOME, PAGE_LOGIN, PAGE_REGISTER, PAGE_ADMIN) ----------
    # For brevity, templates are minimal and styled; they include JS to call /api/chat
    global PAGE_LOGIN, PAGE_REGISTER, PAGE_HOME, PAGE_ADMIN
    PAGE_LOGIN = """
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>KralZeka - Giriş</title>
      <style>body{background:#0b0b0b;color:#eee;font-family:Arial;margin:2rem} .card{background:#081012;padding:20px;border-radius:8px;max-width:480px}</style>
      </head>
      <body>
        <h1>KralZeka - Giriş</h1>
        <div class="card">
          <form method="post">
            <label>Kullanıcı:</label><br><input name="username"><br>
            <label>Şifre:</label><br><input type="password" name="password"><br><br>
            <button type="submit">Giriş</button>
          </form>
          <p>Yeni misin? <a href="{{ url_for('register') }}">Kayıt ol</a></p>
        </div>
      </body>
    </html>
    """

    PAGE_REGISTER = """
    <!doctype html>
    <html><head><meta charset="utf-8"><title>KralZeka - Kayıt</title></head><body style="background:#0b0b0b;color:#eee;font-family:Arial;">
      <h1>Kayıt</h1>
      <form method="post">
        <input name="username" placeholder="Kullanıcı"><br>
        <input name="password" type="password" placeholder="Şifre"><br>
        <input name="password2" type="password" placeholder="Şifre tekrar"><br>
        <button type="submit">Kayıt</button>
      </form>
      <p><a href="{{ url_for('login') }}">Giriş yap</a></p>
    </body></html>
    """

    PAGE_HOME = """
    <!doctype html>
    <html><head><meta charset="utf-8"><title>KralZeka</title>
    <style>
      body{background:#050606;color:#e6f3e9;font-family:Inter,Arial;margin:2rem}
      .container{max-width:900px;margin:0 auto}
      .top{display:flex;justify-content:space-between;align-items:center}
      #chatbox{background:#061414;padding:20px;border-radius:10px;margin-top:20px}
      .msg{background:#083232;padding:14px;border-radius:8px;margin:10px 0}
      .user{font-weight:700;color:#c8f1d5}
      .assistant{font-weight:700;color:#fff2c6}
      input[type=text]{width:78%;padding:12px;border-radius:8px;border:1px solid #123}
      button{padding:10px 16px;border-radius:8px;background:#178f4a;color:white;border:none}
      a{color:#8fb7ff}
      .small{color:#9ab}
    </style>
    </head><body>
      <div class="container">
        <div class="top">
          <h1>Merhaba, {{ username }} {% if is_admin %}<span style="color:#d3a32a">[ADMIN]</span>{% endif %}</h1>
          <div><a href="{{ url_for('logout') }}">Çıkış yap</a> {% if is_admin %}| <a href="{{ url_for('admin_panel') }}">Admin Panel</a>{% endif %}</div>
        </div>

        <div id="chatbox">
          <div id="messages"></div>

          <div style="margin-top:12px;">
            <input id="q" placeholder="Bir şey yaz..." type="text">
            <button id="send">Gönder</button>
            <form enctype="multipart/form-data" action="{{ url_for('upload') }}" method="post" style="display:inline-block;margin-left:10px">
              <input type="file" name="file" accept="image/*">
              <button type="submit">Fotoğraf Yükle</button>
            </form>
          </div>
        </div>

        <h3>Son mesajlar</h3>
        <div class="small">Tüm işlemler kayıt altındadır. Bu prototipte şifreler düz metin saklanır (geliştirme için). Admin: enes / enes1357924680</div>
      </div>

      <script>
        async function addMessage(role, text){
          const el = document.createElement('div'); el.className='msg';
          el.innerHTML = '<div class="'+(role==='user'?'user':'assistant')+'">'+(role==='user'?'Sen: ':'KralZeka: ') + '</div><div>' + text + '</div>';
          document.getElementById('messages').prepend(el);
        }
        document.getElementById('send').addEventListener('click', async ()=>{
          const q = document.getElementById('q').value;
          if(!q) return;
          addMessage('user', q);
          document.getElementById('q').value='';
          const resp = await fetch('/api/chat', {method:'POST',headers:{'Content-Type':'application/json'}, body: JSON.stringify({q})});
          const data = await resp.json();
          if(data.ok){
            addMessage('assistant', data.answer);
          } else {
            addMessage('assistant', 'Hata: ' + (data.error || 'Bilinmeyen'));
          }
        });
      </script>
    </body></html>
    """

    PAGE_ADMIN = """
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Admin Panel</title></head><body style="background:#050606;color:#e6f3e9;font-family:Arial;">
      <h1>Admin Panel</h1>
      <p><a href="{{ url_for('index') }}">Geri</a></p>
      <h2>Kullanıcılar</h2>
      <table border="1" cellpadding="6" style="background:#081018">
        <tr><th>ID</th><th>Kullanıcı</th><th>Admin</th><th>İşlem</th></tr>
        {% for u in users %}
        <tr>
          <td>{{ u['id'] }}</td>
          <td>{{ u['username'] }}</td>
          <td>{{ 'Evet' if u['is_admin'] else 'Hayır' }}</td>
          <td>
            <form method="post" action="{{ url_for('admin_do') }}">
              <input type="hidden" name="target" value="{{ u['username'] }}">
              <button name="action" value="make_admin">Admin Yap</button>
              {% if u['username'] != 'enes' %}
              <button name="action" value="remove_user">Kullanıcıyı Sil</button>
              {% endif %}
            </form>
          </td>
        </tr>
        {% endfor %}
      </table>

      <h2>Son Mesajlar</h2>
      {% for m in messages %}
        <div style="background:#061414;padding:8px;margin:8px;border-radius:6px">
          <strong>{{ m['username'] or 'Anon' }}:</strong> {{ m['content'] }} <div style="color:#bbb">Cevap: {{ m['response'] }}</div>
        </div>
      {% endfor %}

      <h2>Admin İşlemleri</h2>
      {% for a in actions %}
        <div style="background:#081918;padding:6px;margin:6px;border-radius:6px">
          <small>{{ a['created_at'] }}</small> - <strong>{{ a['action'] }}</strong> hedef: <em>{{ a['target_user'] }}</em> not: {{ a['note'] }}
        </div>
      {% endfor %}
    </body></html>
    """

    # ------------------------
    return app

# ----------------- Run if executed directly -----------------
if __name__ == "__main__":
    app = create_app()
    # app.run(host="0.0.0.0", port=5000)  # Render/Heroku kullanıyorsan WSGI ile çalışacak
    print("KralZeka v2 starting...")
    app.run(debug=True)
