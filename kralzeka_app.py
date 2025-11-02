        #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka — Tek dosya tam sürüm
- Gereken tek ortam değişkeni: GROQ_API_KEY
- MODEL_LIST içindeki modeller sırayla denenir (kod içinde sabit)
- İlk admin: enes / enes1357924680
"""

import os
import sqlite3
import uuid
import json
import traceback
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, g, render_template_string, request, redirect, url_for, session, flash,
    jsonify, send_from_directory, abort
)

# Optional imaging
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_OK = True
except Exception:
    PIL_OK = False

import requests
from bs4 import BeautifulSoup

# ------------------------
# CONFIG (kod içinde sabitler)
# ------------------------
DATABASE = os.environ.get("KZ_DB", "kralzeka.db")
UPLOAD_FOLDER = os.environ.get("KZ_UPLOAD_FOLDER", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Only this key must be in environment
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # required for model calls

# Models to try (in order). You asked "az önceki model" — include it first.
MODEL_LIST = [
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "llama-3.1-70b"
]

# Limits
USER_DAILY_IMAGE_LIMIT = 5

# App secret (you can leave this; for prod put env var)
APP_SECRET = os.environ.get("KZ_SECRET", "kralzeka_default_secret_please_change")

# Groq endpoints to attempt (tries order)
GROQ_ENDPOINTS = [
    "https://api.groq.com/openai/v1/chat/completions",
    "https://api.groq.com/v1/generate"
]

# ------------------------
# FLASK INIT
# ------------------------
app = Flask(__name__)
app.secret_key = APP_SECRET
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ------------------------
# DATABASE HELPERS
# ------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript("""
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
        username TEXT,
        content TEXT,
        response TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        kind TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        title TEXT,
        description TEXT,
        state TEXT DEFAULT 'open',
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        actor TEXT,
        target TEXT,
        meta TEXT,
        created_at TEXT
    );
    """)
    db.commit()
    # ensure 'enes' admin exists
    cur.execute("SELECT id FROM users WHERE username = ?", ("enes",))
    if not cur.fetchone():
        now = datetime.utcnow().isoformat()
        cur.execute("INSERT INTO users (username, password, is_admin, created_at) VALUES (?,?,?,?)",
                    ("enes", "enes1357924680", 1, now))
        db.commit()

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ------------------------
# AUTH HELPERS
# ------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            flash("Yönetici yetkiniz yok.")
            return redirect(url_for('index'))
        return f(*a, **kw)
    return wrapper

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def record_admin_log(action, actor, target=None, meta=None):
    db = get_db()
    db.execute("INSERT INTO admin_logs (action, actor, target, meta, created_at) VALUES (?,?,?,?,?)",
               (action, actor, target, json_safe(meta), datetime.utcnow().isoformat()))
    db.commit()

def json_safe(x):
    try:
        return json.dumps(x, ensure_ascii=False)
    except Exception:
        return str(x)

# ------------------------
# USAGE / LIMITS
# ------------------------
def usage_count_today(user_id, kind):
    dt0 = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    row = get_db().execute("SELECT COUNT(*) AS c FROM usage WHERE user_id = ? AND kind = ? AND created_at >= ?",
                           (user_id, kind, dt0)).fetchone()
    return row['c'] if row else 0

def can_use_image(user_id):
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and user['is_admin']:
        return True
    used = usage_count_today(user_id, 'image')
    return used < USER_DAILY_IMAGE_LIMIT

def record_usage(user_id, kind):
    db = get_db()
    db.execute("INSERT INTO usage (user_id, kind, created_at) VALUES (?,?,?)",
               (user_id, kind, datetime.utcnow().isoformat()))
    db.commit()

# ------------------------
# GROQ / MODEL CALL
# ------------------------
def call_groq(user_prompt, system_prompt=None):
    if not GROQ_API_KEY:
        return {"ok": False, "error": "Serverda GROQ API anahtarı yok. Admin ayarlasın."}
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    messages = []
    if system_prompt:
        messages.append({"role":"system","content":system_prompt})
    messages.append({"role":"user","content":user_prompt})

    last_err = None
    for model in MODEL_LIST:
        for url in GROQ_ENDPOINTS:
            payload = None
            if url.endswith("/chat/completions"):
                payload = {"model": model, "messages": messages, "temperature": 0.2, "max_tokens": 800}
            else:
                # generic alternative shape
                payload = {"model": model, "input": user_prompt, "temperature": 0.2}
            try:
                r = requests.post(url, headers=headers, json=payload, timeout=25)
                try:
                    data = r.json()
                except Exception:
                    data = {"raw_text": r.text}
                if r.status_code >= 200 and r.status_code < 300:
                    # try extract common patterns
                    if isinstance(data, dict):
                        # openai style
                        if 'choices' in data and len(data['choices'])>0:
                            ch = data['choices'][0]
                            if isinstance(ch, dict) and 'message' in ch and 'content' in ch['message']:
                                return {"ok": True, "text": ch['message']['content'], "raw": data, "model": model, "endpoint": url}
                            if 'text' in ch:
                                return {"ok": True, "text": ch['text'], "raw": data, "model": model, "endpoint": url}
                        # different shape
                        if 'output' in data:
                            # join outputs
                            out = data['output']
                            if isinstance(out, list):
                                return {"ok": True, "text": " ".join(map(str,out)), "raw": data, "model": model, "endpoint": url}
                            else:
                                return {"ok": True, "text": str(out), "raw": data, "model": model, "endpoint": url}
                        # direct text
                        if 'text' in data and isinstance(data['text'], str):
                            return {"ok": True, "text": data['text'], "raw": data, "model": model, "endpoint": url}
                    # fallback: return full json
                    return {"ok": True, "text": str(data)[:2000], "raw": data, "model": model, "endpoint": url}
                else:
                    last_err = f"{r.status_code} {r.text[:200]}"
            except Exception as e:
                last_err = str(e)
    return {"ok": False, "error": f"Tüm model/endpoint denemeleri başarısız. Son hata: {last_err}"}

# ------------------------
# WEB SEARCH fallback
# ------------------------
HEADERS = {"User-Agent":"Mozilla/5.0 (KralZeka/1.0)"}
def web_search_snippet(query):
    try:
        r = requests.post("https://html.duckduckgo.com/html/", data={"q": query}, headers=HEADERS, timeout=10)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        snippets = []
        for s in soup.select(".result__snippet")[:3]:
            snippets.append(s.get_text(strip=True))
        if snippets:
            return " ".join(snippets)[:800]
        # fallback: titles
        titles = [a.get_text(strip=True) for a in soup.select(".result__a")[:3]]
        return " ".join(titles)[:800] if titles else None
    except Exception:
        return None

# ------------------------
# IMAGE placeholder & quality up
# ------------------------
def generate_placeholder_image(prompt_text, out_path):
    try:
        if PIL_OK:
            img = Image.new('RGB', (800,450), color=(18,18,22))
            draw = ImageDraw.Draw(img)
            txt = "KralZeka Görsel\n" + (prompt_text[:200] + "..." if len(prompt_text)>200 else prompt_text)
            try:
                font = ImageFont.truetype("DejaVuSans.ttf", 18)
            except Exception:
                font = ImageFont.load_default()
            draw.text((12,12), txt, font=font, fill=(220,220,220))
            img.save(out_path)
            return True
        else:
            # write a small text fallback
            with open(out_path + ".txt", "w", encoding="utf-8") as f:
                f.write("KralZeka placeholder image for prompt:\n\n" + prompt_text)
            return True
    except Exception:
        return False

def upscale_image_simple(path_in, path_out):
    if not PIL_OK:
        return False
    try:
        im = Image.open(path_in)
        w,h = im.size
        im2 = im.resize((w*2, h*2), Image.LANCZOS)
        im2.save(path_out)
        return True
    except Exception:
        return False

# ------------------------
# AUTO-REPAIR mechanism
# ------------------------
def system_health_checks():
    """
    Returns list of detected issues (strings).
    Example repairs implemented:
     - missing DB tables -> recreate
     - missing upload folder -> create
    """
    issues = []
    # check DB tables exist
    db = get_db()
    try:
        cur = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cur.fetchone():
            issues.append("users table missing")
    except Exception as e:
        issues.append("DB access error: " + str(e))
    # uploads folder
    if not os.path.isdir(UPLOAD_FOLDER):
        issues.append("upload folder missing")
    # check groq key
    if not GROQ_API_KEY:
        issues.append("GROQ API key not set (GROQ_API_KEY env)")
    return issues

def perform_auto_fix(action_key):
    """
    action_key: string indicating which fix to apply; supported: 'reinit_db', 'create_upload_folder'
    requires user confirmation in frontend; admin_log recorded.
    """
    actor = session.get('username','anonymous')
    try:
        if action_key == 'reinit_db':
            with app.app_context():
                init_db()
            record_admin_log("auto_fix_reinit_db", actor, target=None, meta="reinit_db performed")
            return True, "DB yeniden başlatıldı."
        if action_key == 'create_upload_folder':
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            record_admin_log("auto_fix_create_upload_folder", actor, target=None, meta=UPLOAD_FOLDER)
            return True, "Upload klasörü oluşturuldu."
        return False, "Bilinmeyen eylem."
    except Exception as e:
        return False, str(e)

# ------------------------
# ROUTES: front & api
# ------------------------

# Basic templates (single-file) — can be edited later
LAYOUT_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>KralZeka</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
:root{--bg:#081014;--panel:#0b1b1b;--accent:#6c63ff}
body{background:linear-gradient(180deg,var(--bg),#020409);color:#e6f7f4;font-family:Inter,Arial;margin:0}
.app{display:flex;height:100vh}
.sidebar{width:260px;background:var(--panel);padding:12px;box-sizing:border-box}
.main{flex:1;padding:18px;overflow:auto}
.mod{padding:10px;border-radius:8px;margin:6px 0;cursor:pointer;color:#c9eae3}
.mod.active{background:linear-gradient(90deg,var(--accent),#4aa0ff);color:#fff}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:6px 0}
.chatbox{background:#061a18;padding:12px;border-radius:10px;height:60vh;overflow:auto}
.inputrow{display:flex;margin-top:12px;gap:8px}
.inputrow input{flex:1;padding:10px;border-radius:8px;border:none;background:#072a29;color:#e6f7f4}
.btn-accent{background:var(--accent);border:none;color:white;padding:10px 14px;border-radius:8px}
.small-muted{color:#9fbfb6;font-size:13px}
.card-slim{background:#071b19;padding:10px;border-radius:8px}
.footer-note{font-size:12px;color:#9fbfb6;margin-top:10px}
.request-list{max-height:200px;overflow:auto}
.badge-admin{background:#d4af37;color:#000;padding:4px 6px;border-radius:6px}
</style>
</head><body>
<div class="app">
  <div class="sidebar">
    <div style="font-weight:700;font-size:20px;padding:8px">KralZeka 👑</div>
    <div class="small-muted">Kullanıcı: <strong>{{ username }}</strong> {% if is_admin %}<span class="badge-admin">ADMIN</span>{% endif %}</div>
    <hr style="border-color:#072a29">
    <div style="font-weight:700;margin-top:8px">Modlar</div>
    <div id="mods">
      <div class="mod active" data-mode="chat" onclick="setMode('chat')">💬 Sohbet</div>
      <div class="mod" data-mode="odev" onclick="setMode('odev')">📘 Ödeve Yardım</div>
      <div class="mod" data-mode="espri" onclick="setMode('espri')">😂 Espri</div>
      <div class="mod" data-mode="sunum" onclick="setMode('sunum')">📊 Sunum</div>
    </div>
    <hr style="border-color:#072a29">
    <div style="margin-top:8px;font-weight:700">Hızlı</div>
    <div class="mod" onclick="document.getElementById('fileInput').click()">＋ Görsel Yükle</div>
    <div class="mod" onclick="location.href='/admin'">🛠 Admin Panel</div>
    <hr style="border-color:#072a29">
    <div style="margin-top:8px">
      <div class="small-muted">Yeni Güncelleme İstekleri</div>
      <div class="request-list card-slim" id="requestList">
        {% for req in requests %}
          <div style="padding:6px;border-bottom:1px solid #072a29">
            <strong>{{ req['title'] }}</strong><div class="small-muted">{{ req['username'] }} - {{ req['created_at'] }}</div>
          </div>
        {% endfor %}
      </div>
    </div>
    <div class="footer-note">Kayıtlı kullanıcılar talep ekleyebilir. Adminler talepleri yönetir.</div>
  </div>

  <div class="main">
    <div class="topbar">
      <div style="font-weight:600">Mod: <span id="currentModeLabel">Sohbet</span></div>
      <div>
        <span class="small-muted">Model: {{ model_in_use }}</span>
        &nbsp; | &nbsp;
        <a href="/logout" class="small-muted">Çıkış</a>
      </div>
    </div>

    <div id="contentArea">
      <!-- chat area -->
      <div class="card p-3 mb-3 chatbox" id="chatBox">
        {% for m in messages %}
          {% if m['username'] == username %}
            <div style="text-align:right"><div class="card-slim" style="display:inline-block; max-width:80%"><strong>Sen:</strong><div>{{ m['content'] }}</div></div></div>
            <div style="text-align:right;margin-top:6px"><div class="card-slim" style="display:inline-block; max-width:80%"><strong>KralZeka:</strong><div>{{ m['response'] }}</div></div></div>
          {% else %}
            <div style="text-align:left"><div class="card-slim" style="display:inline-block; max-width:80%"><strong>{{ m['username'] }}:</strong><div>{{ m['content'] }}</div></div></div>
            <div style="text-align:left;margin-top:6px"><div class="card-slim" style="display:inline-block; max-width:80%"><strong>KralZeka:</strong><div>{{ m['response'] }}</div></div></div>
          {% endif %}
        {% endfor %}
      </div>

      <div class="inputrow">
        <input id="userInput" placeholder="KralZeka'ya sor..." autocomplete="off">
        <button class="btn-accent" onclick="sendMessage()">Gönder</button>
      </div>

      <div style="margin-top:12px" id="autoFixArea">
        <!-- auto-fix notifications will appear here -->
      </div>

      <input id="fileInput" type="file" accept=".png,.jpg,.jpeg" style="display:none" onchange="uploadFile(event)">
    </div>
  </div>
</div>

<script>
let currentMode = "chat";
function setMode(m){
  currentMode = m;
  document.getElementById('currentModeLabel').innerText = {chat:'Sohbet',odev:'Ödev',espri:'Espri',sunum:'Sunum'}[m] || m;
  // Add quick notification
  fetch('/mode_switch', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({mode:m})});
}
async function sendMessage(){
  const input = document.getElementById('userInput');
  const text = input.value.trim();
  if(!text) return;
  input.value = '';
  const res = await fetch('/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message:text, mode: currentMode})});
  const j = await res.json();
  if(j.ok){
    // append response to chatBox by reloading page (simpler)
    location.reload();
  } else {
    alert("Hata: " + (j.error || "Bilinmeyen"));
  }
}

async function uploadFile(e){
  const f = e.target.files[0];
  if(!f) return;
  const fd = new FormData();
  fd.append('file', f);
  const res = await fetch('/upload', {method:'POST', body: fd});
  const j = await res.json();
  if(j.ok){
    alert('Yüklendi: ' + j.url);
    location.reload();
  } else {
    alert('Yükleme hatası: ' + (j.error || 'hata'));
  }
}

// On page load, check system health
window.addEventListener('load', async ()=>{
  const r = await fetch('/system_health');
  const data = await r.json();
  if(data.issues && data.issues.length>0){
    const area = document.getElementById('autoFixArea');
    let html = '<div class="card p-2" style="background:#2b1b1a;color:#ffd;">';
    html += '<strong>Sistem bir sorun tespit etti:</strong><ul>';
    data.issues.forEach(i => html += '<li>'+i+'</li>');
    html += '</ul>';
    html += '<div>Onay verirsen KralZeka otomatik düzeltme uygulayabilir.</div>';
    html += '<button class="btn-accent" onclick="autoFix()">Düzelt</button> ';
    html += '<button class="btn-accent" style="background:#888" onclick="dismissFix()">Kapat</button>';
    html += '</div>';
    area.innerHTML = html;
  }
});

async function autoFix(){
  const ok = confirm("KralZeka otomatik düzeltmeyi çalıştıracak. Emin misin?");
  if(!ok) return;
  const res = await fetch('/system_fix', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({action:'reinit_db'})});
  const j = await res.json();
  alert(j.msg || 'Tamamlandı');
  location.reload();
}

function dismissFix(){ document.getElementById('autoFixArea').innerHTML = ''; }
</script>

</body></html>
"""

# Route: homepage (chat UI)
@app.route('/')
@login_required
def index():
    user = current_user()
    db = get_db()
    msgs = db.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 40").fetchall()
    msgs_list = [dict(m) for m in msgs][::-1]
    requests_rows = db.execute("SELECT id, username, title, created_at FROM requests ORDER BY id DESC LIMIT 6").fetchall()
    reqs = [dict(r) for r in requests_rows]
    # get last used model if any from admin_logs
    model_in_use = None
    row = db.execute("SELECT meta FROM admin_logs WHERE action='model_set' ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        try:
            meta = json.loads(row['meta'])
            model_in_use = meta.get('model')
        except Exception:
            model_in_use = row['meta']
    if not model_in_use:
        model_in_use = MODEL_LIST[0]
    return render_template_string(LAYOUT_HTML, username=user['username'], is_admin=bool(user['is_admin']),
                                  messages=msgs_list, requests=reqs, model_in_use=model_in_use)

# Route: chat api (AJAX)
@app.route('/chat', methods=['POST'])
@login_required
def chat_api():
    data = request.get_json() or {}
    msg = data.get('message','').strip()
    mode = data.get('mode','chat')
    if not msg:
        return jsonify({"ok":False, "error":"Mesaj boş"}), 400
    user = current_user()
    # check image/chat limits handled differently; here just check chat (no limit)
    # Build system prompt by mode
    if mode == 'odev':
        system = "Ödev yardım modu: Öğretici, açık adım adım çözüm ver. Türkçe."
    elif mode == 'espri':
        system = "Espri modu: Kısa, eğlenceli, uygunsuz olmayan şakalar üret."
    elif mode == 'sunum':
        system = "Sunum modu: Akıcı başlıklar ve kısa madde notları üret."
    else:
        system = "Genel yardım modu: Kısa ve faydalı cevap ver."
    # Call Groq
    res = call_groq(msg, system_prompt=system)
    if res.get('ok'):
        reply = res.get('text') or ""
    else:
        # fallback: try web search snippet
        snippet = web_search_snippet(msg)
        if snippet:
            reply = "Web sonuçlarından özet: " + snippet
        else:
            reply = "Üzgünüm, şu an modelden yanıt alınamadı: " + (res.get('error') or 'Bilinmeyen hata')
    # store
    db = get_db()
    db.execute("INSERT INTO messages (user_id, username, content, response, created_at) VALUES (?,?,?,?,?)",
               (user['id'], user['username'], msg, reply, datetime.utcnow().isoformat()))
    db.commit()
    # return
    return jsonify({"ok":True, "reply": reply})

# Upload endpoint
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return jsonify({"ok":False, "error":"Dosya yok"}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({"ok":False, "error":"Geçersiz dosya"}), 400
    fname = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    try:
        f.save(path)
        db = get_db()
        db.execute("INSERT INTO images (user_id, filename, created_at) VALUES (?,?,?)",
                   (session['user_id'], fname, datetime.utcnow().isoformat()))
        db.commit()
        return jsonify({"ok":True, "url": url_for('uploaded_file', filename=fname)})
    except Exception as e:
        return jsonify({"ok":False, "error": str(e)}), 500

# Serve uploaded files
from werkzeug.utils import secure_filename
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# generate image (placeholder)
@app.route('/generate-image', methods=['POST'])
@login_required
def generate_image():
    data = request.get_json() or {}
    prompt = data.get('prompt','').strip()
    if not prompt:
        return jsonify({"ok":False, "error":"Prompt yok"}), 400
    user = current_user()
    if not can_use_image(user['id']):
        return jsonify({"ok":False, "error":"Günlük görsel limitin doldu"}), 403
    fname = f"{uuid.uuid4().hex}.png"
    out = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    ok = generate_placeholder_image(prompt, out)
    if ok:
        db = get_db()
        db.execute("INSERT INTO images (user_id, filename, created_at) VALUES (?,?,?)",
                   (user['id'], fname, datetime.utcnow().isoformat()))
        db.commit()
        record_usage(user['id'], 'image')
        return jsonify({"ok":True, "url": url_for('uploaded_file', filename=fname)})
    else:
        return jsonify({"ok":False, "error":"Görsel üretilemedi"}), 500

# quality up endpoint (simple upscale)
@app.route('/quality-up', methods=['POST'])
@login_required
def quality_up():
    data = request.get_json() or {}
    filename = data.get('filename')
    if not filename:
        return jsonify({"ok":False, "error":"filename required"}), 400
    src = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(src):
        return jsonify({"ok":False, "error":"file not found"}), 404
    user = current_user()
    if not can_use_image(user['id']):
        return jsonify({"ok":False, "error":"Günlük kalite hakkın doldu"}), 403
    outname = f"q_{uuid.uuid4().hex}_{filename}"
    out = os.path.join(app.config['UPLOAD_FOLDER'], outname)
    ok = upscale_image_simple(src, out)
    if ok:
        db = get_db()
        db.execute("INSERT INTO images (user_id, filename, created_at) VALUES (?,?,?)",
                   (user['id'], outname, datetime.utcnow().isoformat()))
        db.commit()
        record_usage(user['id'], 'image')
        return jsonify({"ok":True, "url": url_for('uploaded_file', filename=outname)})
    else:
        return jsonify({"ok":False, "error":"Upscale başarısız"}), 500

# requests (feature requests) endpoints
@app.route('/request', methods=['POST'])
@login_required
def request_feature():
    data = request.form or request.get_json() or {}
    title = data.get('title') or request.form.get('title')
    desc = data.get('description') or request.form.get('description')
    if not title:
        return jsonify({"ok":False, "error":"title required"}), 400
    user = current_user()
    db = get_db()
    db.execute("INSERT INTO requests (user_id, username, title, description, created_at) VALUES (?,?,?,?,?)",
               (user['id'], user['username'], title, desc or '', datetime.utcnow().isoformat()))
    db.commit()
    return jsonify({"ok":True})

# admin panel
ADMIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Admin - KralZeka</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:#010d0b;color:#dff7f1;font-family:Inter,Arial;padding:20px}</style></head>
<body>
<div class="container">
<h2>Admin Panel</h2>
<p><a href="/">Geri</a></p>

<h4>Kullanıcılar</h4>
<table class="table table-dark table-striped">
<thead><tr><th>#</th><th>username</th><th>admin</th><th>created</th><th>işlemler</th></tr></thead><tbody>
{% for u in users %}
<tr>
<td>{{u['id']}}</td><td>{{u['username']}}</td><td>{{u['is_admin']}}</td><td>{{u['created_at']}}</td>
<td>
{% if u['username']!='enes' %}
<a href="/admin/toggle_admin/{{u['id']}}" class="btn btn-sm btn-warning">Toggle Admin</a>
<a href="/admin/delete/{{u['id']}}" class="btn btn-sm btn-danger">Sil</a>
{% else %}
<span class="text-warning">Korunan admin</span>
{% endif %}
</td></tr>
{% endfor %}
</tbody></table>

<h4>Güncelleme Talepleri</h4>
{% for r in requests %}
<div style="background:#052a28;padding:10px;margin-bottom:8px;border-radius:6px">
  <b>{{r['title']}}</b> — <small>{{r['username']}}</small><br>
  <div style="margin-top:6px">{{r['description']}}</div>
  <div style="margin-top:6px"><a href="/admin/request_resolve/{{r['id']}}" class="btn btn-sm btn-success">Tamamlandı</a>
  <a href="/admin/request_delete/{{r['id']}}" class="btn btn-sm btn-danger">Sil</a></div>
</div>
{% endfor %}

<h4>Admin Logs</h4>
{% for l in logs %}
<div style="background:#071a19;padding:8px;margin-bottom:6px;border-radius:6px">
  <div><small>{{l['created_at']}}</small> — <b>{{l['actor']}}</b> : {{l['action']}}</div>
  <div style="opacity:0.8">{{l['meta']}}</div>
</div>
{% endfor %}

</div>
</body></html>
"""

@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    users = [dict(r) for r in db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()]
    requests_rows = [dict(r) for r in db.execute("SELECT * FROM requests ORDER BY id DESC").fetchall()]
    logs = [dict(r) for r in db.execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 200").fetchall()]
    return render_template_string(ADMIN_PAGE, users=users, requests=requests_rows, logs=logs)

@app.route('/admin/toggle_admin/<int:uid>')
@admin_required
def admin_toggle(uid):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not user:
        flash("Kullanıcı bulunamadı")
        return redirect(url_for('admin_panel'))
    if user['username'] == 'enes':
        flash("Enes admini değiştirilemez")
        return redirect(url_for('admin_panel'))
    new = 0 if user['is_admin'] else 1
    db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new, uid))
    db.commit()
    record_admin_log("toggle_admin", session.get('username'), user['username'], meta={"new":new})
    flash("Güncellendi")
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete/<int:uid>')
@admin_required
def admin_delete(uid):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not user:
        flash("Kullanıcı yok")
        return redirect(url_for('admin_panel'))
    if user['username'] == 'enes':
        record_admin_log("attempt_delete_enes", session.get('username'), "enes", meta={})
        flash("Enes silinemez")
        return redirect(url_for('admin_panel'))
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    record_admin_log("delete_user", session.get('username'), user['username'], meta={})
    flash("Silindi")
    return redirect(url_for('admin_panel'))

@app.route('/admin/request_resolve/<int:rid>')
@admin_required
def admin_request_resolve(rid):
    db = get_db()
    db.execute("UPDATE requests SET state = 'done' WHERE id = ?", (rid,))
    db.commit()
    flash("İşaretlendi")
    return redirect(url_for('admin_panel'))

@app.route('/admin/request_delete/<int:rid>')
@admin_required
def admin_request_delete(rid):
    db = get_db()
    db.execute("DELETE FROM requests WHERE id = ?", (rid,))
    db.commit()
    flash("Silindi")
    return redirect(url_for('admin_panel'))

# system health endpoints
@app.route('/system_health')
@login_required
def system_health():
    issues = system_health_checks()
    return jsonify({"issues": issues})

@app.route('/system_fix', methods=['POST'])
@login_required
def system_fix():
    data = request.get_json() or {}
    action = data.get('action','reinit_db')
    # Ask for confirmation from user in frontend; here assume user confirmed
    ok, msg = perform_auto_fix(action)
    return jsonify({"ok": ok, "msg": msg})

# login/register/logout
LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Giriş</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body style="background:#010d0b;color:#dff7f1;padding:40px;font-family:Inter,Arial">
<div style="max-width:420px;margin:auto">
<h3>KralZeka Giriş</h3>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <div class="alert alert-warning">{{ messages[0] }}</div>
  {% endif %}
{% endwith %}
<form method="post" action="/login">
<input name="username" class="form-control" placeholder="Kullanıcı"><br>
<input name="password" type="password" class="form-control" placeholder="Şifre"><br>
<button class="btn btn-primary">Giriş</button>
<a href="/register" class="btn btn-secondary">Kayıt ol</a>
</form>
</div></body></html>
"""

REGISTER_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Kayıt</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body style="background:#010d0b;color:#dff7f1;padding:40px;font-family:Inter,Arial">
<div style="max-width:420px;margin:auto">
<h3>Kayıt ol</h3>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <div class="alert alert-warning">{{ messages[0] }}</div>
  {% endif %}
{% endwith %}
<form method="post" action="/register">
<input name="username" class="form-control" placeholder="Kullanıcı"><br>
<input name="password" type="password" class="form-control" placeholder="Şifre"><br>
<input name="password2" type="password" class="form-control" placeholder="Şifre tekrar"><br>
<button class="btn btn-success">Kayıt</button>
</form>
</div></body></html>
"""

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE)
    u = request.form.get('username','').strip()
    p = request.form.get('password','')
    row = get_db().execute("SELECT * FROM users WHERE username = ? AND password = ?", (u,p)).fetchone()
    if not row:
        flash("Kullanıcı veya şifre hatalı")
        return redirect(url_for('login'))
    session['user_id'] = row['id']
    session['username'] = row['username']
    flash("Giriş başarılı")
    return redirect(url_for('index'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template_string(REGISTER_PAGE)
    u = request.form.get('username','').strip()
    p = request.form.get('password','')
    p2 = request.form.get('password2','')
    if p != p2:
        flash("Şifreler eşleşmiyor")
        return redirect(url_for('register'))
    try:
        db = get_db()
        db.execute("INSERT INTO users (username, password, is_admin, created_at) VALUES (?,?,?,?)",
                   (u,p,0, datetime.utcnow().isoformat()))
        db.commit()
        flash("Kayıt başarılı. Giriş yapabilirsiniz.")
        return redirect(url_for('login'))
    except Exception as e:
        flash("Kayıt hatası: " + str(e))
        return redirect(url_for('register'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Çıkış yapıldı")
    return redirect(url_for('login'))

# safe run
if __name__ == '__main__':
    with app.app_context():
        try:
            init_db()
        except Exception:
            traceback.print_exc()
    # For testing / small deploys
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
