#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 — Tam sürüm (tek dosya)
- Düzgün çalışan kayıt/giriş/session (düzeltilmiş)
- SQLite (SQLAlchemy)
- Admin koruması (ilk admin: enes / enes1357924680)
- Groq (öncelik) + Hugging Face (yedek) entegrasyonu (ENV anahtarları)
- Görsel üretme + kalite yükseltme
- Sunum oluşturma + indir
- Admin paneli: kullanıcı yönetimi, loglar, feature istekleri, admin-only kod üretme (üretim: çalıştırma yok)
- Hata handler'ları ve logging
"""

import os
import json
import uuid
import logging
import base64
from io import BytesIO
from datetime import datetime
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash,
    g, jsonify, send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from PIL import Image

# ---------------- Config ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FILE = os.environ.get("KRALZEKA_DB", os.path.join(BASE_DIR, "kralzeka.db"))

HF_API_KEY = os.environ.get("HF_API_KEY", "").strip()
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY") or str(uuid.uuid4())

DEFAULT_GROQ_MODEL = "llama-3.1-70b"
DEFAULT_HF_TEXT_MODEL = "meta-llama/Llama-2-7b-chat-hf"
DEFAULT_HF_IMAGE_MODEL = "stabilityai/stable-diffusion-xl"

IMAGE_DAILY_LIMIT = 5
ADMIN_USERNAME = "enes"
ADMIN_PASSWORD = "enes1357924680"

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kralzeka")

# ---------------- App & DB ----------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_FILE}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ---------------- Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    sender = db.Column(db.String(80))  # username or "KralZeka" etc.
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20))
    message = db.Column(db.Text)
    meta = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ImageUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    usage_date = db.Column(db.String(20))  # YYYY-MM-DD
    count = db.Column(db.Integer, default=0)

class FeatureRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    text = db.Column(db.Text)
    tag = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- DB Init ----------------
with app.app_context():
    db.create_all()
    # Ensure initial admin exists and is protected
    admin = User.query.filter_by(username=ADMIN_USERNAME).first()
    if not admin:
        try:
            admin = User(
                username=ADMIN_USERNAME,
                password_hash=generate_password_hash(ADMIN_PASSWORD),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            logger.info("İlk admin oluşturuldu: %s", ADMIN_USERNAME)
        except Exception:
            logger.exception("İlk admin oluştururken hata")

# ---------------- Helpers ----------------
def add_log(level: str, message: str, meta: Optional[dict] = None):
    try:
        l = Log(level=level, message=message, meta=json.dumps(meta or {}))
        db.session.add(l)
        db.session.commit()
    except Exception:
        logger.exception("log eklenirken hata")

def get_user_by_username(username: str) -> Optional[User]:
    return User.query.filter_by(username=username).first()

def require_login(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Lütfen giriş yapın.", "warning")
            return redirect(url_for("login", next=request.path))
        user = User.query.get(session["user_id"])
        if not user:
            session.clear()
            flash("Oturum hatası. Tekrar giriş yapın.", "warning")
            return redirect(url_for("login"))
        g.user = user
        return fn(*args, **kwargs)
    return wrapper

def require_admin(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Lütfen giriş yapın.", "warning")
            return redirect(url_for("login", next=request.path))
        user = User.query.get(session["user_id"])
        if not user or not user.is_admin:
            return render_template("403.html"), 403
        g.user = user
        return fn(*args, **kwargs)
    return wrapper

def protect_admin_action(target_username: str, acting_admin: str) -> bool:
    if target_username == ADMIN_USERNAME:
        add_log("WARN", f"Admin değişikliği denemesi: {acting_admin} -> {target_username}", {"actor": acting_admin})
        return False
    return True

def today_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d")

# ---------------- AI Backends ----------------
def call_groq_chat(prompt: str, model=DEFAULT_GROQ_MODEL) -> str:
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ key yok")
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 1024}
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    r.raise_for_status()
    resp = r.json()
    if "choices" in resp and resp["choices"]:
        return resp["choices"][0].get("message", {}).get("content") or resp["choices"][0].get("text") or ""
    return json.dumps(resp)

def call_hf_text(prompt: str, model: str = DEFAULT_HF_TEXT_MODEL) -> str:
    if not HF_API_KEY:
        raise RuntimeError("HF key yok")
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    resp = r.json()
    if isinstance(resp, list) and resp and isinstance(resp[0], dict) and "generated_text" in resp[0]:
        return resp[0]["generated_text"]
    if isinstance(resp, str):
        return resp
    return json.dumps(resp)

def ai_chat(prompt: str) -> str:
    try:
        # Groq first, fallback to HF
        if GROQ_API_KEY:
            try:
                out = call_groq_chat(prompt)
                if out:
                    return out
            except Exception as e:
                logger.warning("Groq başarısız: %s", e)
                add_log("WARN", f"Groq başarısız: {e}", {"prompt": prompt})
        if HF_API_KEY:
            try:
                return call_hf_text(prompt)
            except Exception as e:
                logger.warning("HF text başarısız: %s", e)
                add_log("WARN", f"HF text başarısız: {e}", {"prompt": prompt})
        return "Üzgünüm, şu an bir AI modeliyle iletişim kurulamadı."
    except Exception as e:
        logger.exception("ai_chat hata")
        return f"Hata: {e}"

# ---------------- Image (HF primary) ----------------
def generate_image_hf(prompt: str, model: str = DEFAULT_HF_IMAGE_MODEL, size: str = "1024x1024") -> bytes:
    if not HF_API_KEY:
        raise RuntimeError("HF key yok")
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    r = requests.post(url, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    content_type = r.headers.get("Content-Type", "")
    if "application/json" in content_type:
        data = r.json()
        # common HF image responses may vary
        if isinstance(data, dict) and "image_base64" in data:
            return base64.b64decode(data["image_base64"])
        if isinstance(data, list) and data and isinstance(data[0], dict):
            for key in ("generated_image", "image_base64", "b64_json"):
                if key in data[0]:
                    return base64.b64decode(data[0][key])
        # unexpected JSON
        raise RuntimeError("HF image API beklenmeyen JSON döndürdü")
    else:
        return r.content

# ---------------- Image usage helpers ----------------
def image_usage_for_today(user_id: int) -> int:
    rec = ImageUsage.query.filter_by(user_id=user_id, usage_date=today_str()).first()
    return rec.count if rec else 0

def increment_image_usage(user_id: int, amount: int = 1):
    rec = ImageUsage.query.filter_by(user_id=user_id, usage_date=today_str()).first()
    if rec:
        rec.count += amount
    else:
        rec = ImageUsage(user_id=user_id, usage_date=today_str(), count=amount)
        db.session.add(rec)
    db.session.commit()

# ---------------- Routes ----------------
@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = User.query.get(session["user_id"])
    messages = Message.query.order_by(Message.created_at.desc()).limit(20).all()
    return render_template("index.html", user=user, messages=messages, image_limit=IMAGE_DAILY_LIMIT)

# ---- Register ----
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if not username or not password:
            flash("Kullanıcı adı ve parola gerekli.", "danger")
            return redirect(url_for("register"))
        if password != password2:
            flash("Parolalar eşleşmiyor.", "warning")
            return redirect(url_for("register"))
        if get_user_by_username(username):
            flash("Bu kullanıcı adı zaten alınmış.", "warning")
            return redirect(url_for("register"))
        try:
            user = User(username=username, password_hash=generate_password_hash(password), is_admin=False)
            db.session.add(user)
            db.session.commit()
            add_log("INFO", f"Kayıt: {username}")
            flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            logger.exception("kayıt hatası")
            flash("Kayıt sırasında hata oluştu.", "danger")
            return redirect(url_for("register"))
    return render_template("register.html")

# ---- Login ----
@app.route("/login", methods=["GET", "POST"])
def login():
    # If already logged in, go to index
    if "user_id" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = get_user_by_username(username)
        if user and user.check_password(password):
            # Save session securely
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["is_admin"] = bool(user.is_admin)
            add_log("INFO", f"Giriş: {username}")
            flash("Giriş başarılı.", "success")
            next_page = request.args.get("next") or url_for("index")
            return redirect(next_page)
        else:
            flash("Kullanıcı adı veya parola hatalı.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

# ---- Logout ----
@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("login"))

# ---- Chat (post) ----
@app.route("/chat", methods=["POST"])
@require_login
def chat():
    prompt = (request.form.get("prompt") or "").strip()
    if not prompt:
        flash("Lütfen bir soru yazın.", "warning")
        return redirect(url_for("index"))
    try:
        m = Message(user_id=g.user.id, sender=g.user.username, content=prompt)
        db.session.add(m)
        db.session.commit()
    except Exception:
        logger.exception("message store hata")
    try:
        resp = ai_chat(prompt)
    except Exception as e:
        resp = f"KralZeka hata: {e}"
    try:
        mr = Message(user_id=g.user.id, sender="KralZeka", content=resp)
        db.session.add(mr)
        db.session.commit()
    except Exception:
        logger.exception("assistant message store hata")
    return redirect(url_for("index"))

# ---- Feature request ----
@app.route("/feature_request", methods=["POST"])
@require_login
def feature_request():
    text = (request.form.get("request_text") or "").strip()
    tag = (request.form.get("tag") or "").strip()
    if not text:
        flash("İstek boş olamaz.", "warning")
        return redirect(url_for("index"))
    try:
        fr = FeatureRequest(user_id=g.user.id, text=text, tag=tag)
        db.session.add(fr)
        db.session.commit()
        add_log("FEATURE", f"{g.user.username} -> {text}", {"tag": tag})
        flash("İstek gönderildi.", "success")
    except Exception:
        logger.exception("feature kaydetme hata")
        flash("İstek gönderilirken hata oluştu.", "danger")
    return redirect(url_for("index"))

# ---------------- Admin ----------------
@app.route("/admin")
@require_admin
def admin_panel():
    users = User.query.order_by(User.created_at.desc()).all()
    logs = Log.query.order_by(Log.created_at.desc()).limit(200).all()
    requests_ = FeatureRequest.query.order_by(FeatureRequest.created_at.desc()).limit(200).all()
    return render_template("admin.html", users=users, logs=logs, requests=requests_, admin_username=ADMIN_USERNAME, user=g.user)

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
@require_admin
def admin_make_admin(user_id):
    target = User.query.get(user_id)
    if not target:
        flash("Kullanıcı bulunamadı.", "danger")
        return redirect(url_for("admin_panel"))
    if not protect_admin_action(target.username, g.user.username):
        flash("Bu işlemi yapamazsınız (korunuyor).", "danger")
        return redirect(url_for("admin_panel"))
    target.is_admin = True
    db.session.commit()
    add_log("ADMIN", f"{g.user.username} -> {target.username} admin yapıldı")
    flash("Admin yapıldı.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/revoke_admin/<int:user_id>", methods=["POST"])
@require_admin
def admin_revoke_admin(user_id):
    target = User.query.get(user_id)
    if not target:
        flash("Kullanıcı bulunamadı.", "danger")
        return redirect(url_for("admin_panel"))
    if not protect_admin_action(target.username, g.user.username):
        flash("Bu işlemi yapamazsınız (korunuyor).", "danger")
        return redirect(url_for("admin_panel"))
    target.is_admin = False
    db.session.commit()
    add_log("ADMIN", f"{g.user.username} -> {target.username} adminlığı kaldırdı")
    flash("Admin yetkisi kaldırıldı.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@require_admin
def admin_delete_user(user_id):
    target = User.query.get(user_id)
    if not target:
        flash("Kullanıcı bulunamadı.", "danger")
        return redirect(url_for("admin_panel"))
    if not protect_admin_action(target.username, g.user.username):
        flash("Bu kullanıcı silinemez (korunuyor).", "danger")
        return redirect(url_for("admin_panel"))
    try:
        db.session.delete(target)
        db.session.commit()
        add_log("ADMIN", f"{g.user.username} -> {target.username} silindi")
        flash("Kullanıcı silindi.", "success")
    except Exception:
        logger.exception("kullanıcı silme hata")
        flash("Silme sırasında hata.", "danger")
    return redirect(url_for("admin_panel"))

@app.route("/admin/code_tool", methods=["POST"])
@require_admin
def admin_code_tool():
    prompt = (request.form.get("prompt") or "").strip()
    if not prompt:
        flash("Boş istek gönderilemez.", "warning")
        return redirect(url_for("admin_panel"))
    try:
        resp = ai_chat(f"Admin kod üretici: {prompt}")
        add_log("CODE", resp, {"admin": g.user.username, "prompt": prompt})
        flash("Kod üretildi ve loglandı (çalıştırma yapılmadı).", "success")
    except Exception as e:
        logger.exception("code_tool hata")
        flash(f"Hata: {e}", "danger")
    return redirect(url_for("admin_panel"))

# ---------------- Image APIs ----------------
@app.route("/api/generate_image", methods=["POST"])
@require_login
def api_generate_image():
    data = request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    size = data.get("size") or "1024x1024"
    if not prompt:
        return jsonify({"error": "prompt gerekli"}), 400
    user = g.user
    if not user.is_admin:
        if image_usage_for_today(user.id) >= IMAGE_DAILY_LIMIT:
            return jsonify({"error": f"Günlük limit aşıldı ({IMAGE_DAILY_LIMIT})"}), 403
    try:
        image_bytes = None
        # Prefer HF image
        if HF_API_KEY:
            try:
                image_bytes = generate_image_hf(prompt, DEFAULT_HF_IMAGE_MODEL, size)
            except Exception as e:
                logger.warning("HF image hata: %s", e)
                add_log("WARN", f"HF image hata: {e}", {"prompt": prompt})
        # fallback Groq for image if needed
        if not image_bytes and GROQ_API_KEY:
            try:
                headers = {"Authorization": f"Bearer {GROQ_API_KEY}"}
                groq_url = "https://api.groq.com/v1/images/generations"
                payload = {"prompt": prompt, "size": size}
                r = requests.post(groq_url, json=payload, headers=headers, timeout=60)
                r.raise_for_status()
                jr = r.json()
                if isinstance(jr, dict) and "data" in jr and jr["data"]:
                    b64 = jr["data"][0].get("b64_json")
                    if b64:
                        image_bytes = base64.b64decode(b64)
            except Exception as e:
                logger.warning("GROQ image hata: %s", e)
                add_log("WARN", f"GROQ image hata: {e}", {"prompt": prompt})
        if not image_bytes:
            return jsonify({"error": "Hiçbir görsel servisine ulaşılamıyor."}), 500
        if not user.is_admin:
            increment_image_usage(user.id, 1)
        b64 = base64.b64encode(image_bytes).decode("utf-8")
        preview = f"data:image/png;base64,{b64[:200]}..."
        db.session.add(Message(user_id=user.id, sender="KralZeka (görsel)", content=preview))
        db.session.commit()
        return jsonify({"image_base64": b64}), 200
    except Exception as e:
        logger.exception("generate_image hata")
        return jsonify({"error": str(e)}), 500

@app.route("/api/upgrade_image", methods=["POST"])
@require_login
def api_upgrade_image():
    if "image" not in request.files:
        return jsonify({"error": "image file gerekli"}), 400
    file = request.files["image"]
    level = int(request.form.get("level") or 2)
    try:
        img = Image.open(file.stream).convert("RGBA")
        factor = max(1, min(level, 4))
        new_size = (img.width * factor, img.height * factor)
        up = img.resize(new_size, Image.LANCZOS)
        buf = BytesIO()
        up.save(buf, format="PNG")
        buf.seek(0)
        data = buf.read()
        b64 = base64.b64encode(data).decode("utf-8")
        preview = f"data:image/png;base64,{b64[:200]}..."
        db.session.add(Message(user_id=g.user.id, sender="KralZeka (yükseltme)", content=preview))
        db.session.commit()
        return jsonify({"image_base64": b64}), 200
    except Exception as e:
        logger.exception("upgrade image hata")
        return jsonify({"error": str(e)}), 500

# ---------------- Sunum ----------------
@app.route("/sunum", methods=["GET"])
@require_login
def sunum_page():
    return render_template("sunum.html")

@app.route("/sunum_olustur", methods=["POST"])
@require_login
def sunum_olustur():
    konu = (request.form.get("konu") or "").strip()
    if not konu:
        flash("Konu gerekli.", "warning")
        return redirect(url_for("sunum_page"))
    try:
        prompt = f"Sunum taslağı hazırla: {konu}. Madde madde başlıklar ve kısa açıklama ver."
        text = ai_chat(prompt)
    except Exception as e:
        logger.exception("sunum hata")
        text = f"Hata: {e}"
    return render_template("sunum.html", sunum=text)

@app.route("/sunum_indir", methods=["POST"])
@require_login
def sunum_indir():
    content = request.form.get("icerik") or ""
    if not content:
        return "İndirilecek içerik yok", 400
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        import textwrap
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        lines = textwrap.wrap(content, 90)
        y = height - 50
        for line in lines:
            if y < 50:
                p.showPage()
                y = height - 50
            p.drawString(50, y, line)
            y -= 14
        p.save()
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name="sunum.pdf", mimetype="application/pdf")
    except Exception:
        return (content, 200, {"Content-Type": "text/plain; charset=utf-8", "Content-Disposition": "attachment; filename=sunum.txt"})

# --------------- Error handlers ---------------
@app.errorhandler(500)
def err_500(e):
    add_log("ERROR", str(e), {"path": request.path})
    try:
        return render_template("500.html"), 500
    except Exception:
        return "Sunucu hatası (500)", 500

@app.errorhandler(404)
def err_404(e):
    try:
        return render_template("404.html"), 404
    except Exception:
        return "Sayfa bulunamadı (404)", 404

@app.errorhandler(403)
def err_403(e):
    try:
        return render_template("403.html"), 403
    except Exception:
        return "Erişim yasak (403)", 403

@app.errorhandler(401)
def err_401(e):
    try:
        return render_template("401.html"), 401
    except Exception:
        return "Yetkisiz (401)", 401

# --------------- Start ---------------
def start_app():
    with app.app_context():
        db.create_all()
    logger.info("KralZeka v1 başlatılıyor...")
    # In production use gunicorn
    if os.environ.get("FLASK_RUN_LOCAL", "").lower() in ("1", "true"):
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

if __name__ == "__main__":
    start_app()
