#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka — Login-odaklı sağlam sürüm (tek dosya)
Özellikle "giriş yapılıyor ama oturum açılmıyor" sorununu çözecek şekilde yapılandırıldı.
Start: gunicorn kralzeka_login_fixed:app
Env:
  - FLASK_SECRET_KEY  (önerilir)
  - HF_API_KEY (opsiyonel)
  - GROQ_API_KEY (opsiyonel)
"""
import os
import sys
import logging
from datetime import timedelta, datetime
from io import BytesIO
import base64
import json

from flask import (
    Flask, render_template, render_template_string, request, redirect, url_for, flash,
    session, g, jsonify, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

# ------------- CONFIG & LOGGING -------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kralzeka-login-fixed")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FILE = os.environ.get("KRALZEKA_DB", os.path.join(BASE_DIR, "kralzeka_login.db"))
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY") or "kralzeka_dev_fallback_secret_change_me"

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_FILE}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session cookie settings to reduce common login problems
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_COOKIE_HTTPONLY"] = True
# In production (https) set to True. For local/dev set to False if not using HTTPS.
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ------------- DB & LOGIN -------------
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ------------- Models -------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

# For quick debug visibility of login attempts & sessions
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(30))
    message = db.Column(db.Text)
    meta = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def add_log(level: str, message: str, meta: dict = None):
    try:
        l = Log(level=level, message=message, meta=json.dumps(meta or {}))
        db.session.add(l)
        db.session.commit()
    except Exception:
        logger.exception("log ekleme sırasında hata")

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

# ------------- Ensure DB & initial admin -------------
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username="enes").first()
    if not admin:
        try:
            admin = User(username="enes", password_hash=generate_password_hash("enes1357924680"), is_admin=True)
            db.session.add(admin)
            db.session.commit()
            logger.info("İlk admin (enes) oluşturuldu")
        except Exception:
            logger.exception("İlk admin eklenirken hata")

# ------------- Templates fallback (if missing) -------------
# If templates are missing, these inline minimal templates will prevent TemplateNotFound errors.
INDEX_FALLBACK = """
<!doctype html><title>KralZeka</title>
<h2>KralZeka — Ana Sayfa</h2>
{% if current_user.is_authenticated %}
  Hoş geldin {{ current_user.username }} | <a href="{{ url_for('logout') }}">Çıkış</a>
  <form method="post" action="{{ url_for('chat') }}">
    <input name="prompt" placeholder="Soru...">
    <button>Gönder</button>
  </form>
{% else %}
  <a href="{{ url_for('login') }}">Giriş</a> | <a href="{{ url_for('register') }}">Kayıt</a>
{% endif %}
<hr>
<h3>Son mesajlar (kısım test)</h3>
"""

LOGIN_FALLBACK = """
<!doctype html><title>Giriş</title>
<h2>Giriş</h2>
<form method="post">
  <label>Kullanıcı</label><input name="username" required><br>
  <label>Parola</label><input name="password" type="password" required><br>
  <button type="submit">Giriş</button>
</form>
<p><a href="{{ url_for('register') }}">Kayıt ol</a></p>
"""

REGISTER_FALLBACK = """
<!doctype html><title>Kayıt</title>
<h2>Kayıt</h2>
<form method="post">
  <label>Kullanıcı</label><input name="username" required><br>
  <label>Parola</label><input name="password" type="password" required><br>
  <label>Parola tekrar</label><input name="password2" type="password" required><br>
  <button type="submit">Kayıt ol</button>
</form>
"""

# ------------- Routes -------------
@app.route("/")
def index():
    # If templates exist in templates/index.html they will be used,
    # otherwise fallback prevents crash and allows testing.
    try:
        return render_template("index.html")
    except Exception:
        return render_template_string(INDEX_FALLBACK)

@app.route("/register", methods=["GET", "POST"])
def register():
    # Primary reasons registration might "seem" to fail:
    # - form field names mismatch (we require 'username','password','password2')
    # - DB integrity error (duplicate username)
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        logger.info("Kayıt denemesi: username='%s'", username)
        add_log("INFO", "register_attempt", {"username": username})

        if not username or not password:
            flash("Kullanıcı adı ve parola gerekli.", "danger")
            return redirect(url_for("register"))

        if password != password2:
            flash("Parolalar eşleşmiyor.", "warning")
            return redirect(url_for("register"))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Bu kullanıcı adı zaten var.", "warning")
            return redirect(url_for("register"))

        try:
            u = User(username=username, password_hash=generate_password_hash(password))
            db.session.add(u)
            db.session.commit()
            add_log("INFO", "register_success", {"username": username})
            flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            logger.exception("Kayıt ekleme hatası")
            add_log("ERROR", "register_db_error", {"username": username, "error": str(e)})
            flash("Kayıt sırasında hata oluştu.", "danger")
            return redirect(url_for("register"))

    try:
        return render_template("register.html")
    except Exception:
        return render_template_string(REGISTER_FALLBACK)

@app.route("/login", methods=["GET", "POST"])
def login():
    # If already authenticated, redirect to index
    if current_user.is_authenticated:
        flash("Zaten giriş yapmışsınız.", "info")
        return redirect(url_for("index"))

    # Important: form must use POST and fields 'username' and 'password'
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        logger.info("Login attempt for username='%s'", username)
        add_log("INFO", "login_attempt", {"username": username})
        # quick sanity checks to log reasons
        if not username or not password:
            flash("Kullanıcı adı ve parola girin.", "warning")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        if not user:
            logger.info("Login failed: user not found (%s)", username)
            add_log("WARN", "login_failed_no_user", {"username": username})
            flash("Kullanıcı bulunamadı.", "danger")
            return redirect(url_for("login"))

        if not user.check_password(password):
            logger.info("Login failed: wrong password (%s)", username)
            add_log("WARN", "login_failed_wrong_password", {"username": username})
            flash("Parola hatalı.", "danger")
            return redirect(url_for("login"))

        # All good: login_user from Flask-Login
        login_user(user, remember=True)
        # also mark session permanent for lifespan config
        session.permanent = True
        logger.info("Login successful: %s (id=%s)", user.username, user.id)
        add_log("INFO", "login_success", {"username": username, "user_id": user.id})
        next_url = request.args.get("next")
        return redirect(next_url or url_for("index"))

    try:
        return render_template("login.html")
    except Exception:
        return render_template_string(LOGIN_FALLBACK)

@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    session.clear()
    add_log("INFO", "logout", {"username": username})
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("login"))

# Small chat endpoint for testing login-locked access
@app.route("/chat", methods=["POST"])
@login_required
def chat():
    prompt = (request.form.get("prompt") or "").strip()
    if not prompt:
        flash("Soru yaz.", "warning")
        return redirect(url_for("index"))
    # store message or respond dummy
    add_log("CHAT", "user_prompt", {"username": current_user.username, "prompt": prompt})
    # quick dummy reply (replace with ai_chat call)
    flash("KralZeka (örnek cevap): " + prompt[::-1], "info")
    return redirect(url_for("index"))

# Route to print server-side session info for debugging (admin-only in prod, here accessible for testing)
@app.route("/_session_debug")
def session_debug():
    info = {
        "session_keys": list(session.keys()),
        "session_data": {k: session.get(k) for k in session.keys()},
        "is_authenticated": current_user.is_authenticated,
        "current_user": getattr(current_user, "username", None)
    }
    logger.info("Session debug: %s", info)
    return jsonify(info)

# ------------- Run -------------
if __name__ == "__main__":
    # Quick environment checks to help debug common login fail causes
    logger.info("Starting KralZeka login-fixed server")
    logger.info("SECRET_KEY set: %s", bool(app.config.get("SECRET_KEY")))
    logger.info("SESSION_COOKIE_SECURE: %s", app.config.get("SESSION_COOKIE_SECURE"))
    logger.info("SESSION_COOKIE_SAMESITE: %s", app.config.get("SESSION_COOKIE_SAMESITE"))
    logger.info("DB file: %s", DB_FILE)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
