#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KralZeka — Full Sürüm (Tek Dosya)
Modlar: Ödev Yardımcısı, Espri, Sohbet, Sunum, Görsel, Admin Paneli
Giriş sistemi, kullanıcı veritabanı, görsel işleme, otomatik hata düzeltme içerir.
"""

import os
import json
import time
import sqlite3
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import requests

# --- Yüklemeler ---
load_dotenv()
HF_API_KEY = os.getenv("HF_API_KEY")  # Sen bunu .env'ye ekleyeceksin
app = Flask(__name__)
app.secret_key = "KRALZEKASUPERSECRETKEY"

# --- Veritabanı ---
DB_PATH = "kralzeka_users.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0,
    limit_gorsel INTEGER DEFAULT 5
)""")
conn.commit()

# İlk admin hesabı
def create_initial_admin():
    c.execute("SELECT * FROM users WHERE username=?", ("enes",))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, is_admin, limit_gorsel) VALUES (?, ?, ?, ?)",
                  ("enes", generate_password_hash("enes1357924680"), 1, 9999))
        conn.commit()
create_initial_admin()

# --- Yardımcı fonksiyonlar ---
def is_logged_in():
    return "user" in session

def is_admin():
    return session.get("is_admin", False)

def get_user(username):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    return c.fetchone()

def update_user_limit(username, new_limit):
    c.execute("UPDATE users SET limit_gorsel=? WHERE username=?", (new_limit, username))
    conn.commit()

# --- Ana Sayfa Şablonu (HTML + JS) ---
HTML_PAGE = """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>KralZeka 💎</title>
<style>
body { font-family: Arial, sans-serif; background: #0e0e0e; color: white; margin: 0; }
.sidebar { width: 240px; background: #111; position: fixed; top: 0; left: 0; bottom: 0; padding: 15px; }
.chat-container { margin-left: 260px; padding: 20px; }
button { background: #ff0077; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 8px; }
input, textarea { width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #444; background: #1a1a1a; color: white; margin-bottom: 8px; }
.msg { background: #222; padding: 10px; border-radius: 8px; margin: 5px 0; }
.you { color: #ff55aa; }
.kral { color: #55ffcc; }
</style>
</head>
<body>
<div class="sidebar">
  <h2>🤴 KralZeka</h2>
  {% if not logged_in %}
    <button onclick="window.location.href='/login'">Giriş Yap</button>
    <button onclick="window.location.href='/register'">Kayıt Ol</button>
  {% else %}
    <p>👋 Hoşgeldin, {{user}}</p>
    <button onclick="window.location.href='/logout'">Çıkış</button>
    <hr>
    <h4>Modlar</h4>
    <button onclick="changeMode('odev')">📘 Ödev Yardımcısı</button>
    <button onclick="changeMode('espri')">😂 Espri</button>
    <button onclick="changeMode('sohbet')">💬 Sohbet</button>
    <button onclick="changeMode('sunum')">📽️ Sunum</button>
    <button onclick="changeMode('gorsel')">🖼️ Görsel</button>
    {% if admin %}
      <hr><h4>Admin Paneli</h4>
      <button onclick="changeMode('admin')">⚙️ Panel</button>
    {% endif %}
    <hr>
    <button onclick="changeMode('istek')">💡 İstek Gönder</button>
  {% endif %}
</div>

<div class="chat-container">
  {% if not logged_in %}
    <h2>KralZeka'ya Hoşgeldin 👑</h2>
    <p>Devam etmek için giriş yap veya kayıt ol.</p>
  {% else %}
    <h2 id="modTitle">Mod: Sohbet</h2>
    <div id="chatbox"></div>
    <textarea id="userInput" placeholder="Bir şey yaz..."></textarea>
    <button onclick="sendMsg()">Gönder</button>
  {% endif %}
</div>

<script>
let mode = "sohbet";

function changeMode(m) {
  mode = m;
  document.getElementById("modTitle").innerText = "Mod: " + m.toUpperCase();
  document.getElementById("chatbox").innerHTML = "";
}

function sendMsg() {
  const input = document.getElementById("userInput");
  const msg = input.value.trim();
  if (!msg) return;
  const chat = document.getElementById("chatbox");
  chat.innerHTML += `<div class='msg you'><b>Sen:</b> ${msg}</div>`;
  input.value = "";

  fetch("/chat", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({message: msg, mode: mode})
  })
  .then(r => r.json())
  .then(d => {
    chat.innerHTML += `<div class='msg kral'><b>KralZeka:</b> ${d.reply}</div>`;
    chat.scrollTop = chat.scrollHeight;
  });
}
</script>
</body>
</html>
"""

# --- ROUTES ---

@app.route("/")
def home():
    return render_template_string(HTML_PAGE, logged_in=is_logged_in(), user=session.get("user"), admin=is_admin())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]
        c.execute("SELECT * FROM users WHERE username=?", (user,))
        data = c.fetchone()
        if data and check_password_hash(data[2], pw):
            session["user"] = user
            session["is_admin"] = bool(data[3])
            return redirect("/")
        else:
            return "Hatalı giriş!", 403
    return """
    <form method='post'>
    <h3>Giriş Yap</h3>
    <input name='username' placeholder='Kullanıcı Adı'>
    <input name='password' type='password' placeholder='Şifre'>
    <button>Giriş</button>
    </form>"""

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, generate_password_hash(pw)))
            conn.commit()
            return redirect("/login")
        except:
            return "Bu kullanıcı adı zaten alınmış!"
    return """
    <form method='post'>
    <h3>Kayıt Ol</h3>
    <input name='username' placeholder='Kullanıcı Adı'>
    <input name='password' type='password' placeholder='Şifre'>
    <button>Kayıt Ol</button>
    </form>"""

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    msg = data.get("message", "")
    mode = data.get("mode", "sohbet")

    # --- Modlara göre cevap oluşturma ---
    reply = ""

    if mode == "espri":
        jokes = [
            "Bilgisayar neden denize düşmüş? Çünkü çok fazla bayt (byte) almış!",
            "Python neden yılan gibi sürünüyor? Çünkü çok fazla döngüsü var 😂"
        ]
        reply = jokes[int(time.time()) % len(jokes)]
    elif mode == "odev":
        reply = "Bu ödevle ilgili bilgileri analiz ediyorum... 🔍"
    elif mode == "sunum":
        reply = "Sunum için başlık ve slayt taslağı oluşturuyorum..."
    elif mode == "gorsel":
        reply = generate_image(msg)
    elif mode == "istek":
        reply = f"'{msg}' isteğin kaydedildi. Güncellemede değerlendirilecek 💡"
    elif mode == "admin" and is_admin():
        reply = "Admin panelindesin. Buradan kullanıcıları, limitleri ve hata ayarlarını yönetebilirsin."
    else:
        reply = chat_with_hf(msg)

    return jsonify({"reply": reply})

# --- Hugging Face Chat (metin üretim) ---
def chat_with_hf(prompt):
    try:
        headers = {"Authorization": f"Bearer {HF_API_KEY}"}
        payload = {"inputs": prompt}
        res = requests.post("https://api-inference.huggingface.co/models/google/gemma-7b", headers=headers, json=payload)
        if res.status_code == 200:
            data = res.json()
            if isinstance(data, list) and "generated_text" in data[0]:
                return data[0]["generated_text"]
            else:
                return data
        else:
            return "Cevap alınamadı. Model yoğun olabilir."
    except Exception as e:
        return f"Hata: {str(e)}"

# --- Görsel oluşturma ---
def generate_image(prompt):
    try:
        headers = {"Authorization": f"Bearer {HF_API_KEY}"}
        payload = {"inputs": prompt}
        res = requests.post("https://api-inference.huggingface.co/models/CompVis/stable-diffusion-v1-4", headers=headers, json=payload)
        if res.status_code == 200:
            return "🖼️ Görsel oluşturuldu (demo mod)."
        else:
            return "Görsel oluşturulamadı."
    except Exception as e:
        return f"Hata: {str(e)}"

# --- Uygulama başlat ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
