from flask import Flask, render_template_string, request, session, redirect, url_for
import requests
import os
from flask_sqlalchemy import SQLAlchemy

# =====================
# 🔑 GROQ API AYARLARI
# =====================
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # Render'da Environment sekmesinde ayarla
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# =====================
# ⚙️ FLASK AYARLARI
# =====================
app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# =====================
# 👤 VERİTABANI MODELİ
# =====================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# =====================
# 🧠 GROQ API FONKSİYONU
# =====================
def ask_groq(prompt):
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "llama-3.1-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 1024
    }

    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=data)
        result = response.json()
        if "error" in result:
            return f"Groq API hatası: {result['error'].get('message', 'Bilinmeyen hata')}"
        return result["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Bağlantı hatası: {e}"

# =====================
# 💾 VERİTABANI BAŞLATMA
# =====================
def init_db():
    with app.app_context():
        db.create_all()
        # İlk admin hesabı oluştur
        if not User.query.filter_by(username="enes").first():
            admin = User(username="enes", password="enes1357924680", is_admin=True)
            db.session.add(admin)
            db.session.commit()

# =====================
# 🏠 GİRİŞ SAYFASI
# =====================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session["username"] = username
            session["is_admin"] = user.is_admin
            return redirect(url_for("chat"))
        return "Hatalı kullanıcı adı veya şifre"
    return render_template_string("""
        <html>
        <head>
            <title>KralZeka Giriş</title>
            <style>
                body {background-color:#0d0d0d; color:white; text-align:center; font-family:Arial;}
                input {padding:10px; border-radius:5px; border:none; margin:5px;}
                button {padding:10px 20px; border:none; border-radius:5px; background-color:green; color:white;}
            </style>
        </head>
        <body>
            <h2>👑 KralZeka Giriş</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Kullanıcı adı" required><br>
                <input type="password" name="password" placeholder="Şifre" required><br>
                <button type="submit">Giriş Yap</button>
            </form>
        </body>
        </html>
    """)

# =====================
# 💬 ANA SOHBET SAYFASI
# =====================
@app.route("/chat", methods=["GET", "POST"])
def chat():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    response_text = None

    if request.method == "POST":
        user_input = request.form["user_input"]
        response_text = ask_groq(user_input)

    return render_template_string("""
        <html>
        <head>
            <title>KralZeka</title>
            <style>
                body {background-color:#000; color:white; text-align:center; font-family:Arial;}
                .chatbox {background-color:#111; width:60%; margin:auto; padding:20px; border-radius:10px;}
                input {width:70%; padding:10px; border:none; border-radius:5px;}
                button {padding:10px 20px; background-color:green; border:none; border-radius:5px; color:white;}
                .logout {color:red; text-decoration:none;}
            </style>
        </head>
        <body>
            <h2>Merhaba, {{username}} 👑</h2>
            <div class="chatbox">
                {% if response_text %}
                    <p><b>Sen:</b> {{request.form['user_input']}}</p>
                    <p><b>KralZeka:</b> {{response_text}}</p>
                {% endif %}
                <form method="POST">
                    <input type="text" name="user_input" placeholder="Bir şey yaz..." required>
                    <button type="submit">Gönder</button>
                </form>
                <br>
                <a href="{{url_for('logout')}}" class="logout">Çıkış yap</a>
            </div>
        </body>
        </html>
    """, username=username, response_text=response_text)

# =====================
# 🚪 ÇIKIŞ
# =====================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =====================
# 🚀 BAŞLAT
# =====================
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
