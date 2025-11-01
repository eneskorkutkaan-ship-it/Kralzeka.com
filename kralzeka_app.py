import os
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import requests

# =====================================================
# 🔑 Groq API Anahtarı
# =====================================================
GROQ_API_KEY = "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"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# =====================================================
# 🌐 Flask Başlatma
# =====================================================
app = Flask(__name__)
app.secret_key = "kralzeka_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///kralzeka.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# =====================================================
# 🧱 Veritabanı Modelleri
# =====================================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    daily_limit = db.Column(db.Integer, default=5)

# =====================================================
# 💾 Veritabanı Başlatma
# =====================================================
def init_db():
    db.create_all()
    # İlk admin hesabı eklenir (Enes)
    if not User.query.filter_by(name="enes").first():
        admin = User(name="enes", password="enes1357924680", is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin hesabı oluşturuldu: enes / enes1357924680")

# =====================================================
# 🤖 Groq Yapay Zeka İsteği
# =====================================================
def ask_groq(prompt):
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": "llama3-70b-8192",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7
    }
    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Hata: {str(e)}"

# =====================================================
# 🌐 HTML Şablonu (tek dosyada)
# =====================================================
page_template = """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>KralZeka - Giriş</title>
<style>
body { font-family: Arial; background: #101010; color: #fff; text-align: center; }
.container { margin-top: 100px; }
input { padding: 10px; margin: 5px; border-radius: 8px; border: none; }
button { padding: 10px 20px; border: none; border-radius: 8px; background: #00b894; color: #fff; cursor: pointer; }
.chat-box { width: 60%; margin: auto; background: #1e1e1e; padding: 20px; border-radius: 12px; margin-top: 20px; }
.message { text-align: left; margin: 10px; }
.user { color: #00cec9; }
.bot { color: #81ecec; }
</style>
</head>
<body>
<div class="container">
  {% if not session.get("user") %}
    <h1>KralZeka'ya Hoş Geldin</h1>
    <form method="post" action="/login">
      <input name="name" placeholder="Kullanıcı adı" required><br>
      <input name="password" placeholder="Şifre" type="password" required><br>
      <button type="submit">Giriş Yap</button>
    </form>
    <form method="post" action="/register">
      <input name="name" placeholder="Yeni kullanıcı adı" required><br>
      <input name="password" placeholder="Şifre" type="password" required><br>
      <button type="submit">Kayıt Ol</button>
    </form>
  {% else %}
    <h2>Merhaba, {{ session['user'] }} 👑</h2>
    <div class="chat-box" id="chat-box"></div>
    <input id="prompt" placeholder="Bir şey yaz..." style="width:60%">
    <button onclick="sendMessage()">Gönder</button><br><br>
    <a href="/logout" style="color:#ff7675">Çıkış yap</a>
  {% endif %}
</div>
<script>
async function sendMessage() {
  let prompt = document.getElementById("prompt").value;
  if (!prompt) return;
  let chatBox = document.getElementById("chat-box");
  chatBox.innerHTML += "<div class='message user'><b>Sen:</b> " + prompt + "</div>";
  document.getElementById("prompt").value = "";
  let response = await fetch("/ask", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({prompt: prompt})
  });
  let data = await response.json();
  chatBox.innerHTML += "<div class='message bot'><b>KralZeka:</b> " + data.reply + "</div>";
  chatBox.scrollTop = chatBox.scrollHeight;
}
</script>
</body>
</html>
"""

# =====================================================
# 🌍 Rotalar
# =====================================================
@app.route("/", methods=["GET"])
def home():
    return render_template_string(page_template)

@app.route("/login", methods=["POST"])
def login():
    name = request.form["name"]
    password = request.form["password"]
    user = User.query.filter_by(name=name, password=password).first()
    if user:
        session["user"] = user.name
        return redirect(url_for("home"))
    return "Hatalı giriş bilgisi!"

@app.route("/register", methods=["POST"])
def register():
    name = request.form["name"]
    password = request.form["password"]
    if User.query.filter_by(name=name).first():
        return "Bu kullanıcı zaten kayıtlı!"
    new_user = User(name=name, password=password)
    db.session.add(new_user)
    db.session.commit()
    return "Kayıt başarılı! Giriş yapabilirsiniz."

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/ask", methods=["POST"])
def ask():
    data = request.get_json()
    prompt = data.get("prompt", "")
    reply = ask_groq(prompt)
    return jsonify({"reply": reply})

# =====================================================
# 🚀 Uygulama Başlatma
# =====================================================
if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
