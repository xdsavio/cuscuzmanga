import os
import smtplib
import base64
import pickle
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import re
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Configuração do Flask
app = Flask(__name__)
app.secret_key = "sua_chave_secreta_aqui"  # Alterar para algo seguro

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///biblioteca.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuração da pasta de uploads
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Criar a pasta de uploads se não existir
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Função para verificar a extensão do arquivo
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Validação do nome de usuário
def validar_usuario(usuario):
    return bool(re.match("^[a-z0-9]{8,}$", usuario))

# Validação da senha
def validar_senha(senha):
    return len(senha) >= 8

# Configuração para envio de e-mail via Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
CREDENTIALS_FILE = 'config/credentials.json'

def send_confirmation_email(user_email):
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    try:
        service = build('gmail', 'v1', credentials=creds)
        message = MIMEMultipart()
        message['to'] = user_email
        message['subject'] = 'Cadastro Realizado com Sucesso!'
        msg = MIMEText('Olá, seu cadastro foi realizado com sucesso em nossa biblioteca de mangás.')
        message.attach(msg)

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        message = service.users().messages().send(userId="me", body={'raw': raw_message}).execute()
        print(f"E-mail enviado com sucesso! Message Id: {message['id']}")
    except Exception as error:
        print(f"Ocorreu um erro: {error}")

# Modelos do banco de dados
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Manga(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    volume = db.Column(db.Integer, nullable=False)
    stars = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_filename = db.Column(db.String(200), nullable=True)

# Criação do banco de dados
with app.app_context():
    db.create_all()

# Rotas
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        session["user_id"] = user.id
        return redirect(url_for("library"))
    else:
        error_message = "Usuário ou senha inválidos."
        return render_template("index.html", error_message=error_message)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        email = request.form["email"]

        if not validar_usuario(username):
            flash("O nome de usuário deve ter pelo menos 8 caracteres e conter apenas letras minúsculas e números.")
            return redirect(url_for("home"))

        if User.query.filter_by(username=username).first():
            flash("Usuário já existe!")
            return redirect(url_for("home"))

        if not validar_senha(password):
            flash("A senha deve ter pelo menos 8 caracteres.")
            return redirect(url_for("home"))

        if password != confirm_password:
            flash("As senhas não coincidem.")
            return redirect(url_for("home"))

        if User.query.filter_by(email=email).first():
            flash("E-mail já cadastrado!")
            return redirect(url_for("home"))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        flash("Cadastro realizado com sucesso!")
        send_confirmation_email(email)
        return redirect(url_for("home"))

    return render_template("register.html")

@app.route("/library", methods=["GET", "POST"])
def library():
    if "user_id" not in session:
        return redirect(url_for("home"))
    
    user_id = session["user_id"]
    name_filter = request.form.get("name_filter", "")
    stars_filter = request.form.get("stars_filter", "")

    mangas = Manga.query.filter(Manga.user_id == user_id)

    if name_filter:
        mangas = mangas.filter(Manga.title.contains(name_filter))

    if stars_filter.isdigit():
        mangas = mangas.filter(Manga.stars == int(stars_filter))

    mangas = mangas.all()
    return render_template("library.html", mangas=mangas)

@app.route("/add_manga", methods=["POST"])
def add_manga():
    if "user_id" not in session:
        return redirect(url_for("home"))
    
    title = request.form["title"]
    volume = request.form["volume"]
    stars = request.form["stars"]
    user_id = session["user_id"]

    if not volume.isdigit() or not (0 <= int(volume) <= 999):
        return "O volume deve ser um número entre 0 e 999.", 400

    if not stars.isdigit() or not (0 <= int(stars) <= 5):
        return "A classificação deve ser um número entre 0 e 5.", 400

    volume = int(volume)
    stars = int(stars)

    image = request.files.get("image")
    image_filename = None
    if image and allowed_file(image.filename):
        image_filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        image.save(image_path)

    new_manga = Manga(title=title, volume=volume, stars=stars, user_id=user_id, image_filename=image_filename)
    db.session.add(new_manga)
    db.session.commit()

    return redirect(url_for("library"))

if __name__ == "__main__":
    app.run(debug=True)