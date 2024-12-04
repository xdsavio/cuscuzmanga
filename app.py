import os
import base64
import pickle
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import re

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

# Modelos do banco de dados
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    security_question = db.Column(db.String(200), nullable=False)
    security_answer = db.Column(db.String(200), nullable=False)
    profile_image = db.Column(db.String(200), nullable=True)  # Campo para a imagem de perfil

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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            return redirect(url_for("library"))
        else:
            error_message = "Usuário ou senha inválidos."
            return render_template("index.html", error_message=error_message)
    
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        security_question = request.form["security_question"]
        security_answer = request.form["security_answer"]

        # Validando o nome de usuário
        if not validar_usuario(username):
            flash("O nome de usuário deve ter pelo menos 8 caracteres e conter apenas letras minúsculas e números.")
            return render_template("register.html", username=username, security_question=security_question, security_answer=security_answer)

        # Verificando se o nome de usuário já existe
        if User.query.filter_by(username=username).first():
            flash("Usuário já existe!")
            return render_template("register.html", username=username, security_question=security_question, security_answer=security_answer)

        # Validando a senha
        if not validar_senha(password):
            flash("A senha deve ter pelo menos 8 caracteres.")
            return render_template("register.html", username=username, security_question=security_question, security_answer=security_answer)

        # Verificando se as senhas coincidem
        if password != confirm_password:
            flash("As senhas não coincidem.")
            return render_template("register.html", username=username, security_question=security_question, security_answer=security_answer)

        # Criptografando a senha
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, 
                        security_question=security_question, security_answer=security_answer)
        db.session.add(new_user)
        db.session.commit()

        flash("Cadastro realizado com sucesso!")
        return redirect(url_for("home"))

    return render_template("register.html")

@app.route("/library", methods=["GET", "POST"])
def library():
    if "user_id" not in session:
        return redirect(url_for("home"))
    
    user_id = session["user_id"]
    user = User.query.get(user_id)  # Garantindo que o usuário seja passado para o template
    name_filter = request.form.get("name_filter", "")
    stars_filter = request.form.get("stars_filter", "")

    mangas = Manga.query.filter(Manga.user_id == user_id)

    if name_filter:
        mangas = mangas.filter(Manga.title.contains(name_filter))

    if stars_filter.isdigit():
        mangas = mangas.filter(Manga.stars == int(stars_filter))

    mangas = mangas.all()
    return render_template("library.html", mangas=mangas, user=user)  # Passando o user para o template

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

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect(url_for("home"))

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        new_username = request.form["username"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        
        # Validar se a senha foi alterada e confirmar se as senhas coincidem
        if new_password and new_password != confirm_password:
            flash("As senhas não coincidem.")
            return render_template("edit_profile.html", user=user)
        
        if new_password:
            user.password = generate_password_hash(new_password)

        if new_username:
            user.username = new_username
        
        # Verificando e salvando a nova imagem de perfil
        image = request.files.get("profile_image")
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.profile_image = filename
        
        db.session.commit()
        flash("Perfil atualizado com sucesso!")
        return redirect(url_for("library"))

    return render_template("edit_profile.html", user=user)

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username")  # Usando .get() para evitar KeyError

        # Verificando se o nome de usuário foi fornecido
        if not username:
            flash("Por favor, insira seu nome de usuário.")
            return redirect(url_for("forgot_password"))

        # Buscando o usuário no banco de dados
        user = User.query.filter_by(username=username).first()

        if user:
            # Exibindo a pergunta de segurança para o usuário
            return render_template("security_question.html", user_id=user.id, security_question=user.security_question)
        else:
            flash("Usuário não encontrado!")
            return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html")

@app.route("/security_question/<int:user_id>", methods=["POST"])
def security_question(user_id):
    user = User.query.get(user_id)
    answer = request.form.get("security_answer")

    # Verificando a resposta
    if user and user.security_answer and user.security_answer == answer:
        flash("Resposta correta! Agora você pode alterar sua senha.")
        return redirect(url_for("reset_password", user_id=user.id))
    else:
        flash("Resposta incorreta. Tente novamente.")
        return redirect(url_for("forgot_password"))

@app.route("/reset_password/<int:user_id>", methods=["GET", "POST"])
def reset_password(user_id):
    user = User.query.get(user_id)
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        if new_password != confirm_password:
            flash("As senhas não coincidem.")
            return render_template("reset_password.html", user=user)

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Senha alterada com sucesso!")
        return redirect(url_for("login"))

    return render_template("reset_password.html", user=user)

if __name__ == "__main__":
    app.run(debug=True)
