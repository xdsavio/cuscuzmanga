import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import re
from datetime import timedelta

# Configuração do Flask
app = Flask(__name__)
app.secret_key = "sua_chave_secreta_aqui"  # Alterar para algo seguro

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///biblioteca.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuração das pastas de uploads
app.config['DEFAULT_IMAGE_FOLDER'] = 'static/images'  # Imagens padrão
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Imagens enviadas pelos usuários
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Configuração da expiração da sessão (30 dias)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Criar as pastas de imagens se não existirem
for folder in [app.config['DEFAULT_IMAGE_FOLDER'], app.config['UPLOAD_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Função para verificar a extensão do arquivo
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Função para salvar imagens
def save_image(file, is_profile=False):
    if file and allowed_file(file.filename):
        folder = app.config['UPLOAD_FOLDER'] if not is_profile else app.config['DEFAULT_IMAGE_FOLDER']
        filename = secure_filename(file.filename)
        file.save(os.path.join(folder, filename))
        return filename
    return None

# Função para carregar os títulos dos mangás a partir do arquivo mangaList.txt
def load_manga_titles():
    try:
        with open("mangaList.txt", "r", encoding="utf-8") as file:
            titles = [line.strip() for line in file.readlines() if line.strip()]
        return titles
    except Exception as e:
        flash(f"Erro ao carregar os títulos do mangá: {e}")
        return []

# Validação do nome de usuário
def validar_usuario(usuario):
    return bool(re.match("^[a-z0-9]{8,}$", usuario))

# Validação da senha
def validar_senha(senha):
    return len(senha) >= 8

# Modelos do banco de dados
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)  # Nome do usuário
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    security_question = db.Column(db.String(200), nullable=False)
    security_answer = db.Column(db.String(200), nullable=False)
    profile_image = db.Column(db.String(200), nullable=True)


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

# Configuração para sessões permanentes
@app.before_request
def make_session_permanent():
    session.permanent = True

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
            return redirect(url_for("main_home"))  # Redireciona para o main_home após login
        else:
            flash("Usuário ou senha inválidos.")
            return redirect(url_for("home"))  # Retorna para a página inicial em caso de falha
    
    return render_template("index.html")

@app.route("/main_home")
def main_home():
    # Este é o redirecionamento correto após o login
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('home'))  # Redireciona se o usuário não estiver logado

    user = User.query.get(user_id)
    return render_template("main_home.html", user=user)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]  # Nome do usuário
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        security_question = request.form["security_question"]
        security_answer = request.form["security_answer"]

        if not validar_usuario(username):
            flash("O nome de usuário deve ter pelo menos 8 caracteres e conter apenas letras minúsculas e números.")
            return render_template("register.html")

        if User.query.filter_by(username=username).first():
            flash("Usuário já existe!")
            return render_template("register.html")

        if not validar_senha(password):
            flash("A senha deve ter pelo menos 8 caracteres.")
            return render_template("register.html")

        if password != confirm_password:
            flash("As senhas não coincidem.")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,  # Armazena o nome
            username=username,
            password=hashed_password, 
            security_question=security_question, 
            security_answer=security_answer
        )
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
    user = User.query.get(user_id)
    user.profile_image = user.profile_image or "default_profile.jpg"

    # Pegando os filtros da query string
    name_filter = request.args.get("name_filter", "")
    stars_filter = request.args.get("stars_filter", "")

    # Iniciando a consulta de mangás
    mangas = Manga.query.filter(Manga.user_id == user_id)

    # Filtro por título (name_filter)
    if name_filter:
        mangas = mangas.filter(Manga.title.contains(name_filter))

    # Filtro por classificação (stars_filter)
    if stars_filter and stars_filter.isdigit():
        mangas = mangas.filter(Manga.stars == int(stars_filter))

    mangas = mangas.all()

    return render_template("library.html", mangas=mangas, user=user)

@app.route("/add_manga", methods=["GET", "POST"])
def add_manga():
    manga_titles = load_manga_titles()  # Carrega os títulos do arquivo

    if request.method == "POST":
        title = request.form["title"]
        volume = int(request.form["volume"])
        stars = int(request.form["stars"])
        image = request.files.get("image")

        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        new_manga = Manga(title=title, volume=volume, stars=stars, user_id=session['user_id'], image_filename=image_filename)
        db.session.add(new_manga)
        db.session.commit()

        flash("Mangá adicionado com sucesso!")
        return redirect(url_for("library"))

    return render_template("add_manga.html", manga=None, manga_titles=manga_titles)

@app.route("/friends")
def friends():
    if "user_id" not in session:
        return redirect(url_for("home"))
    
    current_user = User.query.get(session["user_id"])
    users = User.query.filter(User.id != session["user_id"]).all()

    return render_template("friends.html", users=users, current_user=current_user)

@app.route("/user/<int:user_id>")
def view_user(user_id):
    if "user_id" not in session:
        return redirect(url_for("home"))
    
    user = User.query.get(user_id)
    if not user:
        flash("Usuário não encontrado.")
        return redirect(url_for("friends"))

    mangas = Manga.query.filter_by(user_id=user_id).all()

    return render_template("user_profile.html", user=user, mangas=mangas)

@app.route("/edit_manga/<int:manga_id>", methods=["GET", "POST"])
def edit_manga(manga_id):
    manga = Manga.query.get_or_404(manga_id)
    manga_titles = load_manga_titles()  # Carrega os títulos do arquivo

    if request.method == "POST":
        title = request.form["title"]
        volume = int(request.form["volume"])
        stars = int(request.form["stars"])
        image = request.files.get("image")

        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        manga.title = title
        manga.volume = volume
        manga.stars = stars
        if image_filename:
            manga.image_filename = image_filename

        db.session.commit()

        flash("Mangá atualizado com sucesso!")
        return redirect(url_for("library"))

    return render_template("add_manga.html", manga=manga, manga_titles=manga_titles)

@app.route("/delete_manga/<int:manga_id>", methods=["POST"])
def delete_manga(manga_id):
    if "user_id" not in session:
        return redirect(url_for("home"))
    
    manga = Manga.query.get_or_404(manga_id)
    if manga.user_id != session["user_id"]:
        flash("Você não tem permissão para excluir este mangá.")
        return redirect(url_for("library"))
    
    db.session.delete(manga)
    db.session.commit()
    flash("Mangá excluído com sucesso!")
    return redirect(url_for("library"))

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect(url_for("home"))
    
    user = User.query.get(session["user_id"])  # Acessando o usuário da sessão
    if request.method == "POST":
        new_username = request.form["username"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if new_password and new_password != confirm_password:
            flash("As senhas não coincidem.")
            return render_template("edit_profile.html", user=user)

        if new_password:
            user.password = generate_password_hash(new_password)

        if new_username:
            user.username = new_username

        image = request.files.get("profile_image")
        if image and allowed_file(image.filename):
            filename = save_image(image, is_profile=True)
            user.profile_image = filename

        db.session.commit()
        flash("Perfil atualizado com sucesso!")
        return redirect(url_for("library"))

    return render_template("edit_profile.html", user=user)

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"]
        user = User.query.filter_by(username=username).first()
        
        if user:
            flash(f"Instruções de recuperação de senha enviadas para o e-mail associado ao usuário {username}.")
        else:
            flash("Usuário não encontrado.")
        return redirect(url_for("home"))
    
    return render_template("forgot_password.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Você foi desconectado com sucesso!")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
