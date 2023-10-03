from flask import Flask, request, render_template, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Mock de banco de dados (usuários registrados)
users = {"teste": "$2b$12$Vr8zVcVhEAS/.59vcYLOSuyMOJI3pYKkkVC6/iNKOVlsaWwQgaWd6"}

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/loggin_sucess')
def logged():
    if current_user.is_authenticated:
        return render_template('loggin_sucess.html')
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and bcrypt.check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            flash('Login bem sucedido!', 'success')
            return redirect(url_for('logged'))
        else:
            error = 'Usuário ou senha incorreto(s)'

    if not request.referrer or "/login" not in request.referrer:
        flash('', 'success')
        flash('', 'danger')

    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if username in users:
            error = 'Nome de usuário já existe.'
        elif password != confirm_password:
            error = 'As senhas não coincidem.'
        else:
            # Hash da senha e armazenamento no banco de dados (você deve usar um banco de dados real)
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users[username] = hashed_password
            flash('Registro bem sucedido!', 'success')
            return redirect(url_for('login'))  # Redirecionar para a página de login após o registro

    return render_template('register.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout bem sucedido!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.secret_key = '123'
    app.run(debug=True)

