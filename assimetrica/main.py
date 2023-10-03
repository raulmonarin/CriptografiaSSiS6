from flask import Flask, request, render_template, redirect, url_for, flash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import base64

app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Mock de banco de dados (usuários registrados)
users = {}

# Gere um par de chaves pública e privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize as chaves para armazenamento seguro (guarde-as em um local seguro na prática)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

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
        clean_password = request.form['password']  # Recebe a senha criptografada em base64

        if username in users:
            try:
                
                raw_userpass = base64.b64decode(users[username])
                
                decrypted_password = private_key.decrypt(
                    raw_userpass,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode('utf-8')

                print(decrypted_password)

                if decrypted_password == clean_password:
                    user = User(username)
                    login_user(user)
                    flash('Login bem sucedido!', 'success')
                    return redirect(url_for('logged'))
                else:
                    error = 'Usuário ou senha incorreto(s)'
            except base64.binascii.Error as e:
                error = 'Erro ao decodificar a senha em base64: {}'.format(e)
            except Exception as e:
                error = 'Erro ao descriptografar a senha: {}'.format(e)
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
            try:
                # Criptografa a senha com a chave pública antes de armazená-la no banco de dados
                encrypted_password = public_key.encrypt(
                    password.encode('utf-8'),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # Codifica a senha criptografada em base64
                users[username] = base64.b64encode(encrypted_password).decode('utf-8')

                flash('Registro bem sucedido!', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                error = 'Erro ao criptografar a senha: {}'.format(e)

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

