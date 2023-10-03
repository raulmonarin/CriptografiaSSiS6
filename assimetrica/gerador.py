import bcrypt

def welcome():
	print("Bem-vindo ao seu painel!")

def gainAccess(Username=None, Password=None):
    Username = input("Digite seu Usuário:")
    Password = input("Digite sua Senha:")
    
    
    if not len(Username or Password) < 1:
        if True:
            db = open("database.txt", "r")
            d = []
            f = []
            for i in db:
                a,b = i.split(",")
                b = b.strip()
                c = a,b
                d.append(a)
                f.append(b)
                data = dict(zip(d, f))
            try:
                if Username in data:
                    hashed = data[Username].strip('b')
                    hashed = hashed.replace("'", "")
                    hashed = hashed.encode('utf-8')
                    
                    try:
                        if bcrypt.checkpw(Password.encode(), hashed):
                        
                            print("Login bem sucedido!")
                            print("Hi", Username)
                            welcome()
                        else:
                            print("Senha Errada")
                        
                    except:
                        print("Senha ou nome incorreto(s)")
                else:
                    print("Usuário não existe")
            except:
                print("Usuário ou senha não existem")
        else:
            print("Erro ao logar no sistema")
            
    else:
        print("Tente logar novamente")
        gainAccess()

def register(Username=None, Password1=None, Password2=None):
    Username = input("Digite um nome de usuario:")
    Password1 = input("Crie uma senha:")
    Password2 = input("Confirme a senha:")
    db = open("database.txt", "r")
    d = []
    for i in db:
        a,b = i.split(",")
        b = b.strip()
        c = a,b
        d.append(a)
    if not len(Password1)<=8:
        db = open("database.txt", "r")
        if not Username ==None:
            if len(Username) <1:
                print("Por favor insira um nome de usuário")
                register()
            elif Username in d:
                print("Usuário já existe")
                register()		
            else:
                if Password1 == Password2:
                    Password1 = Password1.encode('utf-8')
                    Password1 = bcrypt.hashpw(Password1, bcrypt.gensalt())
                                       
                    db = open("database.txt", "a")
                    db.write(Username+", "+str(Password1)+"\n")
                    print("Usuário criado com sucesso!")
                    print("Por favor faça o login para prosseguir:")
                else:
                    print("As senhas sao diferentes")
                    register()
    else:
        print("Senha muito curta")



def home(option=None):
	print("Bem-vindo, selecione uma opção")
	option = input("[L]ogin | [S]ignup:")
	if option == "L":
		gainAccess()
	elif option == "S":
		register()
	else:
		print("Por favor digite um parâmetro válido!")

home()

