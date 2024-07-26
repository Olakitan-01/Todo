from flask import Flask,render_template,request,redirect,url_for,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash



app = Flask(__name__, template_folder="templates")
bcrypt = Bcrypt(app) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///c:/Users/hp/Desktop/Todo/database.db'
app.config['SECRET_KEY'] = 'secret'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)

class SignupForm(FlaskForm): 
    username = StringField(validators=[InputRequired(),Length(
        min=8, max=15)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(
        min=8, max=10)],render_kw={"placeholder":"password"})
    submit = SubmitField("Sign Up")

    def validate_username(self,username):
        existing_user_username =User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("This username already exist.Please choose another one")
        

class LoginForm(FlaskForm): 
    username = StringField(validators=[InputRequired(),Length(
        min=5, max=15)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(
        min=5, max=10)],render_kw={"placeholder":"password"})
    submit = SubmitField("Log in")


todos = [{"task":"Sample Todo", "done":False}]

@app.route("/")
def home():
    return render_template("home.html", todos=todos)

@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    print(form.data)
    if form.validate_on_submit():
         user = User.query.filter_by(username=form.username.data).first()
         print(user)
         if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user)
            return redirect (url_for('/dashboard'))
    return render_template("login.html", todos=todos,form=form)

@app.route('/dashboard', methods = ['GET','POST'])
@login_required
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return f'Hello, {user.username}!'
    return redirect(url_for('login'))


@app.route("/signup", methods=['GET','POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        session = db.session()
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(username=form.username.data, password = hashed_password)
        db.session.add(user)
        print(f"User added: {user.username}")
        db.session.commit()
        print("Database commit successful!") 
        return redirect(url_for('login'))
        print(form.data)
    return render_template("signup.html", todos=todos, form=form)


@app.route("/index")
def index():
    print(todos)
    return render_template("index.html", todos=todos)

@app.route("/add", methods=["POST"])
def add():
    todo = request.form ['todo']
    todos.append({"task": todo, "done": False})
    print(f"Updated todos list: {todos}")  # Print updated todos list
    return redirect(url_for("index"))

@app.route("/edit/<int:index>", methods=["GET","POST"])
def edit(index):
    todo = todos[index]
    if request.method == "POST":
        todo['task'] = request.form["todo"]
        return redirect(url_for("index"))
    else:
        return render_template( "edit.html",todo=todo, index=index)
    

@app.route("/check/<int:index>")
def check(index):
    todos[index]['done'] = not todos[index]['done']
    return redirect(url_for("index"))

@app.route("/delete/<int:index>")
def delete(index):
     del todos[index]
     return redirect(url_for("index"))

     
if __name__ == '__main__':
     with app.app_context():
        try:
            db.create_all()
            print("Database created successfully!")
        except Exception as e:
            print(f"Error creating database: {e}")
        app.run(debug=True)
