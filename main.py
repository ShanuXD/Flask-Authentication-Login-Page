from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)


app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(10000))
    name = db.Column(db.String(1000))


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        is_new_user = User.query.filter_by(email=request.form.get('email')).first()
        if is_new_user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        user_name = request.form['name']
        user_email = request.form['email']
        user_password = request.form['password']

        hash_password = generate_password_hash(user_password, method='pbkdf2:sha256', salt_length=8)

        if user_name and user_email and user_password:
            new_user = User(email=user_email, name=user_name, password=hash_password)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for('secrets'))

    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_email = request.form.get('email')
        user_password = request.form.get('password')
        print(user_email, user_password)

        user = User.query.filter_by(email=user_email).first()

        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, user_password):
            flash('Password incorrect, try again!')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))
    return render_template("login.html")

@app.route('/secrets')
@login_required
def secrets():
    # print(current_user.name)
    return render_template("secrets.html", name=current_user.name)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")

@login_manager.unauthorized_handler
def unauthorized():
    # do stuff
    print('go home')
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)
