from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Replace the database URI with your MySQL database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:Preetreet11.@localhost/python'
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user' 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'register' in request.form:
            username = request.form['username']
            password = request.form['password']

            if User.query.filter_by(username=username).first():
                flash('Username already exists. Please choose another username.', 'error')
            else:
                hashed_password = generate_password_hash(password, method='sha256')
                new_user = User(username=username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful. You can now log in.', 'success')
        elif 'login' in request.form:
            username = request.form['username']
            password = request.form['password']

            user = User.query.filter_by(username=username).first()

            if not user or not check_password_hash(user.password, password):
                flash('Invalid username or password. Please try again.', 'error')
            else:
                session['username'] = username
                flash('Login successful.', 'success')

    if 'username' in session:
        return f'Logged in as: {session["username"]}<br><a href="/logout">Logout</a>'
    else:
        return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
