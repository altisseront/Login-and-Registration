from asyncio import DatagramProtocol
from flask_app.models.user import User
from flask_app import app
from flask import render_template,redirect,request,session, flash
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
@app.route ('/')
def index():
    return render_template('index.html')
@app.route('/register_user', methods = ['POST'])
def create_user():
    if not User.validate_user(request.form):
        return redirect('/')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    data = {
        "first_name" : request.form['first_name'],
        "last_name" : request.form['last_name'],
        "email" : request.form['email'],
        "password" : pw_hash
    }
    user_id = User.create(data)
    session['user_id'] = user_id
    return redirect('/dashboard')

@app.route('/login', methods = ['POST'])
def login():
    data = { "email" : request.form['email']}
    user_in_db = User.get_by_email(data)
    if not user_in_db:
        flash('Invalid Email/password', "login")
        return redirect('/')
    if not bcrypt.check_password_hash(user_in_db.password, request.form["pword"]):
        flash('Invalid Email/password', "login")
        return redirect('/')
    session['user_id'] = user_in_db.id
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard ():
    if 'user_id' not in session:
        flash('You must log in first!')
        return redirect ('/')
    data = { "user_id" : session['user_id']}
    return render_template('dashboard.html', user=User.get_user_by_id(data))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')