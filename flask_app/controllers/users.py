from flask_app import app
from flask import render_template,redirect,request,session,flash
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    if 'user_id' in session:
        data = {
            'user_id': session['user_id']
        }
        user = User.get_user_by_id(data)
        allMagazines = User.getAllMagazines()
        return render_template('dashboard.html', loggedUser= user, allMagazines = allMagazines)#, userLikedPosts= userLikedPosts
    return redirect('/logout')

@app.route('/loginregister')
def first_page():
    return render_template('login_register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        data = {
            'user_id': session['user_id']
        }
        user = User.get_user_by_id(data)
        allMagazines = User.getAllMagazines()
        userLikedMagazines = User.get_logged_user_liked_magazines(data)
        return render_template("dashboard.html",loggedUser= user,  allMagazines = allMagazines, userLikedMagazines = userLikedMagazines)
    return redirect('/loginregister')

@app.route('/register', methods=['POST'])
def register():
    # validate the form here ...
    if User.is_valid(request.form):
        # User.save(request.form)
        
        # create the hash
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        print(pw_hash)
    # put the pw_hash into the data dictionary
        data = {
            "name": request.form['name'],
            "lname": request.form['lname'],
            "email": request.form['email'],
            "password" : pw_hash
        }
        # Call the save @classmethod on User
        user_id = User.save(data)
    # store user id into session
        session['user_id'] = user_id
    return redirect("/loginregister")


@app.route('/login', methods=['POST'])
def login():
# see if the username provided exists in the database
    data = { "email" : request.form["email"] }
    user_in_db = User.get_by_email(data)
    # user is not registered in the db
    if not user_in_db:
        flash("Invalid Email/Password", "invalidEmail")
        return redirect("/loginregister")
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        # if we get False after checking the password
        flash("Invalid Email/Password", "invalidEmail")
        return redirect('/loginregister')
    # if the passwords matched, we set the user_id into session
    session['user_id'] = user_in_db.id
# never render on a post!!!
    return redirect("/dashboard")

@app.route('/logout/')
def logout():
    session.clear()
    return redirect('/loginregister')
