from flask import Flask, render_template, url_for, redirect, request
from flask_pymongo import PyMongo
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId  # To handle MongoDB ObjectId

import cv2
import numpy as np
import base64
from flask import request, jsonify
from camera import process_image  # Your OpenCV processing function

# Initialize Flask app
app = Flask(__name__)

# MongoDB connection settings
app.config['MONGO_URI'] = 'mongodb+srv://gunputsneha:mydbpassword@cluster0.ermdea1.mongodb.net/mydatabase?retryWrites=true&w=majority&appName=Cluster0'
mongo = PyMongo(app)

bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'thisisasecretkey'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Loader Function
@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(str(user_data['_id']), user_data['email'], user_data['password'])
    return None

# User Class
class User(UserMixin):
    def __init__(self, _id, email, password):
        self.id = _id
        self.email = email
        self.password = password

    @staticmethod
    def get(user_id):
        user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return User(str(user_data['_id']), user_data['email'], user_data['password'])
        return None

    @staticmethod
    def find_by_email(email):
        user_data = mongo.db.users.find_one({"email": email})
        if user_data:
            return User(str(user_data['_id']), user_data['email'], user_data['password'])
        return None

# Register Form
class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(min=6, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_email(self, email):
        existing_user_email = mongo.db.users.find_one({"email": email.data})
        if existing_user_email:
            raise ValidationError('That email is already registered. Please choose a different one.')

# Login Form
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(min=6, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# Redirect to Login on Homepage
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/menu')
def menu():
    return render_template('menu.html')

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/search')
def search():
    return render_template('search.html')

@app.route('/fav')
def fav():
    return render_template('fav.html')

@app.route('/setting')
def setting():
    return render_template('setting.html')


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.find_by_email(form.email.data)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))  # Redirect to dashboard
    return render_template('login.html', form=form)

# Dashboard Route
@app.route('/menu')
@login_required
def dashboard():
    return render_template('menu.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = {
            "email": form.email.data,
            "password": hashed_password
        }
        inserted_user = mongo.db.users.insert_one(new_user)
        login_user(User(str(inserted_user.inserted_id), form.email.data, hashed_password))
        return redirect(url_for('menu'))  # Redirect to dashboard after registration

    return render_template('register.html', form=form)




@app.route('/capture', methods=['POST'])
def capture():
    data = request.get_json()
    image_data = data['image']
    header, encoded = image_data.split(',', 1)  # Remove the data URL prefix
    img_bytes = base64.b64decode(encoded)
    np_arr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    result = process_image(img)  # Your OpenCV image processing
    return jsonify(result=result)



# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)
