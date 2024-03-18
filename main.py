import os
import random
from sqlite3 import IntegrityError
from flask import Flask, render_template, request, redirect, url_for, flash, session
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_bootstrap import Bootstrap5
# pip install Bootstrap-Flask==2.3.3
from collections import defaultdict

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, TextAreaField, PasswordField, BooleanField, HiddenField
from wtforms.validators import DataRequired, URL
import smtplib

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'  # SQLite database file path

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATA_BASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
bootstrap = Bootstrap5(app)
db = SQLAlchemy(app)

# Configure Flask-Login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(50))
    map_url = db.Column(db.String(200))
    img_url = db.Column(db.String(200))
    location = db.Column(db.String(200))
    has_sockets = db.Column(db.Boolean)
    has_toilet = db.Column(db.Boolean)
    has_wifi = db.Column(db.Boolean)
    can_take_calls = db.Column(db.Boolean)
    seats = db.Column(db.String(50))
    coffee_price = db.Column(db.String(50))

    # Add a foreign key relationship to the User model
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('cafes', lazy=True))

    def __repr__(self):
        return f"Cafe('{self.name}', '{self.location}')"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return self.username


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cafe_id = db.Column(db.Integer, db.ForeignKey('cafe.id'), nullable=False)

    # Define relationships
    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    cafe = db.relationship('Cafe', backref=db.backref('comments', lazy=True))

    def __repr__(self):
        return f'<Comment {self.id}>'


# Create the database tables (if they don't exist)
with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')


class RegisterForm(FlaskForm):
    username = StringField("User Name", validators=[DataRequired()])
    email = StringField("Email Address", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long"),
        Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$',
               message="Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character")
    ])
    submit = SubmitField("Sign up")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'error')
        else:
            # Hash the user's password
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')

            # Create a new user object with hashed password
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password
            )

            # Add the new user to the database
            try:
                db.session.add(new_user)
                db.session.commit()

                # Automatically log in the user after registration
                login_user(new_user)

                return redirect(url_for('index'))
            except IntegrityError:
                # In case of any database integrity errors
                db.session.rollback()
                flash('Registration failed. Please try again later.', 'error')

    return render_template("register.html", form=form)


class LoginForm(FlaskForm):
    email = StringField("Email Adress", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# Make a login route logic
# check for the user profile existing and password
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Find user by email entered.
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Invalid email or password.', 'error')
        else:
            flash('User not found.', 'error')

    return render_template('login.html', form=form)


@app.route('/cities')
def cities():
    cafes_by_country = defaultdict(list)
    cafes = Cafe.query.all()

    for cafe in cafes:
        cafes_by_country[cafe.country].append(cafe.location)

    # Convert the defaultdict to a regular dictionary to ensure it's JSON-serializable
    cafes_by_country = dict(cafes_by_country)

    return render_template('cities.html', cafes_by_country=cafes_by_country)


@app.route('/cafe/<location>')
def cafes(location):
    cafes = Cafe.query.filter_by(location=location).all()
    return render_template('cafe.html', cafes=cafes, User=User)


@app.route('/search')
def search():
    response = True
    query = request.args.get('query').upper()
    results = Cafe.query.filter(or_(Cafe.name.ilike(f'%{query}%'),
                                    Cafe.location.ilike(f'%{query}%'),
                                    Cafe.country.ilike(f'%{query}%'))).all()
    if not results:
        response = False
    query = request.args.get('query')
    return render_template('search_results.html', results=results, query=query, response=response)


class EmailSender:
    def __init__(self, email):
        self.sender_email = 'YOUR EMAIL'
        self.receiver_email = email
        self.password = 'YOUR EMAIL APP PASSWORD'

    def send_email(self, token):

        email_text = f"""
        From: Super Blog resetting service

        We received a request to reset your Blog password.\n
        Enter the following password reset code: {token}
        """

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(self.sender_email, self.password)
            server.sendmail(self.sender_email, self.receiver_email, email_text)
            server.quit()
            return True  # Email sent successfully
        except Exception as e:
            return False  # Failed to send email


class ResetPasswordForm(FlaskForm):
    # Form field for entering the email to search for the user's account
    email = StringField("Please enter your email to search for your account.", validators=[DataRequired()])
    # Button to submit the email for password reset
    submit = SubmitField("Search")


@app.route('/reset-password/', methods=['GET', 'POST'])
def reset_password():
    reset_form = ResetPasswordForm()

    if reset_form.validate_on_submit():
        email = reset_form.email.data
        # Check if the entered email exists in the database
        user_email = User.query.filter_by(email=email).first()

        if user_email:
            # Generate a random token for password reset
            token = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            email_sender = EmailSender(email)

            # Send an email to the user with the generated token
            email_sent = email_sender.send_email(token)

            if email_sent:
                # Email sent successfully, store the token in the session for verification
                session['reset_token'] = token

                # Redirect to a page for entering the token received in the email
                return redirect(url_for('enter_token', email=email))
            else:
                # Failed to send email
                flash('Failed to send email. Please try again.', 'error')
        else:
            # Invalid email entered
            flash('Invalid email!', 'error')

    # Render the reset-password.html template with the reset_form
    return render_template('reset-password.html', reset_form=reset_form)


# Logout route that disconect the user and redirect to home page.
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


class CafeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired()])
    map_url = StringField('Map URL', validators=[URL(), DataRequired()])
    img_url = StringField('Image URL', validators=[URL(), DataRequired()])
    location = StringField('City', validators=[DataRequired()])
    open_in_ramadhan = BooleanField('Open in Ramdhan', default=False)
    has_sockets = BooleanField('Has Sockets', default=False)
    has_toilet = BooleanField('Has Toilet', default=False)
    has_wifi = BooleanField('Has WiFi', default=False)
    can_take_calls = BooleanField('Can Take Calls', default=False)
    seats = StringField('Seats', validators=[DataRequired()])
    coffee_price = StringField('Coffee Price', validators=[DataRequired()])

    submit = SubmitField('Submit')


@app.route('/suggest', methods=['GET', 'POST'])
@login_required
def suggest():
    form = CafeForm()
    if form.validate_on_submit():
        new_cafe = Cafe(
            name=form.name.data,
            country=form.country.data,
            map_url=form.map_url.data,
            img_url=form.img_url.data,
            location=form.location.data,
            has_sockets=form.has_sockets.data,
            has_toilet=form.has_toilet.data,
            has_wifi=form.has_wifi.data,
            can_take_calls=form.can_take_calls.data,
            seats=form.seats.data,
            coffee_price=form.coffee_price.data,
            open_in_ramadhan=form.open_in_ramadhan.data,
            user_id=current_user.id


        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for('cities'))
    return render_template('suggest.html', form=form)


class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit')


@app.route('/reviews/<cafe_id>', methods=['GET', 'POST'])
def reviews(cafe_id):
    form = CommentForm()

    # Fetch cafe information
    cafe_info = Cafe.query.filter_by(id=cafe_id).first()

    # Fetch all comments associated with the cafe ID
    comments = Comment.query.filter_by(cafe_id=cafe_id).all()

    if form.validate_on_submit():
        # If the form is submitted, add the comment
        new_comment = Comment(
            content=form.content.data,
            user_id=current_user.id,
            cafe_id=cafe_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('reviews', cafe_id=cafe_id))

    return render_template("reviews.html", cafe=cafe_info, form=form, comments=comments)


if __name__ == '__main__':
    app.run(debug=False)
