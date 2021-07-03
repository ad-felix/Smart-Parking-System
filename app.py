from flask import Flask, render_template, Response
from flask import Flask, render_template, url_for, redirect, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
import cv2

from detect import run

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'din22n2mxm'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


camera = cv2.VideoCapture(0)


def gen_frames():

    while True:
        success, frame = camera.read()  # read the camera frame
        if not success:
            camera.release()
            cv2.destroyAllWindows()
            break
        else:
            frame = run(frame)
            ret, buffer = cv2.imencode('.jpg', frame)
            # print(buffer.shape)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')  # concat frame one by one and show result


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):

    email = StringField('Email',
                        validators=[DataRequired(), Length(min=2, max=20), Email()])

    password = PasswordField('Password',
                             validators=[DataRequired()])

    submit = SubmitField('Login')


@app.route('/video_feed')
def video_feed():
    global camera
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user_row = User.query.filter_by(email=form.email.data).first()
        if user_row:
            if bcrypt.check_password_hash(user_row.password, form.password.data):
                login_user(user_row)
                return redirect(url_for("home"))

    return render_template('login.html', form=form)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/home', methods=["GET", "POST"])
@login_required
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=False)
