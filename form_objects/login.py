from flask_wtf import Form
from wtforms import PasswordField, TextField
from wtforms.validators import DataRequired


class LoginForm(Form):
    username = TextField('Enter your username', [DataRequired()])
    password = PasswordField('Enter your password', [DataRequired()])
