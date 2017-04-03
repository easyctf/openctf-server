from flask import Blueprint, render_template, request
from flask_login import login_required, login_user
from flask_wtf import FlaskForm
from sqlalchemy import func
from wtforms import ValidationError
from wtforms.fields import *
from wtforms.validators import *

from openctf.models import User
from openctf.utils import get_redirect_target, redirect_back

blueprint = Blueprint("users", __name__, template_folder="templates")


@blueprint.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    next = get_redirect_target()
    if login_form.validate_on_submit():
        login_user(login_form.get_user(), remember=login_form.remember.data)
        return redirect_back("users.profile")
    return render_template("users/login.html", login_form=login_form, next=next)


@blueprint.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    return "hi"


@blueprint.route("/register", methods=["GET", "POST"])
def register():
    return "hi"


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired("Please enter your username.")])
    password = PasswordField("Password", validators=[InputRequired("Please enter your password.")])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

    def get_user(self):
        query = User.query.filter(func.lower(User.username) == self.username.data.lower())
        return query.first()

    def validate_username(self, field):
        if not self.get_user():
            raise ValidationError("This user doesn't exist.")

    def validate_password(self, field):
        user = self.get_user()
        if not user:
            return  # should never happen
        if not user.check_password(field.data):
            raise ValidationError("Check your password again.")
