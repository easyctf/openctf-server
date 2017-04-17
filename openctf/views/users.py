from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required, login_user
from flask_wtf import FlaskForm
from sqlalchemy import func
from wtforms import ValidationError
from wtforms.fields import *
from wtforms.validators import *

from openctf.constants import UserLevel, UserLevelNames
from openctf.models import User, db
from openctf.utils import (VALID_USERNAME, generate_string,
                           get_redirect_target, redirect_back)

blueprint = Blueprint("users", __name__, template_folder="templates")


@blueprint.route("/forgot")
def forgot():
    return "hi"


@blueprint.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("users.profile"))
    login_form = LoginForm()
    next = get_redirect_target()
    if login_form.validate_on_submit():
        # TODO: make sure user's email is verified!
        login_user(login_form.get_user(), remember=login_form.remember.data)
        return redirect_back("users.profile")
    return render_template("users/login.html", login_form=login_form, next=next)


@blueprint.route("/profile")
@blueprint.route("/profile/<int:id>")
def profile(id=None):
    if id is None and current_user.is_authenticated:
        return redirect(url_for("users.profile", id=current_user.id))
    user = User.get_by_id(id)
    if user is None:
        abort(404)
    user.type = UserLevelNames[UserLevel(user.level)]
    return render_template("users/profile.html", user=user)


@blueprint.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("users.profile"))
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_user = register_user(register_form.name.data,
                                 register_form.email.data,
                                 register_form.username.data,
                                 register_form.password.data,
                                 int(register_form.level.data), admin=False)
        if current_app.config["EMAIL_VERIFICATION_REQUIRED"]:
            # Make sure they verify their email first.
            flash("You've registered! Check your inbox for a confirmation email.", "success")
            return redirect(url_for("users.login"))
        else:
            # Go ahead and log the user in.
            login_user(new_user)
            return redirect(url_for("users.profile"))
    return render_template("users/register.html", register_form=register_form)


@blueprint.route("/settings")
def settings():
    return "hi"


@blueprint.route("/verify/<string:code>")
@login_required
def verify(code):
    if current_user.email_verified:
        flash("You've already verified your email.", "info")
    elif current_user.email_token == code:
        current_user.email_verified = True
        db.session.add(current_user)
        db.session.commit()
        flash("Email verified!", "success")
    else:
        flash("Incorrect code.", "danger")
    return redirect(url_for("users.settings"))


def register_user(name, email, username, password, level, admin=False, send_email=True, **kwargs):
    new_user = User(name=name, username=username, password=password, email=email, level=level, admin=admin)
    # TODO limit this to certain values, I forgot what this was for.
    for key, value in kwargs.items():
        setattr(new_user, key, value)
    code = generate_string()
    new_user.email_token = code
    if send_email and current_app.config["MAILGUN_API_KEY"]:
        send_verification_email(username, email, url_for("users.verify", code=code, _external=True))
    db.session.add(new_user)
    db.session.commit()
    return new_user


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


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired("Please enter a name.")])
    username = StringField("Username", validators=[InputRequired("Please enter a username."), Length(3, 24, "Your username must be between 3 and 24 characters long.")])
    email = StringField("Email", validators=[InputRequired("Please enter an email."), Email("Please enter a valid email.")])
    password = PasswordField("Password", validators=[InputRequired("Please enter a password.")])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired("Please confirm your password."), EqualTo("password", "Please enter the same password.")])
    level = RadioField("Eligibility status:", choices=[("1", "Eligible"), ("2", "Ineligible"), ("3", "Teacher")])
    github_id = HiddenField(validators=[Optional()])
    google_id = HiddenField(validators=[Optional()])
    submit = SubmitField("Register")

    def validate_username(self, field):
        if not VALID_USERNAME.match(field.data):
            raise ValidationError("Username must be contain letters, numbers, or _, and not start with a number.")
        if User.query.filter(func.lower(User.username) == field.data.lower()).count():
            raise ValidationError("Username is taken.")

    def validate_email(self, field):
        if User.query.filter(func.lower(User.email) == field.data.lower()).count():
            raise ValidationError("Email is taken.")
