import json
import string
from cStringIO import StringIO
from datetime import datetime, timedelta
from urlparse import urljoin, urlparse

import pyqrcode
import requests
from flask import Blueprint, abort, flash, redirect, render_template, request, \
    url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import Form
from sqlalchemy import func
from wtforms import ValidationError
from wtforms.fields import *
from wtforms.validators import *
from wtforms.widgets.html5 import NumberInput

import util
from constants import USER_LEVELS
from decorators import email_verified_required
from models import Config, PasswordResetToken, User, db

blueprint = Blueprint("users", __name__, template_folder="templates")


# http://flask.pocoo.org/snippets/62/

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def get_redirect_target():
    for target in request.values.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target


def redirect_back(endpoint, **values):
    target = request.form['next']
    if not target or not is_safe_url(target):
        target = url_for(endpoint, **values)
    return redirect(target)


@blueprint.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm(prefix="login")
    next = get_redirect_target()
    if login_form.validate_on_submit():
        login_user(login_form.get_user(), remember=login_form.remember.data)
        return redirect_back("users.profile")
    return render_template("users/login.html", login_form=login_form,
                           next=next)


@blueprint.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("base.index"))


@blueprint.route("/password/forgot", methods=["GET", "POST"])
def forgot():
    forgot_form = PasswordForgotForm()
    if forgot_form.validate_on_submit():
        if forgot_form.user is not None:
            token = PasswordResetToken(active=True, uid=forgot_form.user.uid,
                                       email=forgot_form.email.data,
                                       expire=datetime.utcnow() + timedelta(
                                           days=1))
            db.session.add(token)
            db.session.commit()
            url = url_for("users.reset", code=token.token, _external=True)
            util.sendmail(forgot_form.email.data,
                          "%s Password Reset" % Config.get("ctf_name"),
                          "Click here to reset your password: %s" % url)
            flash("Sent! Check your email.", "success")
        return redirect(url_for("users.forgot"))
    return render_template("users/forgot.html", forgot_form=forgot_form)


@blueprint.route("/password/reset/<string:code>", methods=["GET", "POST"])
def reset(code):
    token = PasswordResetToken.query.filter_by(token=code, active=True).first()
    if not token or token.expired or token.email != token.user.email:
        abort(404)

    reset_form = PasswordResetForm()
    if reset_form.validate_on_submit():
        user = User.get_by_id(token.uid)
        user.password = reset_form.password.data
        token.active = False
        db.session.add(user)
        db.session.commit()
        flash("Password has been reset! Try logging in now.", "success")
        return redirect(url_for("users.login"))
    return render_template("users/reset.html", reset_form=reset_form)


@blueprint.route("/profile")
@blueprint.route("/profile/<int:uid>")
def profile(uid=None):
    if uid is None and current_user.is_authenticated:
        return redirect(url_for("users.profile", uid=current_user.uid))
    user = User.get_by_id(uid)
    if user is None:
        abort(404)
    user.type = USER_LEVELS[user.level]
    return render_template("users/profile.html", user=user)


@blueprint.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm(prefix="register")
    if register_form.validate_on_submit():
        new_user = register_user(register_form.name.data,
                                 register_form.email.data,
                                 register_form.username.data,
                                 register_form.password.data,
                                 int(register_form.level.data), admin=False)
        login_user(new_user)
        return redirect(url_for("users.profile"))
    return render_template("users/register.html", register_form=register_form)


@blueprint.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    change_password_form = ChangePasswordForm(prefix="change-password")
    profile_edit_form = ProfileEditForm(prefix="profile-edit")
    if change_password_form.validate_on_submit() and change_password_form.submit.data:
        current_user.password = change_password_form.password.data
        db.session.add(current_user)
        db.session.commit()
        flash("Password changed.", "success")
        return redirect(url_for("users.settings"))
    if profile_edit_form.validate_on_submit() and profile_edit_form.submit.data:
        for field in profile_edit_form:
            if field.short_name == "avatar":
                if len(field.data.read()) > 0:
                    field.data.seek(0)
                    response = requests.post("http://filestore:8000/save",
                                             data={"prefix": "avatar"},
                                             files={"file": field.data})
                    if response.status_code == 200:
                        current_user._avatar = "/static/%s" % response.text
                continue
            if hasattr(current_user, field.short_name):
                setattr(current_user, field.short_name, field.data)
        if profile_edit_form.remove_avatar.data:
            current_user._avatar = None
        db.session.add(current_user)
        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("users.settings"))
    else:
        for field in profile_edit_form:
            if hasattr(current_user, field.short_name):
                field.data = getattr(current_user, field.short_name, "")
    return render_template("users/settings.html",
                           change_password_form=change_password_form,
                           profile_edit_form=profile_edit_form)


@blueprint.route("/two_factor/required")
def two_factor_required():
    user = User.query.filter(
        func.lower(User.username) == request.args.get("username",
                                                      "").lower()).first()
    if not user:
        return json.dumps(False)
    return json.dumps(user.otp_confirmed)


@blueprint.route("/two_factor/setup", methods=["GET", "POST"])
@email_verified_required
@login_required
def two_factor_setup():
    two_factor_form = TwoFactorAuthSetupForm()
    if two_factor_form.validate_on_submit():
        current_user.otp_confirmed = True
        db.session.add(current_user)
        db.session.commit()
        flash("Two-factor authentication setup is complete.", "success")
        return redirect(url_for("users.settings"))
    return render_template("users/two_factor/setup.html",
                           two_factor_form=two_factor_form)


@blueprint.route("/two_factor/qr")
@login_required
def two_factor_qr():
    url = pyqrcode.create(current_user.get_totp_uri())
    stream = StringIO()
    url.svg(stream, scale=6)
    return stream.getvalue().encode("utf-8"), 200, {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": 0,
        "Secret": current_user.otp_secret
    }


@blueprint.route("/two_factor/disable")
@login_required
def two_factor_disable():
    current_user.otp_confirmed = False
    db.session.add(current_user)
    db.session.commit()
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("users.settings"))


@blueprint.route("/verify")
@login_required
def verify_email():
    if current_user.email_verified:
        return False
    code = util.generate_string()
    current_user.email_token = code
    db.session.add(current_user)
    db.session.commit()
    try:
        send_verification_email(current_user.username, current_user.email,
                                url_for("users.verify", code=code,
                                        _external=True))
        return "success"
    except Exception, e:
        return str(e)


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


def send_verification_email(username, email, verification_link):
    ctf_name = Config.get("ctf_name")
    subject = "[ACTION REQUIRED] Email Verification - %s" % ctf_name
    body = string.Template(open("email.txt").read()).substitute({
        "link": verification_link,
        "ctf_name": ctf_name,
        "username": username
    })
    response = util.sendmail(email, subject, body)
    if response.status_code != 200:
        raise Exception("Failed: %s" % response.text)
    response = response.json()
    if "Queued" in response["message"]:
        return True
    else:
        raise Exception(response["message"])


def register_user(name, email, username, password, level, admin=False,
                  **kwargs):
    new_user = User(name=name, username=username, password=password,
                    email=email, level=level, admin=admin)
    for key, value in kwargs.items():
        setattr(new_user, key, value)
    code = util.generate_string()
    new_user.email_token = code
    send_verification_email(username, email,
                            url_for("users.verify", code=code, _external=True))
    db.session.add(new_user)
    db.session.commit()
    return new_user


class ChangePasswordForm(Form):
    old_password = PasswordField("Old Password", validators=[
        InputRequired("Please enter your old password.")])
    password = PasswordField("Password", validators=[
        InputRequired("Please enter a password.")])
    confirm_password = PasswordField("Confirm Password", validators=[
        InputRequired("Please confirm your password."),
        EqualTo("password", "Please enter the same password.")])
    submit = SubmitField("Update Password")

    def validate_old_password(self, field):
        if not current_user.check_password(field.data):
            raise ValidationError("Old password doesn't match.")


class LoginForm(Form):
    username = StringField("Username", validators=[
        InputRequired("Please enter your username.")])
    password = PasswordField("Password", validators=[
        InputRequired("Please enter your password.")])
    code = IntegerField("Two-Factor Token", validators=[])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

    def get_user(self):
        query = User.query.filter(
            func.lower(User.username) == self.username.data.lower())
        return query.first()

    def validate_username(self, field):
        if self.get_user() is None:
            raise ValidationError("This user doesn't exist.")

    def validate_code(self, field):
        user = self.get_user()
        if not user:
            return
        if user.otp_confirmed and not user.verify_totp(field.data):
            raise ValidationError("Incorrect code.")

    def validate_password(self, field):
        user = self.get_user()
        if not user:
            return
        if not user.check_password(field.data):
            raise ValidationError("Check your password again.")


class ProfileEditForm(Form):
    name = StringField("Name",
                       validators=[InputRequired("Please enter a name.")])
    avatar = FileField("Avatar")
    remove_avatar = BooleanField("Remove Avatar")
    submit = SubmitField("Update Profile")


class PasswordForgotForm(Form):
    email = StringField("Email",
                        validators=[InputRequired("Please enter your email."),
                                    Email("Please enter a valid email.")])
    submit = SubmitField("Send Recovery Email")

    def __init__(self):
        super(PasswordForgotForm, self).__init__()
        self._user = None
        self._user_cached = False

    @property
    def user(self):
        if not self._user_cached:
            self._user = User.query.filter(
                func.lower(User.email) == self.email.data.lower()).first()
            self._user_cached = True
        return self._user


class PasswordResetForm(Form):
    password = PasswordField("Password", validators=[
        InputRequired("Please enter a password.")])
    confirm_password = PasswordField("Confirm Password", validators=[
        InputRequired("Please confirm your password."),
        EqualTo("password", "Please enter the same password.")])
    submit = SubmitField("Change Password")


class RegisterForm(Form):
    name = StringField("Name",
                       validators=[InputRequired("Please enter a name.")])
    username = StringField("Username", validators=[
        InputRequired("Please enter a username."),
        Length(3, 24,
               "Your username must be between 3 and 24 characters long.")])
    email = StringField("Email",
                        validators=[InputRequired("Please enter an email."),
                                    Email("Please enter a valid email.")])
    password = PasswordField("Password", validators=[
        InputRequired("Please enter a password.")])
    confirm_password = PasswordField("Confirm Password", validators=[
        InputRequired("Please confirm your password."),
        EqualTo("password", "Please enter the same password.")])
    level = RadioField("Who are you?", choices=[("1", "Student"), ("2",
                                                                   "Observer"),
                                                ("3", "Teacher")])
    github_id = HiddenField(validators=[Optional()])
    google_id = HiddenField(validators=[Optional()])
    submit = SubmitField("Register")

    def validate_username(self, field):
        if not util.VALID_USERNAME.match(field.data):
            raise ValidationError(
                "Username must be contain letters, numbers, or _, and not start with a number.")
        if User.query.filter(
                func.lower(User.username) == field.data.lower()).count():
            raise ValidationError("Username is taken.")

    def validate_email(self, field):
        if User.query.filter(
                func.lower(User.email) == field.data.lower()).count():
            raise ValidationError("Email is taken.")


class TwoFactorAuthSetupForm(Form):
    code = IntegerField("Code",
                        validators=[InputRequired("Please enter the code.")],
                        widget=NumberInput())
    password = PasswordField("Password", validators=[
        InputRequired("Please enter your password.")])
    submit = SubmitField("Confirm")

    def validate_code(self, field):
        if not current_user.verify_totp(field.data):
            raise ValidationError("Incorrect code.")

    def validate_password(self, field):
        if not current_user.check_password(field.data):
            raise ValidationError("Incorrect password.")
