import logging

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import login_user
from flask_wtf import FlaskForm
from wtforms import ValidationError
from wtforms.fields import (IntegerField, PasswordField, StringField,
                            SubmitField, TextAreaField)
from wtforms.validators import Email, EqualTo, InputRequired, Length, Optional

from openctf.models import Config, db
from openctf.utils import VALID_USERNAME, generate_string
from openctf.views.users import register_user

blueprint = Blueprint("base", __name__, template_folder="templates")


@blueprint.route("/")
def index():
    return render_template("base/index.html")


@blueprint.route("/scoreboard")
def scoreboard():
    return render_template("base/scoreboard.html")


@blueprint.route("/setup", methods=["GET", "POST"])
def setup():
    if Config.get("setup_complete"):
        abort(404)
    if request.method == "GET":  # Config.get("setup_verification") is None:
        verification_code = generate_string()
        logging.warning("Verification code is: " + verification_code)
        Config.set("setup_verification", verification_code)
    setup_form = SetupForm()
    if setup_form.validate_on_submit():
        for field in setup_form:
            if field.name in ["csrf_token", "submit"]:
                continue
            db.session.add(Config(key=field.name, value=field.data))
        db.session.add(Config(key="setup_complete", value="True"))
        user = register_user(setup_form.name.data, setup_form.email.data, setup_form.username.data,
                             setup_form.password.data, 0, admin=True, send_email=False)
        login_user(user)
        db.session.commit()
        return redirect(url_for("base.index"))
    return render_template("base/setup.html", setup_form=setup_form)


class SetupForm(FlaskForm):
    ctf_name = StringField("CTF Name", validators=[InputRequired("Please enter a CTF name.")])
    ctf_description = TextAreaField("CTF Description", validators=[Optional()])
    start_time = IntegerField("Start Time", validators=[InputRequired("Please enter a CTF start time.")])
    end_time = IntegerField("End Time", validators=[InputRequired("Please enter a CTF end time.")])
    team_size = IntegerField("Team Size", default=5, validators=[InputRequired("Please enter a max team size.")])

    name = StringField("Name", validators=[InputRequired("Please enter a name.")])
    username = StringField("Username", validators=[InputRequired("Please enter a username."), Length(3, 24, "Your username must be between 3 and 24 characters long.")])
    email = StringField("Email", validators=[InputRequired("Please enter an email."), Email("Please enter a valid email.")])
    password = PasswordField("Password", validators=[InputRequired("Please enter a password.")])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired("Please confirm your password."), EqualTo("password", "Please enter the same password.")])

    verification = StringField("Verification", validators=[InputRequired("Please enter a verification code.")])
    submit = SubmitField("Create CTF")

    def validate_username(self, field):
        if not VALID_USERNAME.match(field.data):
            raise ValidationError("Username must be contain letters, numbers, or _, and not start with a number.")

    def validate_verification(self, field):
        code = Config.get("setup_verification")
        if code is None or code != field.data:
            raise ValidationError("Verification failed.")
