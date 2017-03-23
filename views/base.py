import string

from flask import Blueprint, abort, redirect, render_template, url_for
from flask_breadcrumbs import register_breadcrumb, default_breadcrumb_root
from flask_wtf import Form
from sqlalchemy import func
from wtforms import ValidationError
from wtforms.fields import *
from wtforms.validators import *

import users
import util
from models import Config, Team, User, School, db, cache

blueprint = Blueprint("base", __name__, template_folder="templates")
default_breadcrumb_root(blueprint, ".")


@blueprint.route("/")
@register_breadcrumb(blueprint, ".", "Home")
def index():
    return render_template("base/index.html")


@blueprint.route("/scoreboard")
def scoreboard():
    scoreboard = Team.scoreboard()
    return render_template("base/scoreboard.html", scoreboard=scoreboard)


@blueprint.route("/setup", methods=["GET", "POST"])
def setup():
    if Config.get("setup_complete"):
        abort(404)
    if Config.get("setup_verification") is None:
        db.session.add(Config(key="setup_verification",
                              value=util.generate_string()))
        db.session.commit()
    setup_form = SetupForm()
    if setup_form.validate_on_submit():
        for field in setup_form:
            if field.name in ["csrf_token", "submit"]:
                continue
            db.session.add(Config(key=field.name, value=field.data))
        db.session.add(Config(key="stylesheet_url",
                              value="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"))
        db.session.add(Config(key="setup_complete", value="True"))
        users.register_user(setup_form.name.data, setup_form.email.data, setup_form.username.data,
                            setup_form.password.data, 0, admin=True)
        db.session.commit()
        return redirect(url_for("base.index"))
    return render_template("base/setup.html", setup_form=setup_form)


@blueprint.route("/u/<identifier>")
@cache.memoize()
def user(identifier):
    if identifier[0] not in string.digits:
        user = User.query.filter(func.lower(
            User.username) == identifier.lower()).first()
        if not user:
            abort(404)
        uid = user.uid
    else:
        uid = int(identifier)
    return redirect(url_for("users.profile", uid=uid))


class SetupForm(Form):
    ctf_name = StringField("CTF Name", validators=[
                           InputRequired("Please enter a CTF name.")])
    ctf_description = TextAreaField("CTF Description", validators=[Optional()])
    start_time = IntegerField("Start Time", validators=[
                              InputRequired("Please enter a CTF start time.")])
    end_time = IntegerField("End Time", validators=[
                            InputRequired("Please enter a CTF end time.")])
    team_size = IntegerField("Team Size", default=5, validators=[
                             InputRequired("Please enter a max team size.")])

    name = StringField("Name", validators=[
                       InputRequired("Please enter a name.")])
    username = StringField("Username", validators=[InputRequired("Please enter a username."), Length(
        3, 24, "Your username must be between 3 and 24 characters long.")])
    email = StringField("Email",
                        validators=[InputRequired("Please enter an email."), Email("Please enter a valid email.")])
    password = PasswordField("Password", validators=[
                             InputRequired("Please enter a password.")])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired(
        "Please confirm your password."), EqualTo("password", "Please enter the same password.")])

    verification = StringField("Verification", validators=[
                               InputRequired("Please enter a verification code.")])
    submit = SubmitField("Create CTF")

    def validate_username(self, field):
        if not util.VALID_USERNAME.match(field.data):
            raise ValidationError(
                "Username must be contain letters, numbers, or _, and not start with a number.")

    def validate_verification(self, field):
        code = Config.get("setup_verification")
        if code is None or code != field.data:
            raise ValidationError("Verification failed.")
