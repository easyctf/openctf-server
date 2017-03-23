"""
    server.views.admin
    ~~~~~~~~~~~~~~~~~~

    The endpoints that serve admin users, for administrative pages. Most of
    the endpoints in this file should use @admin_required.
"""
# pylint: disable=wildcard-import

import imp
import random

from flask import Blueprint, abort, flash, redirect, render_template, \
    request, url_for
from flask_breadcrumbs import default_breadcrumb_root, register_breadcrumb
from flask_wtf import Form
from sqlalchemy import and_
from wtforms import ValidationError
from wtforms.fields import *
from wtforms.validators import *
from wtforms_components import read_only

from judge_api import judge_api
import util
from decorators import admin_required
from constants import USER_LEVELS
from models import AutogenFile, Config, Problem, Team, User, db
from teams import ManageTeamForm

blueprint = Blueprint("admin", __name__, template_folder="templates")
default_breadcrumb_root(blueprint, ".admin")


@blueprint.route("/")
@register_breadcrumb(blueprint, ".", "Admin")
@admin_required
def index():
    return render_template("admin/index.html")


@blueprint.route("/problems", methods=["GET", "POST"])
@blueprint.route("/problems/<int:pid>", methods=["GET", "POST"])
@register_breadcrumb(blueprint, ".problems", "Problems")
@admin_required
def problems(pid=None):
    problem = None
    problem_form = ProblemForm()
    if problem_form.validate_on_submit():
        if pid is None:
            problem = Problem()
        else:
            problem = Problem.get_by_id(pid)
            if problem is None:
                abort(404)
        problem_form.populate_obj(problem)
        if pid is None:
            problem.pid = None
        db.session.add(problem)
        db.session.flush()
        if problem_form.programming.data:
            if judge_api.problems_get(problem.pid).status_code == 404:
                api_method = judge_api.problems_create
            else:
                api_method = judge_api.problems_modify
            result = api_method(
                problem_id=problem.pid,
                test_cases=problem_form.test_cases.data or 10,
                time_limit=problem_form.time_limit.data or 1,
                memory_limit=problem_form.memory_limit.data or 256000,
                generator_code=problem_form.generator.data,
                generator_language="python2",
                grader_code=problem_form.grader.data,
                grader_language="python2",
                source_verifier_code=problem_form.source_verifier.data,
                source_verifier_language="python2",
            )
            if not result.is_ok():
                abort(500)
        autogen_files = AutogenFile.query.filter_by(pid=pid)
        if autogen_files.count():
            autogen_files.delete()
        db.session.commit()
        return redirect(url_for("admin.problems", pid=problem.pid))
    problems = Problem.query.order_by(Problem.value).all()
    if pid is not None:
        problem = Problem.get_by_id(pid)
        if request.method != "POST":
            problem_form = ProblemForm(obj=problem)
            if problem.programming:
                judge_problem = judge_api.problems_get(pid)
                if judge_problem.status_code == 404:
                    abort(500)
                problem_form.grader.data = judge_problem.data['grader_code']
                problem_form.generator.data = judge_problem.data['generator_code']
        if not problem:
            abort(404)
    return render_template("admin/problems.html", current_problem=problem,
                           problems=problems, problem_form=problem_form)


@blueprint.route("/problems/<int:pid>/delete", methods=["POST"])
@admin_required
def delete_problem(pid):
    problem = Problem.get_by_id(pid)
    if problem is None:
        abort(404)
    db.session.delete(problem)
    db.session.commit()
    return redirect(url_for("admin.problems"))


@blueprint.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    settings_form = SettingsForm()
    read_only(settings_form.public_key)
    services = ["GOOGLE", "GITHUB"]
    if settings_form.validate_on_submit():
        for field in settings_form:
            if field.short_name in ["csrf_token", "submit"]:
                continue
            config = Config.query.filter_by(key=field.short_name).first()
            if config is None:
                config = Config(key=field.short_name, value=field.data)
            config.value = field.data
            db.session.add(config)
        db.session.commit()
        flash("Settings saved!", "success")
        return redirect(url_for("admin.settings"))
    else:
        for field in settings_form:
            if field.short_name == "csrf_token":
                continue
            if field.short_name == "public_key":
                dummy, field.data = Config.get_ssh_keys()
                continue
            field.data = Config.get(field.short_name, "")
    return render_template("admin/settings.html", settings_form=settings_form,
                           services=services)


@blueprint.route("/users")
@blueprint.route("/users/<int:page>")
@register_breadcrumb(blueprint, ".users", "Users")
@admin_required
def users(page=1):
    if page < 1:
        return redirect(url_for("admin.users", page=1))
    users = User.query.paginate(page, 20, False)
    if not users.items:
        abort(404)
    return render_template("admin/users.html", page=page, pages=users.pages,
                           users=users.items)


@blueprint.route("/users/manage/<int:uid>", methods=["GET", "POST"])
@admin_required
def user_manage(uid):
    user = User.query.get_or_404(uid)
    manage_user_form = ManageUserForm(obj=user, type=user.level)
    if manage_user_form.validate_on_submit():
        user.name = manage_user_form.name.data
        user.email = manage_user_form.email.data
        user.username = manage_user_form.username.data
        user.level = int(manage_user_form.type.data)
        db.session.add(user)
        db.session.commit()
        flash("Success", "success")
        return redirect(url_for("admin.user_manage", uid=user.uid))
    return render_template("admin/manage-user.html", user=user, manage_user_form=manage_user_form)


@blueprint.route("/teams")
@blueprint.route("/teams/<int:page>")
@register_breadcrumb(blueprint, ".teams", "Teams")
@admin_required
def teams(page=1):
    if page < 1:
        return redirect(url_for("admin.teams", page=1))
    teams = Team.query.paginate(page, 20, False)
    if not teams.items:
        abort(404)
    return render_template("admin/teams.html", page=page, pages=teams.pages,
                           teams=teams.items)


@blueprint.route("/teams/manage/<int:tid>", methods=["GET", "POST"])
@admin_required
def team_manage(tid):
    team = Team.query.get_or_404(tid)
    manage_team_form = ManageTeamForm(tid=team.tid)
    if manage_team_form.validate_on_submit():
        manage_team_form.populate_obj(team)
        db.session.commit()
        flash("Updated team information.", "success")
        return redirect(url_for("admin.team_manage", tid=tid))
    else:
        manage_team_form.teamname.data = team.teamname
        manage_team_form.school.data = team.school
    return render_template("admin/manage-team.html", team=team,
                           manage_team_form=manage_team_form)


class ProblemForm(Form):
    pid = HiddenField("PID")
    author = StringField("Problem Author", validators=[
        InputRequired("Please enter the author.")])
    title = StringField("Problem Title", validators=[
        InputRequired("Please enter a problem title.")])
    name = StringField("Problem Name", validators=[
        InputRequired("Please enter a problem name.")])
    category = StringField("Problem Category", validators=[
        InputRequired("Please enter a problem category.")])
    description = TextAreaField("Description", validators=[
        InputRequired("Please enter a description.")])
    value = IntegerField("Value",
                         validators=[InputRequired("Please enter a value.")])
    programming = BooleanField(default=False, validators=[Optional()])

    autogen = BooleanField("Autogen", validators=[Optional()])
    grader = TextAreaField("Grader", validators=[
        InputRequired("Please enter a grader.")])
    generator = TextAreaField("Generator", validators=[Optional()])
    source_verifier = TextAreaField("Source Verifier", validators=[Optional()])

    test_cases = IntegerField("Test Cases", validators=[Optional()])
    time_limit = FloatField("Time Limit", validators=[Optional()])
    memory_limit = IntegerField("Memory Limit", validators=[Optional()])

    submit = SubmitField("Submit")

    def validate_name(self, field):
        if not util.VALID_PROBLEM_NAME.match(field.data):
            raise ValidationError(
                "Problem name must be an all-lowercase, slug-style string.")
        if Problem.query.filter(and_(Problem.name == field.data,
                                     Problem.pid != self.pid.data)).count():
            raise ValidationError("That problem name already exists.")

    def validate_grader(self, field):
        grader = imp.new_module("grader")
        if self.programming.data:
            # TODO validation
            pass
        else:
            try:
                exec (field.data, grader.__dict__)
                assert hasattr(grader, "grade"), \
                    "Grader is missing a 'grade' function."
                if self.autogen.data:
                    assert hasattr(grader, "generate"), \
                        "Grader is missing a 'generate' function."
                    seed1 = util.generate_string()
                    random.seed(seed1)
                    data = grader.generate(random)
                    assert type(data) is dict, "'generate' must return dict"
                else:
                    result = grader.grade(None, "")
                    assert type(result) is tuple, \
                        "'grade' must return (correct, message)"
                    correct, message = result
                    assert type(correct) is bool, \
                        "'correct' must be a boolean."
                    assert type(message) is str, \
                        "'message' must be a string."
            except Exception, e:
                raise ValidationError(
                    "%s: %s" % (e.__class__.__name__, str(e)))


class SettingsForm(Form):
    ctf_name = StringField("CTF Name", validators=[
        InputRequired("Please enter a CTF name.")])
    ctf_description = TextAreaField("CTF Description", validators=[])
    team_size = IntegerField("Team Size", default=5,
                             validators=[NumberRange(min=1), InputRequired(
                                 "Please enter a max team size.")])
    start_time = IntegerField("Start Time", validators=[
        InputRequired("Please enter a CTF start time.")])
    end_time = IntegerField("End Time", validators=[
        InputRequired("Please enter a CTF end time.")])

    stylesheet_url = StringField("Stylesheet URL",
                                 validators=[URL("Please enter a valid URL."),
                                             Optional()])

    judge_api_key = StringField("Judge API Key", validators=[Optional()])

    webhook_secret = StringField("Webhook Secret", validators=[Optional()])
    public_key = StringField("Public Key", validators=[Optional()])

    github_id = StringField("Github Client ID", validators=[Optional()])
    github_secret = StringField("Github Client Secret", validators=[
        Optional()])
    google_id = StringField("Google Client ID", validators=[Optional()])
    google_secret = StringField("Google Client Secret", validators=[
        Optional()])

    keywords = StringField("Keywords", validators=[Optional()])
    submit = SubmitField("Save Settings")

class ManageUserForm(Form):
    name = StringField("Name",
                       validators=[InputRequired("Please enter a name.")])
    username = StringField("Username", validators=[
        InputRequired("Please enter a username."),
        Length(3, 12,
               "Your username must be between 3 and 12 characters long.")])
    email = StringField("Email",
                        validators=[InputRequired("Please enter an email."),
                                    Email("Please enter a valid email.")])
    type = SelectField("Type: ", choices=[(str(_type), str(level)) for _type, level in zip(range(len(USER_LEVELS)), USER_LEVELS)])
    banned = BooleanField("Banned: ")
    silenced = BooleanField("Silenced: ")
    submit = SubmitField("Save")
