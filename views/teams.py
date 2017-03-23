import json

from flask import Blueprint, abort, flash, redirect, render_template, \
    url_for, current_app
from flask_login import current_user, login_required
from flask_wtf import FlaskForm as Form
from sqlalchemy import and_, func
from wtforms import ValidationError
from wtforms.fields import *
from wtforms.validators import *

from constants import *
from decorators import email_verified_required
from models import Config, School, Team, TeamInvitation, User, db

blueprint = Blueprint("teams", __name__, template_folder="templates")


@blueprint.route("/accept/<int:id>")
@email_verified_required
@login_required
def accept(id):
    max_size = int(Config.get("team_size"))
    invitation = TeamInvitation.query.filter_by(id=id).first()
    if not invitation:
        flash("Invitation not found.", "danger")
        return redirect(url_for("teams.create"))
    if invitation.type == INVITATION_TO_USER:
        if current_user.team:
            flash("You're already part of a team.", "danger")
            return redirect(url_for("teams.profile"))
        if current_user.uid != invitation._to:
            flash("This invitation isn't for you.", "danger")
            return redirect(url_for("teams.create"))
        if not invitation.fr.admin and invitation.fr.size >= max_size:
            flash("This team has reached the team member limit!", "danger")
            return redirect(url_for("teams.create"))
        db.session.delete(invitation)
        current_user.tid = invitation._fr
        db.session.add(current_user)
        db.session.commit()
        flash("Successfully joined the team!", "success")
        return redirect(url_for("teams.profile"))
    elif invitation.type == INVITATION_TO_TEAM:
        if not current_user.team:
            flash("You're not in a team.", "danger")
            return redirect(url_for("teams.create"))
        if not (current_user.uid == current_user.team.owner):
            flash("You're not the owner of your team.", "danger")
            return redirect(url_for("teams.profile"))
        if not current_user.team.admin and current_user.team.size >= max_size:
            flash("You've reached the max team member limit!", "danger")
            return redirect(url_for("teams.profile"))
        user = invitation.fr
        db.session.delete(invitation)
        user.tid = current_user.tid
        db.session.add(user)
        db.session.commit()
        flash("Successfully accepted this member!", "success")
        return redirect(url_for("teams.profile"))


@blueprint.route("/create", methods=["GET", "POST"])
@email_verified_required
@login_required
def create():
    if current_user.tid:
        return redirect(url_for("teams.profile"))
    create_team_form = CreateTeamForm(prefix="create")
    if create_team_form.validate_on_submit():
        new_team = create_team(create_team_form)
        current_app.logger.info("Created team '%s' (id=%s)!" %
                                (new_team.teamname, new_team.tid))
        return redirect(url_for("teams.profile"))
    return render_template("teams/create.html",
                           create_team_form=create_team_form)


@blueprint.route("/profile", methods=["GET", "POST"])
@blueprint.route("/profile/<int:tid>", methods=["GET", "POST"])
def profile(tid=None):
    add_member_form = AddMemberForm(prefix="add-member")
    disband_team_form = DisbandTeamForm(prefix="disband-team")
    manage_team_form = None
    if tid is None and current_user.is_authenticated:
        if current_user.tid is None:
            return redirect(url_for("teams.create"))
        else:
            return redirect(url_for("teams.profile", tid=current_user.tid))
    team = Team.get_by_id(tid)
    if current_user.is_authenticated and current_user.uid == team.owner:
        manage_team_form = ManageTeamForm(prefix="manage-team",
                                          tid=current_user.tid)
    if team is None:
        abort(404)
    if add_member_form.submit.data and add_member_form.validate_on_submit():
        invite = TeamInvitation(type=INVITATION_TO_USER, fr=tid,
                                to=add_member_form.get_user().uid)
        db.session.add(invite)
        db.session.commit()
        return redirect(url_for("teams.profile", tid=tid))
    elif disband_team_form.submit.data and disband_team_form.validate_on_submit():
        Team.query.filter_by(tid=current_user.tid).update(dict(owner=None))
        User.query.filter_by(tid=current_user.tid).update(dict(tid=None))
        db.session.commit()
        return redirect(url_for("teams.profile", tid=tid))
    elif manage_team_form and manage_team_form.submit.data and manage_team_form.validate_on_submit():
        manage_team_form.populate_obj(current_user.team)
        db.session.commit()
        return redirect(url_for("teams.profile", tid=tid))
    kwargs = {"team": team}
    if current_user.is_authenticated and current_user.uid == team.owner:
        manage_team_form.teamname.data = team.teamname
        manage_team_form.school.data = team.school
        kwargs["add_member_form"] = add_member_form
        kwargs["disband_team_form"] = disband_team_form
        kwargs["manage_team_form"] = manage_team_form
    return render_template("teams/profile.html", **kwargs)


@blueprint.route("/evict/<int:uid>")
@login_required
def evict(uid):
    return abort(404)
    if not current_user.team:
        flash("You're not in a team.", "danger")
        return redirect(url_for("teams.create"))
    if current_user.uid == uid:
        if current_user.team.owner != current_user.uid:
            current_user.tid = None
            db.session.add(current_user)
            db.session.commit()
            flash("Successfully left the team.", "success")
            return redirect(url_for("teams.create"))
        else:
            flash("You can't remove yourself if you are the captain.",
                  "danger")
            return redirect(url_for("teams.profile"))
    if current_user.team.owner != current_user.uid:
        flash("You're not allowed to make this change.", "danger")
        return redirect(url_for("teams.profile"))
    user = User.get_by_id(uid)
    if not user:
        flash("This user doesn't exist.", "danger")
        return redirect(url_for("teams.profile"))
    user.tid = None
    db.session.add(user)
    db.session.commit()
    flash("Successfully evicted the user.", "success")
    return redirect(url_for("teams.profile"))


@blueprint.route("/request/<int:tid>")
@login_required
def request(tid):
    if current_user.team:
        flash("You're already in a team.", "danger")
        return redirect(url_for("teams.profile", tid=tid))
    invites = TeamInvitation.query.filter_by(type=INVITATION_TO_TEAM, to=tid)
    if invites.count() >= int(Config.get("team_size")):
        flash("This team already has the maximum number of requests.",
              "danger")
        return redirect(url_for("teams.profile", tid=tid))
    invite = TeamInvitation.query.filter_by(type=INVITATION_TO_TEAM,
                                            _fr=current_user.uid, to=tid)
    if invite.count():
        flash("You've already sent a request.", "danger")
        return redirect(url_for("teams.profile", tid=tid))
    invite = TeamInvitation(type=INVITATION_TO_TEAM, fr=current_user.uid,
                            to=tid)
    db.session.add(invite)
    db.session.commit()
    flash("Successfully sent request!", "success")
    return redirect(url_for("teams.profile", tid=tid))


@blueprint.route("/schools")
@login_required
def schools():
    schools = School.query.all()
    return json.dumps(
        [dict((key, getattr(school, key)) for key in ["name"]) for school in
         schools])


def create_team(form):
    new_team = Team(owner=current_user.uid)
    db.session.add(new_team)
    db.session.commit()
    current_user.tid = new_team.tid
    form.populate_obj(current_user.team)
    db.session.add(current_user)
    db.session.commit()
    return new_team


class AddMemberForm(Form):
    username = StringField("Username", validators=[InputRequired(
        "Please enter the username of the person you would like to add.")])
    submit = SubmitField("Add")

    def get_user(self):
        query = User.query.filter(
            func.lower(User.username) == self.username.data.lower())
        return query.first()

    def validate_username(self, field):
        if not current_user.team:
            raise ValidationError("You must belong to a team.")
        if current_user.team.owner != current_user.uid:
            raise ValidationError(
                "Only the team captain can invite new members.")
        invites = TeamInvitation.query.filter_by(type=INVITATION_TO_USER,
                                                 _fr=current_user.tid)
        if not current_user.team.admin and invites.count() >= int(Config.get("team_size")):
            raise ValidationError(
                "You've already sent the maximum number of invitations.")
        user = User.query.filter(
            func.lower(User.username) == field.data.lower()).first()
        if user is None:
            raise ValidationError("This user doesn't exist.")
        if user.tid is not None:
            raise ValidationError("This user is already a part of a team.")
        if current_user.team.pending_invitations(to=user.uid):
            raise ValidationError("You've already invited this member.")


class CreateTeamForm(Form):
    teamname = StringField("Team Name", validators=[
        InputRequired("Please create a team name."),
        Length(3, 24,
               "Your teamname must be between 3 and 24 characters long.")])
    school = StringField("School", validators=[
        InputRequired("Please enter your school."),
        Length(3, 36,
               "Your school name must be between 3 and 36 characters long." +
               "Use abbreviations if necessary.")])
    submit = SubmitField("Create Team")

    def validate_teamname(self, field):
        if current_user.tid is not None:
            raise ValidationError("You are already in a team.")
        if Team.query.filter(
                func.lower(Team.teamname) == field.data.lower()).count():
            raise ValidationError("Team name is taken.")


class DisbandTeamForm(Form):
    teamname = StringField("Confirm Team Name")
    submit = SubmitField("Delete Team")

    def validate_teamname(self, field):
        if not current_user.team:
            raise ValidationError("You must belong to a team.")
        if current_user.team.owner != current_user.uid:
            raise ValidationError(
                "Only the team captain can disband the team.")
        if field.data != current_user.team.teamname:
            raise ValidationError("Incorrect confirmation.")


class ManageTeamForm(Form):
    teamname = StringField("Team Name", validators=[
        InputRequired("Please create a team name."),
        Length(3, 24,
               "Your teamname must be between 3 and 24 characters long.")])
    school = StringField("School", validators=[
        InputRequired("Please enter your school."),
        Length(3, 36,
               "Your school name must be between 3 and 36 characters long." +
               "Use abbreviations if necessary.")])
    submit = SubmitField("Update")

    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(*args, **kwargs)
        self.tid = kwargs.get("tid", None)

    def validate_teamname(self, field):
        if Team.query.filter(
            and_(func.lower(Team.teamname) == field.data.lower(),
                 Team.tid != self.tid)).count():
            raise ValidationError("Team name is taken.")
