import json

from flask import Blueprint, abort, flash, redirect, request, render_template, url_for
from flask_login import current_user, login_required
from flask_wtf import Form
from wtforms import ValidationError
from wtforms.fields import *
from wtforms.validators import *

import constants
from datetime import datetime
from judge_api import judge_api, SUPPORTED_LANGUAGES
from decorators import block_before_competition, team_required
from models import  Problem, Solve, User, cache, db

blueprint = Blueprint("problems", __name__, template_folder="templates")


@blueprint.route("/", methods=["GET", "POST"])
@block_before_competition
@team_required
@login_required
def list():
    problems = current_user.team.get_unlocked_problems()
    problem_submit_form = ProblemSubmitForm()
    if problem_submit_form.validate_on_submit():
        pid = int(problem_submit_form.pid.data)
        problem = Problem.get_by_id(pid)
        if problem is None or not is_unlocked(problem, current_user.tid):
            flash("Problem not found.", ("info"))
            return redirect(url_for("problems.list"))
        solved = Solve.query.filter_by(tid=current_user.tid, pid=pid,
                                       correct=True).count()
        if solved:
            flash("You've already solved this problem.", ("info"))
            return redirect(url_for("problems.list"))
        already_tried = Solve.query.filter_by(tid=current_user.tid, pid=pid,
                                              correct=False,
                                              flag=problem_submit_form.flag.data).count()
        # if already_tried:
        #     flash("You've already tried this flag.", ("info"))
        #     return redirect(url_for("problems.list"))
        random = None
        if problem.autogen:
            random = problem.get_autogen(current_user.tid)
        grader = problem.get_grader()
        correct, message = grader.grade(random, problem_submit_form.flag.data)
        submission = Solve(pid=pid, tid=current_user.tid, uid=current_user.uid,
                           correct=correct, flag=problem_submit_form.flag.data)
        db.session.add(submission)
        db.session.commit()
        cache.delete_memoized(current_user.team.place)
        cache.delete_memoized(current_user.team.points)
        cache.delete_memoized(current_user.team.get_last_solved)
        cache.delete_memoized(current_user.team.get_score_progression)
        flash(message, ("success" if correct else "danger"))
        return redirect(url_for("problems.list"))
    return render_template("problems/list.html", problems=problems,
                           problem_submit_form=problem_submit_form)


@blueprint.route("/game")
@block_before_competition
@team_required
@login_required
def game():
    return render_template("problems/game.html")


@blueprint.route("/solves/<int:pid>")
@block_before_competition
def solves(pid):
    problem = Problem.query.filter_by(pid=pid).first()
    if not problem:
        abort(404)
    return render_template("problems/solves.html", problem=problem,
                           solves=problem.solves)


@blueprint.route("/programming", methods=["GET", "POST"])
@blueprint.route("/programming/<int:pid>", methods=["GET", "POST"])
@block_before_competition
@team_required
@login_required
def programming(pid=None):
    if not pid:
        problems = current_user.team.get_unlocked_problems(programming=True)
        if not problems:
            return redirect(url_for("problems.list"))
        return redirect(url_for("problems.programming", pid=problems[0].pid))
    problem = Problem.get_by_id(pid)
    if not current_user.team.has_unlocked(problem) or not problem.programming:
        return redirect(url_for("problems.list"))

    programming_submit_form = ProgrammingSubmitForm()
    if programming_submit_form.validate_on_submit():
        problem = Problem.query.filter_by(name=problem.name,
                                          programming=True).first()
        if not problem:
            return redirect(url_for("problems.list"))

        result = judge_api.submissions_create(
            problem_id=problem.pid,
            language=programming_submit_form.language.data,
            code=programming_submit_form.code.data,
            gid=current_user.tid,
            uid=current_user.uid,

            callback_url="http://judge_hook" + url_for('problems.judge_submit', nonce='asfdasdfijeru94835798skjdv2983iufskjdbs98342yskjdb'),
        )
        if not result.is_ok():
            abort(500)
        submission_id = result.data['id']
        flash("Code was sent! Refresh the page for updates.", "success")
        return redirect(url_for("problems.submission", id=submission_id))
    problems = current_user.team.get_unlocked_problems(programming=True)
    return render_template("problems/programming.html", problem=problem,
                           problems=problems,
                           programming_submit_form=programming_submit_form)


import logging

# TODO: make this not-horrible
@blueprint.route("/programming/judge_submit/<string:nonce>", methods=["POST"])
def judge_submit(nonce):
    if nonce != 'asfdasdfijeru94835798skjdv2983iufskjdbs98342yskjdb':
        abort(503)
    submission_id = int(request.form['submission_id'])
    submission = judge_api.submissions_details(submission_id)
    if request.form['verdict'] == 'JobVerdict.accepted' and not Solve.query.filter_by(tid=submission.data['gid'], pid=submission.data['problem_id'], correct=True).count():
        date = datetime.strptime(request.form['creation_time'], "%Y-%m-%d %H:%M:%S")
        solve = Solve(pid=int(submission.data['problem_id']), tid=int(submission.data['gid']), uid=int(submission.data['uid']),
              correct=True, flag=None, _date=date)
        db.session.add(solve)
        db.session.commit()
    return ''


@blueprint.route("/programming/status")
@block_before_competition
@team_required
@login_required
def status():
    submissions_response = judge_api.submissions_list_by_gid(current_user.tid)
    if not submissions_response.is_ok():
        return abort(500)
    submissions = submissions_response.data
    for submission in submissions:
        submission["user"] = User.query.get(submission["uid"])
        submission["problem"] = Problem.query.get(submission["problem_id"])
    submissions = [submission for submission in submissions if submission["problem"]]
    return render_template("problems/status.html", submissions=submissions)


@blueprint.route("/programming/submission/<int:id>")
@block_before_competition
@team_required
@login_required
def submission(id):
    submission_response = judge_api.submissions_details(id)
    if not submission_response.is_ok():
        return abort(404)
    submission = submission_response.data
    problem = Problem.query.get(submission['problem_id'])
    user = User.query.get(submission['uid'])
    if submission["gid"] != current_user.tid:
        return abort(403)
    return render_template("problems/submission.html", problem=problem, submission=submission, user=user)


def is_unlocked(problem, tid):
    solves = Solve.query.filter_by(tid=tid, correct=True).all()
    if not problem.weightmap:
        return True
    current = sum([problem.weightmap.get(solve.pid, 0) for solve in solves])
    return current > problem.threshold


class ProblemSubmitForm(Form):
    pid = HiddenField("Problem ID")
    flag = StringField("Flag",
                       validators=[InputRequired("Please enter a flag.")])


class ProgrammingSubmitForm(Form):
    pid = HiddenField()
    code = TextAreaField("Code",
                         validators=[InputRequired("Please enter code.")])
    language = HiddenField()

    def validate_language(self, field):
        if field.data not in SUPPORTED_LANGUAGES:
            raise ValidationError("Invalid language.")

    def validate_code(self, field):
        if len(field.data) > 65536:
            raise ValidationError("Code too large! (64KB max)")
