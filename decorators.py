"""
    server.decorators
    ~~~~~~~~~~~~~~~~~

    Platform-wide functions that are used to control the current user's
    access to certain endpoints based on their privileges as well as
    competition status (before competition, after competition).
"""

from datetime import datetime
from functools import wraps

from flask import abort, redirect, url_for
from flask import flash
from flask_login import current_user

from config import Config as AppConfig
from models import Config

EMAIL_VERIFICATION_REQUIRED = AppConfig().EMAIL_VERIFICATION_REQUIRED == 1


def admin_required(func):
    """
    Only allows users with admin privileges to access the endpoint that
    this function is wrapping. Users that are not logged in will also be
    denied access.

    :param func: The function that is to be wrapped.
    :return: The wrapped function.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        """ lul """
        if not (current_user.is_authenticated and current_user.admin):
            abort(403)
        return func(*args, **kwargs)

    return wrapper


def teacher_required(func):
    """
    Only allows teacher users to access the endpoint that this function is
    wrapping. Users that are not logged in will also be denied access.

    :param func: The function that is to be wrapped.
    :return: The wrapped function.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        """ lul """
        if not current_user.level == 3:
            abort(403)
        return func(*args, **kwargs)

    return wrapper


def email_verified_required(func):
    """
    Only allows users who have verified their emails to access the endpoint
    that this function is wrapping. Users that are not logged in will also
    be denied access.

    NB: If email verification has been disabled through environment
    variables, then this function will not do anything.

    :param func: The function that is to be wrapped.
    :return: The wrapped function.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        """ lul """
        if EMAIL_VERIFICATION_REQUIRED and not (
                current_user.is_authenticated and current_user.email_verified):
            flash("Please verify your email before continuing.", "warning")
            return redirect(url_for("users.settings"))
        return func(*args, **kwargs)

    return wrapper


def team_required(func):
    """
    Only allows users who have teams (created or joined a team) to access the
    endpoint that this function is wrapping. Users that are not logged in
    will also be denied access.

    :param func: The function that is to be wrapped.
    :return: The wrapped function.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        """ lul """
        if current_user.level != 3 and \
            (not hasattr(current_user, "team") or not current_user.tid):
            flash("You need a team to view this page!", "info")
            return redirect(url_for("teams.create"))
        return func(*args, **kwargs)

    return wrapper


def block_before_competition(func):
    """
    Denied access to the endpoint that this function is wrapping from users
    before the competition start time. The competition start time can be set
    in the administration panel.

    :param func: The function that is to be wrapped.
    :return: The wrapped function.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        """ lul """
        start_time = Config.get("start_time")
        if not start_time or not (
                current_user.is_authenticated and current_user.admin) and \
                datetime.utcnow() < datetime.fromtimestamp(int(start_time)):
            abort(403)
        return func(*args, **kwargs)

    return wrapper


def block_after_competition(func):
    """
    Denied access to the endpoint that this function is wrapping from users
    after the competition start time. The competition start time can be set in
    the administration panel.

    :param func: The function that is to be wrapped.
    :return: The wrapped function.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        """ lul """
        end_time = Config.get("end_time")
        if not end_time or not (
                current_user.is_authenticated and current_user.admin) \
            and datetime.utcnow() > datetime.fromtimestamp(
                int(end_time)):
            abort(403)
        return func(*args, **kwargs)

    return wrapper
