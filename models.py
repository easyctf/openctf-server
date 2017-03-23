"""
    server.models
    ~~~~~~~~~~~~~

    Contains all the models that are used by the platform.
"""

import base64
import imp
import os
import re
import time
from cStringIO import StringIO
from datetime import datetime
from string import Template

import onetimepass
import paramiko
import requests
from Crypto.PublicKey import RSA
from flask import current_app as app
from flask_breadcrumbs import Breadcrumbs
from flask_cache import Cache
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from markdown2 import markdown
from passlib.hash import bcrypt
from sqlalchemy import and_, select, func
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql.expression import union_all
from sqlalchemy.orm import backref

import constants
import util
from config import Config as AppConfig

# pylint: disable=invalid-name
breadcrumbs = Breadcrumbs()
db = SQLAlchemy()
login_manager = LoginManager()
cache = Cache()
# pylint: enable=invalid-name

SEED = "OPENCTF_PROBLEM_SEED_PREFIX_%s" % AppConfig().SECRET_KEY
login_manager.login_view = "users.login"
login_manager.login_message_category = "danger"

new_user_pattern = re.compile("user\{(user[\d]{5}):([a-zA-Z0-9]+)\}")


def filename_filter(name):
    """
    Cleans a file name (or any string, really) so it can be used in a
    string template. This is for problem descriptions, into which generated
    variables are injected.

    More specifically, it only allows [a-zA-Z0-9] characters to remain in the
    string, replacing all other characters with an underscore (_).

    :param name: The file name to be replaced.
    :return: The cleaned up filename.
    :rtype: str
    """
    return re.sub("[^a-zA-Z0-9]+", "_", name)


# pylint: disable=invalid-name
team_classroom = db.Table('team_classroom',
                          db.Column('team_id', db.Integer,
                                    db.ForeignKey('teams.tid'),
                                    nullable=False),
                          db.Column('classroom_id', db.Integer,
                                    db.ForeignKey('classrooms.id'),
                                    nullable=False),
                          db.PrimaryKeyConstraint('team_id', 'classroom_id'))
classroom_invitation = db.Table('classroom_invitation',
                                db.Column('team_id', db.Integer,
                                          db.ForeignKey('teams.tid'),
                                          nullable=False),
                                db.Column('classroom_id', db.Integer,
                                          db.ForeignKey('classrooms.id'),
                                          nullable=False),
                                db.PrimaryKeyConstraint('team_id',
                                                        'classroom_id'))


# pylint: enable=invalid-name


class Config(db.Model):
    """
    Represents a single key-value pair in the configuration of the
    platform. All keys and values are strings and cid is kinda useless but
    nice to have.
    """

    __tablename__ = "config"
    cid = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.Unicode(32), index=True)
    value = db.Column(db.Text)

    def __init__(self, key, value):
        """
        Creates a new Config object with the specified key and value.

        :param key: The key of the new Config object.
        :param value: The value of the new Config object.
        """

        self.key = key
        self.value = value

    @classmethod
    def get(cls, key, default=None):
        """
        Retrieves the value for key from the database, defaulting to
        `default` if no row in the Config table contains the key `key`.

        :param key: The key to look up.
        :param default: (optional) The value to return should the key not
            exist in the database.
        :return: The value corresponding to `key`.
        """

        config = cls.query.filter_by(key=key).first()
        if config is None:
            return default
        return str(config.value)

    @classmethod
    def set(cls, key, value):
        """
        Sets the value of the key `key` to `value`. This will create a
        Config object in the database if it doesn't already exist, and will
        overwrite any existing key-value pair with the same `key`.

        :param key: The key to store the value in.
        :param value: The value to store.
        """
        config = cls.query.filter_by(key=key).first()
        if config is None:
            config = Config(key, value)
        db.session.add(config)
        db.session.commit()

    @classmethod
    def set_many(cls, configs):
        """
        Sets many key-value pairs from a dictionary.

        :param configs: A dictionary containing the key-value pairs that
            will be written to the database.
        :type configs: dict
        """
        for key, value in configs.items():
            config = cls.query.filter_by(key=key).first()
            if config is None:
                config = Config(key, value)
            config.value = value
            db.session.add(config)
        db.session.commit()

    @classmethod
    def get_ssh_keys(cls):
        """
        Retrieves (or generates, if one doesn't already exist) a key pair (
        public and private) for the current machine, used to clone a Git
        repository for importing problems.

        :return: An ordered pair (private_key, public_key).
        :rtype: tuple
        """
        private_key = cls.get("private_key")
        public_key = cls.get("public_key")
        if not (private_key and public_key):
            key = RSA.generate(2048)
            private_key = key.exportKey("PEM")
            public_key = key.publickey().exportKey("OpenSSH")
            cls.set_many({
                "private_key": private_key,
                "public_key": public_key
            })
        return private_key, public_key


class User(db.Model):
    """
    Represents a user.
    """

    __tablename__ = "users"
    uid = db.Column(db.Integer, index=True, primary_key=True)
    tid = db.Column(db.Integer, db.ForeignKey("teams.tid"))
    name = db.Column(db.Unicode(32))
    username = db.Column(db.String(16), unique=True, index=True)
    email = db.Column(db.String(128), unique=True)
    _password = db.Column("password", db.String(128))
    admin = db.Column(db.Boolean, default=False)
    level = db.Column(db.Integer)
    _register_time = db.Column("register_time", db.DateTime,
                               default=datetime.utcnow)
    reset_token = db.Column(db.String(32))
    otp_secret = db.Column(db.String(16))
    otp_confirmed = db.Column(db.Boolean, default=False)
    email_token = db.Column(db.String(32))
    email_verified = db.Column(db.Boolean, default=False)
    _avatar = db.Column("avatar", db.String(128))

    team = db.relationship("Team", back_populates="members")
    _solves = db.relationship("Solve", back_populates="user", lazy="subquery")

    @property
    def solves(self):
        s = dict()
        for solve in self._solves:
            if not solve.correct:
                continue
            s[solve.problem.pid] = solve
        return [s[k] for k in s]

    ctfcal_id = db.Column(db.String(64))
    github_id = db.Column(db.String(64))
    google_id = db.Column(db.String(64))

    def __eq__(self, other):
        """
        Compares a user to another user by id.

        :param other: Another user to compare to.
        :type other: User
        :return: Whether or not the two users are the same.
        :rtype: bool
        """
        if isinstance(other, User):
            return self.uid == other.uid
        return NotImplemented

    def __str__(self):
        return "<User %s>" % self.uid

    def check_password(self, password):
        """
        Uses bcrypt to check if the given password matches the current
        user's password.

        :param password: The password to check.
        :return: Whether the password is correct.
        :rtype: bool
        """
        return bcrypt.verify(password, self.password)

    def get_id(self):
        """
        why do we have this again?

        :return: A string representation of this User's id.
        """
        return str(self.uid)

    @property
    def is_anonymous():
        return False

    @staticmethod
    @login_manager.user_loader
    def get_by_id(id):
        """
        Gets a User by his id. Used by Flask-Login to retrieve the User
        based on the id that is stored in the session.

        :param id: The id of the User to look up.
        :return: A User object corresponding to the id, if the id exists,
            otherwise None.
        """
        query_results = User.query.filter_by(uid=id)
        return query_results.first() if query_results.count() else None

    @property
    def is_active(self):
        """
        Gets whether or not the user is allowed to login. Used by
        Flask-Login to determine whether to allow the user to login or not.

        So far, this hasn't been implemented yet (always return true),
        but this will be based off account standing.

        :return: Whether the user is allowed to login.
        :rtype: bool
        """
        # TODO This will be based off account standing.
        return True

    @property
    def is_authenticated(self):
        """
        Gets whether or not the user is authenticated. Used by Flask-Login
        to determine whether the user is authenticated or not.

        :return: Whether the user is authenticated.
        :rtype: bool
        """
        return True

    @hybrid_property
    def password(self):
        """
        Gets the user's hashed password as it appears in the database. This
        method only exists so the password field has a setter function.

        :return: The user's hashed password.
        """
        return self._password

    @password.setter
    def password(self, password):
        """
        Hashes the password and sets the hash as the user's current
        password in the database, using bcrypt. By default, it goes 10 rounds.

        :param password:
        :return:
        """
        self._password = bcrypt.encrypt(password, rounds=10)

    @hybrid_property
    def register_time(self):
        """
        Gets the time (in seconds since the epoch) that the user created
        his account.

        :return: The time that the user created his account, in seconds.
        :rtype: int
        """
        return int(time.mktime(self._register_time.timetuple()))

    @property
    def avatar(self):
        """
        Gets the URL for the user's current avatar. If the user doesn't
        have an avatar, then it will generate and use an identicon instead.
        Avatar images (and identicons) are stored into and served from the
        filestore server.

        :return: The user's avatar's URL.
        """
        if not self._avatar:
            avatar_file = StringIO()
            avatar = util.generate_identicon(self.email)
            avatar.save(avatar_file, format="PNG")
            avatar_file.seek(0)
            response = requests.post("http://filestore:8000/save",
                                     data={"prefix": "avatar"},
                                     files={"file": avatar_file})
            if response.status_code == 200:
                self._avatar = "/static/%s" % response.text
                db.session.add(self)
                db.session.commit()
        return self._avatar

    def pending_invitations(self, fr=None):
        if fr is not None:
            return TeamInvitation.query.filter_by(
                type=constants.INVITATION_TO_USER, _fr=fr,
                _to=self.uid).first()
        else:
            return TeamInvitation.query.filter_by(
                type=constants.INVITATION_TO_USER, _to=self.uid).all()

    def pending_requests(self, to=None):
        if to is not None:
            return TeamInvitation.query.filter_by(
                type=constants.INVITATION_TO_TEAM, _fr=self.uid,
                _to=to).first()
        else:
            return TeamInvitation.query.filter_by(
                type=constants.INVITATION_TO_TEAM, _fr=self.uid).all()

    @hybrid_property
    def username_lower(self):
        return self.username.lower()

    def get_totp_uri(self):
        if self.otp_secret is None:
            secret = base64.b32encode(os.urandom(10)).decode("utf-8").lower()
            self.otp_secret = secret
            db.session.add(self)
            db.session.commit()
        service_name = Config.get("ctf_name")
        return "otpauth://totp/%s:%s?secret=%s&issuer=%s" % (
            service_name, self.username, self.otp_secret, service_name)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    @cache.memoize(timeout=120)
    def points(self):
        points = 0
        for solve in self.solves:
            points += solve.problem.value
        return points


class Problem(db.Model):
    __tablename__ = "problems"
    pid = db.Column(db.Integer, index=True, primary_key=True)
    author = db.Column(db.Unicode(32))
    name = db.Column(db.String(32), unique=True)
    title = db.Column(db.Unicode(64))
    description = db.Column(db.Text)
    hint = db.Column(db.Text)
    category = db.Column(db.Unicode(64))
    value = db.Column(db.Integer)

    grader = db.Column(db.UnicodeText)
    autogen = db.Column(db.Boolean)
    programming = db.Column(db.Boolean)
    threshold = db.Column(db.Integer)
    weightmap = db.Column(db.PickleType)

    _solves = db.relationship(
        "Solve", back_populates="problem", lazy="subquery")

    @property
    def solves(self):
        s = dict()
        for solve in self._solves:
            if not solve.correct:
                continue
            s[solve.tid] = solve
        return [s[k] for k in s]

    def __str__(self):
        return "<Problem %d>" % self.pid

    @staticmethod
    def get_by_id(id):
        query_results = Problem.query.filter_by(pid=id)
        return query_results.first() if query_results.count() else None

    @property
    def solved(self):
        return Solve.query.filter_by(pid=self.pid, tid=current_user.tid,
                                     correct=True).count()

    def get_grader(self):
        grader = imp.new_module("grader")
        exec (self.grader, grader.__dict__)
        return grader

    def get_autogen(self, tid):
        autogen = __import__("random")
        autogen.seed("%s_%s_%s" % (SEED, self.pid, tid))
        return autogen

    def render_description(self, tid):
        description = markdown(self.description, extras=["fenced-code-blocks"])
        try:
            variables = {}
            template = Template(description)
            if self.autogen:
                autogen = self.get_autogen(tid)
                grader = self.get_grader()
                generated_problem = grader.generate(autogen)
                if "variables" in generated_problem:
                    variables.update(generated_problem["variables"])
                if "files" in generated_problem:
                    for file in generated_problem["files"]:
                        file_object = AutogenFile. \
                            query.filter_by(pid=self.pid,
                                            tid=tid,
                                            filename=file).first()
                        if file_object is None:
                            data = generated_problem["files"][file](autogen)
                            file_object = AutogenFile(pid=self.pid, tid=tid,
                                                      filename=file, data=data)
                            db.session.add(file_object)
                            db.session.commit()
                        file = AutogenFile.clean_name(file)
                        variables[file] = file_object.url
            static_files = File.query.filter_by(pid=self.pid).all()
            if static_files is not None:
                for file in static_files:
                    variables[File.clean_name(file.filename)] = file.url
            description = template.safe_substitute(variables)
        except:
            description += "*parsing error*"
        return description


class File(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, index=True, primary_key=True)
    pid = db.Column(db.Integer, index=True)
    filename = db.Column(db.Unicode(64))
    url = db.Column(db.String(128))

    @staticmethod
    def clean_name(name):
        return filename_filter(name)

    def __init__(self, pid, filename, data):
        self.pid = pid
        self.filename = filename
        data.seek(0)
        if not app.config.get("TESTING"):
            response = requests.post("http://filestore:8000/save",
                                     data={"suffix": "%s" % filename},
                                     files={"file": data})
            if response.status_code == 200:
                self.url = "/static/%s" % response.text


class AutogenFile(db.Model):
    __tablename__ = "autogen_files"
    id = db.Column(db.Integer, index=True, primary_key=True)
    pid = db.Column(db.Integer, index=True)
    tid = db.Column(db.Integer, index=True)
    filename = db.Column(db.Unicode(64))
    url = db.Column(db.String(128))

    @staticmethod
    def clean_name(name):
        return filename_filter(name)

    def __init__(self, pid, tid, filename, data):
        self.pid = pid
        self.tid = tid
        self.filename = filename
        data.seek(0)
        if not app.config.get("TESTING"):
            response = requests.post("http://filestore:8000/save",
                                     data={"suffix": "%s" % filename},
                                     files={"file": data})
            if response.status_code == 200:
                self.url = "/static/%s" % response.text


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Integer, db.ForeignKey("users.uid"), index=True)
    active = db.Column(db.Boolean)
    token = db.Column(db.String(length=16),
                      default=lambda: util.generate_string(length=16))
    email = db.Column(db.Unicode(length=128))
    expire = db.Column(db.DateTime)

    @property
    def expired(self):
        return datetime.utcnow() >= self.expire

    @property
    def user(self):
        return User.get_by_id(self.uid)


class Solve(db.Model):
    __tablename__ = "solves"
    id = db.Column(db.Integer, index=True, primary_key=True)
    pid = db.Column(db.Integer, db.ForeignKey("problems.pid"), index=True)
    tid = db.Column(db.Integer, db.ForeignKey("teams.tid"), index=True)
    uid = db.Column(db.Integer, db.ForeignKey("users.uid"), index=True)
    _date = db.Column("date", db.DateTime, default=datetime.utcnow)
    correct = db.Column(db.Boolean)
    flag = db.Column(db.Text)

    user = db.relationship("User", back_populates="_solves", lazy="subquery")
    team = db.relationship("Team", back_populates="_solves", lazy="subquery")
    problem = db.relationship(
        "Problem", back_populates="_solves", lazy="subquery")

    @hybrid_property
    def date(self):
        return int(time.mktime(self._date.timetuple()))

    @date.expression
    def date_expression(self):
        return self._date


class Team(db.Model):
    __tablename__ = "teams"
    tid = db.Column(db.Integer, primary_key=True, index=True)
    teamname = db.Column(db.Unicode(32), unique=True)
    sid = db.Column(db.Integer, db.ForeignKey("schools.id"))
    _school = db.relationship("School", back_populates="teams")
    owner = db.Column(db.Integer)
    classrooms = db.relationship('Classroom', secondary=team_classroom,
                                 backref='classrooms')
    classroom_invites = db.relationship('Classroom',
                                        secondary=classroom_invitation,
                                        backref='classroom_invites')
    members = db.relationship("User", back_populates="team")
    admin = db.Column(db.Boolean, default=False)
    shell_user = db.Column(db.String(16), unique=True)
    shell_pass = db.Column(db.String(32))

    _solves = db.relationship("Solve", back_populates="team", lazy="subquery")

    @property
    def solves(self):
        s = dict()
        for solve in self._solves:
            if not solve.correct:
                continue
            s[solve.problem.pid] = solve
        return [s[k] for k in s]

    def __repr__(self):
        return "%s_%s" % (self.__class__.__name__, self.tid)

    def __str__(self):
        return "<Team %s>" % self.tid

    @property
    def school(self):
        return self._school

    def __setattr__(self, key, value):
        if key == "school":
            value = value.strip()
            school = School.query.filter(
                func.lower(School.name) == value.lower()).first()
            if not school:
                school = School(name=value)
                db.session.add(school)
                db.session.commit()
            self.sid = school.id
            db.session.commit()
        else:
            db.Model.__setattr__(self, key, value)

    @staticmethod
    def get_by_id(id):
        query_results = Team.query.filter_by(tid=id)
        return query_results.first() if query_results.count() else None

    @property
    def size(self):
        return User.query.filter_by(tid=self.tid).count()

    @hybrid_property
    def observer(self):
        return self.size == 0 or \
            User.query.filter(and_(User.tid == self.tid,
                                   User.level != constants.USER_REGULAR)) \
                   .count()

    @hybrid_property
    def prop_points(self):
        return sum(problem.value for problem, solve in db.session.query(Problem, Solve).filter(Solve.tid == self.tid).filter(Problem.pid == Solve.tid).all())
        # return func.sum(solve.problem.value for solve in self.solves)

    @prop_points.expression
    def prop_points(self):
        return db.session.query(Problem, Solve).filter(Solve.tid == self.tid).filter(Problem.pid == Solve.tid)\
            .with_entities(func.sum(Problem.value)).scalar()

    @cache.memoize(timeout=120)
    def points(self):
        points = 0
        solves = self.solves
        solves.sort(key=lambda s: s.date, reverse=True)
        for solve in solves:
            problem = Problem.query.filter_by(pid=solve.pid).first()
            points += problem.value
        return points

    @cache.memoize(timeout=120)
    def place(self):
        scoreboard = Team.scoreboard()
        if not self.observer:
            scoreboard = filter(lambda team: not team.observer, scoreboard)
        i = 0
        for i in range(len(scoreboard)):
            if scoreboard[i].tid == self.tid:
                break
        i += 1
        k = i % 10
        return i, "%d%s" % (i, "tsnrhtdd"[(i / 10 % 10 != 1) * (k < 4) * k::4])

    @hybrid_property
    def prop_last_solved(self):
        solve = Solve.query.filter_by(
            tid=self.tid).order_by(Solve.date).first()
        if not solve:
            return 0
        return solve.date

    @cache.memoize(timeout=120)
    def get_last_solved(self):
        solves = self.solves
        solves.sort(key=lambda s: s.date, reverse=True)
        if solves:
            solve = solves[0]
            return solve.date if solve else 0
        return 0

    def pending_invitations(self, to=None):
        if to is not None:
            return TeamInvitation.query.filter_by(
                type=constants.INVITATION_TO_USER, _fr=self.tid,
                _to=to).first()
        else:
            return TeamInvitation.query.filter_by(
                type=constants.INVITATION_TO_USER, _fr=self.tid).all()

    def pending_requests(self, fr=None):
        if fr is not None:
            return TeamInvitation.query.filter_by(
                type=constants.INVITATION_TO_TEAM, _fr=fr,
                _to=self.tid).first()
        else:
            return TeamInvitation.query.filter_by(
                type=constants.INVITATION_TO_TEAM, _to=self.tid).all()

    def has_unlocked(self, problem):
        solves = Solve.query.filter_by(tid=self.tid, correct=True).all()
        if not problem.weightmap:
            return True
        current = sum(
            [problem.weightmap.get(solve.pid, 0) for solve in solves])
        return current >= problem.threshold

    def get_unlocked_problems(self, admin=False, programming=None):
        match = {}
        if programming is not None:
            match["programming"] = programming
        problems = Problem.query.filter_by(**match).order_by(
            Problem.value).all()
        if admin:
            return problems
        solves = Solve.query.filter_by(tid=self.tid, correct=True).all()

        def unlocked(problem):
            if not problem.weightmap:
                return True
            current = sum(
                [problem.weightmap.get(solve.pid, 0) for solve in solves])
            return current >= problem.threshold

        return filter(unlocked, problems)

    def get_jobs(self):
        return Job.query.filter_by(tid=self.tid).order_by(
            Job.completion_time.desc()).all()

    def has_solved(self, pid):
        return Solve.query.filter_by(tid=self.tid, pid=pid,
                                     correct=True).count() > 0

    @classmethod
    # @cache.memoize(timeout=120)
    def scoreboard(cls):
        import logging
        score = db.func.sum(Problem.value).label("score")
        date = db.func.max(Solve.date).label("date")
        uniq = db.session\
            .query(Solve.tid.label("tid"), Solve.pid.label("pid"), Solve.correct.label("correct"))\
            .distinct()\
            .subquery()
        scores = db.session\
            .query(uniq.columns.tid.label("tid"), score, date)\
            .join(Problem)\
            .filter(uniq.columns.correct == True)\
            .group_by(uniq.columns.tid)
        results = union_all(scores).alias("results")
        sumscores = db.session\
            .query(results.columns.tid, db.func.sum(results.columns.score).label("score"), db.func.max(results.columns.date).label("date"))\
            .group_by(results.columns.tid)\
            .subquery()
        query = db.session\
            .query(Team.tid.label("tid"), Team.teamname.label("teamname"), School.name.label("school"), sumscores.columns.score)\
            .join(sumscores, Team.tid == sumscores.columns.tid)\
            .join(School, Team.sid == School.id)\
            .order_by(sumscores.columns.score.desc(), sumscores.columns.date)
        return query.all()

    @cache.memoize(timeout=120)
    def get_score_progression(self):

        def convert_to_time(time):
            m, s = divmod(time, 60)
            h, m = divmod(m, 60)
            return "%d:%02d:%02d" % (h, m, s)

        solves = self.solves
        solves.sort(key=lambda s: s.date)
        progression = [["Time", "Score"], [convert_to_time(0), 0]]
        score = 0
        start_time = int(Config.get("start_time", default=0))
        for solve in solves:
            score += solve.problem.value
            frame = [convert_to_time(solve.date - start_time), score]
            progression.append(frame)

        progression.append([convert_to_time(time.time() - start_time), score])

        return progression


class School(db.Model):
    __tablename__ = "schools"
    id = db.Column(db.Integer, index=True, primary_key=True)
    name = db.Column(db.Unicode(128))
    teams = db.relationship("Team", backref=backref("school", lazy="subquery"))

    def __str__(self):
        return self.name

    @cache.memoize(timeout=120)
    def __len__(self):
        return len(self.name)

    def strip(self):
        return self.name.strip()

    @cache.memoize(timeout=120)
    def scoreboard(self):
        teams = Team.query.filter_by(sid=self.id, admin=False).all()
        return sorted(teams, key=lambda team: (
            team.points(), -team.get_last_solved()), reverse=True)


class TeamInvitation(db.Model):
    __tablename__ = "team_invitations"
    id = db.Column(db.Integer, index=True, primary_key=True)
    type = db.Column(db.Integer)
    _fr = db.Column("fr", db.Integer, index=True)
    _to = db.Column("to", db.Integer, index=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def fr(self):
        if self.type == constants.INVITATION_TO_USER:
            return Team.query.filter_by(tid=self._fr).first()
        elif self.type == constants.INVITATION_TO_TEAM:
            return User.query.filter_by(uid=self._fr).first()
        return None

    @property
    def to(self):
        if self.type == constants.INVITATION_TO_USER:
            return User.query.filter_by(uid=self._to).first()
        elif self.type == constants.INVITATION_TO_TEAM:
            return Team.query.filter_by(tid=self._to).first()
        return None

    @fr.setter
    def fr(self, id):
        self._fr = id

    @to.setter
    def to(self, id):
        self._to = id


class Classroom(db.Model):
    __tablename__ = 'classrooms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64), nullable=False)
    owner = db.Column(db.Integer)
    teams = db.relationship('Team', passive_deletes=True,
                            secondary=team_classroom, backref='teams')
    invites = db.relationship('Team', passive_deletes=True,
                              secondary=classroom_invitation,
                              backref='invites')

    def __contains__(self, obj):
        if isinstance(obj, Team):
            return obj in self.teams
        return False

    @property
    def teacher(self):
        return User.query.filter_by(uid=self.owner).first()

    @property
    def size(self):
        return len(self.teams)

    @property
    def scoreboard(self):
        return sorted(self.teams, key=lambda team: (
            team.points(), -team.get_last_solved()), reverse=True)
