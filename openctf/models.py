import time
from datetime import datetime
from io import BytesIO
import sys
import json
import requests
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt
from sqlalchemy.ext.hybrid import hybrid_property

import logging
from openctf.services import cache, login_manager
from openctf.utils import generate_identicon

db = SQLAlchemy()
avatar_filename = json.dumps(["avatar", "png"])


class Config(db.Model):
    __tablename__ = "config"
    cid = db.Column(db.Integer, primary_key=True, index=True)
    key = db.Column(db.Unicode(32), unique=True, index=True)
    value = db.Column(db.Text)

    @classmethod
    def get(cls, key, default=None):
        config = cls.query.filter_by(key=key).first()
        if config is None:
            return default
        return str(config.value)

    @classmethod
    def set(cls, key, value):
        config = cls.query.filter_by(key=key).first()
        if config is None:
            config = Config(key, value)
            db.session.add(config)
        else:
            config.value = value
        db.session.commit()


class Challenge(db.Model):
    __tablename__ = "challenges"
    id = db.Column(db.Integer, index=True, primary_key=True)
    name = db.Column(db.String(32), unique=True, index=True)
    author = db.Column(db.Unicode(32))
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
    bonus = db.Column(db.PickleType)

    solves = db.relationship("Solve", back_populates="challenge", lazy="subquery")


class Solve(db.Model):
    __tablename__ = "solves"
    id = db.Column(db.Integer, index=True, primary_key=True)
    pid = db.Column(db.Integer, db.ForeignKey("challenges.id"), index=True)
    tid = db.Column(db.Integer, db.ForeignKey("teams.id"), index=True)
    uid = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    _date = db.Column("date", db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.Integer)
    correct = db.Column(db.Boolean)
    ua = db.Column(db.Text)
    flag = db.Column(db.Text)

    user = db.relationship("User", back_populates="solves", lazy="subquery")
    team = db.relationship("Team", back_populates="solves", lazy="subquery")
    challenge = db.relationship("Challenge", back_populates="solves", lazy="subquery")


class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, index=True, primary_key=True)
    teamname = db.Column(db.Unicode(32), unique=True, index=True)
    affiliation = db.Column(db.Unicode(48))
    captain = db.Column(db.Integer)
    members = db.relationship("User", back_populates="team")

    solves = db.relationship("Solve", back_populates="team", lazy="subquery")


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, index=True, primary_key=True)
    tid = db.Column(db.Integer, db.ForeignKey("teams.id"))
    name = db.Column(db.Unicode(32))
    username = db.Column(db.String(16), unique=True, index=True)
    email = db.Column(db.String(128), unique=True, index=True)
    _password = db.Column("password", db.String(128))
    admin = db.Column(db.Boolean, default=False)
    level = db.Column(db.Integer)
    _register_time = db.Column("register_time", db.DateTime, default=datetime.utcnow)
    reset_token = db.Column(db.String(32))
    otp_secret = db.Column(db.String(16))
    otp_confirmed = db.Column(db.Boolean, default=False)
    email_token = db.Column(db.String(32))
    email_verified = db.Column(db.Boolean, default=False)
    _avatar = db.Column("avatar", db.String(128))

    team = db.relationship("Team", back_populates="members")
    solves = db.relationship("Solve", back_populates="user", lazy="subquery")

    @property
    def avatar(self):
        if not self._avatar:
            avatar_file = BytesIO()
            avatar = generate_identicon(self.email)
            avatar.save(avatar_file, format="PNG")
            avatar_file.seek(0)
            response = requests.post("{}/save".format(current_app.config["FILESTORE_URL"]), data={"filename": avatar_filename}, files={"file": avatar_file})
            if response.status_code == 200:
                self._avatar = "/static/%s" % response.text
                db.session.add(self)
                db.session.commit()
        return self._avatar

    def check_password(self, password):
        return bcrypt.verify(password, self.password)

    def get_id(self):
        return str(self.id)

    @staticmethod
    @login_manager.user_loader
    def get_by_id(id):
        query_results = User.query.filter_by(id=id)
        return query_results.first()

    @property
    def is_active(self):
        # TODO This will be based off account standing.
        return True

    @property
    def is_authenticated(self):
        return True

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = bcrypt.encrypt(password, rounds=10)

    @hybrid_property
    def register_time(self):
        return int(time.mktime(self._register_time.timetuple()))
