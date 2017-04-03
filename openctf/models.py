from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt
from sqlalchemy.ext.hybrid import hybrid_property

from openctf.users import login_manager

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, index=True, primary_key=True)
    tid = db.Column(db.Integer, db.ForeignKey("teams.id"))
    name = db.Column(db.Unicode(32))
    username = db.Column(db.String(16), unique=True, index=True)
    email = db.Column(db.String(128), unique=True)
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


class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, index=True, primary_key=True)
    teamname = db.Column(db.Unicode(32), unique=True)
    affiliation = db.Column(db.Unicode(48))
    captain = db.Column(db.Integer)
    members = db.relationship("User", back_populates="team")
