"""
    server.config
    ~~~~~~~~~~~~~

    Prepares the configuration for the platform based on options specified
    in the environment file.
"""

import cPickle as pickle
import os

import pathlib
from werkzeug.contrib.cache import RedisCache

SERVICES = ['github', 'google']


class CTFCache(RedisCache):
    """
    A custom class used by Flask-Cache as a storage engine. tbh i forgot
    why i made a custom class over just using RedisCache, there was
    probably good reason behind it
    """

    def dump_object(self, value):
        value_type = type(value)
        if value_type in (int, long):
            return str(value).encode('ascii')
        return b'!' + pickle.dumps(value, -1)


def cache(app, config, args, kwargs):
    """
    A custom cache engine for Flask-Cache that uses the CTFCache to store
    values to redis. See the CTFCache docstring for the motivation behind
    this.
    """
    # pylint: disable=unused-argument

    kwargs["host"] = app.config.get("CACHE_REDIS_HOST", "localhost")
    return CTFCache(*args, **kwargs)


class Config(object):
    """
    The configuration for the Flask app. A configuration created from this
    class will eventually be consumed using app.from_object().
    """

    # pylint: disable=too-many-instance-attributes,too-few-public-methods

    def __init__(self, app_root=None, testing=False):
        # pylint: disable=invalid-name

        if app_root is None:
            self.app_root = pathlib.Path(
                os.path.dirname(os.path.abspath(__file__)))
        else:
            self.app_root = pathlib.Path(app_root)

        self.TESTING = False
        self.SECRET_KEY = None
        self._load_secret_key()
        self.SQLALCHEMY_DATABASE_URI = self._get_database_url()
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.PREFERRED_URL_SCHEME = 'https'

        self.CACHE_TYPE = "config.cache"
        self.CACHE_REDIS_HOST = "redis"

        self.OAUTH_CREDENTIALS = self._load_oauth_credentials()

        self.ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
        self.MAILGUN_URL = os.getenv("MAILGUN_URL", "")
        self.MAILGUN_APIKEY = os.getenv("MAILGUN_APIKEY", "")
        self.EMAIL_VERIFICATION_REQUIRED = int(
            os.getenv("EMAIL_VERIFICATION_REQUIRED", "0"))
        self.ENV = os.getenv("ENV", "")

        self.JUDGE_URL = os.getenv("JUDGE_URL", "http://judge/")
        self.JUDGE_API_KEY = os.getenv("JUDGE_API_KEY", "")

        if testing or self.ENV == "test":
            if os.getenv("DATABASE_URL"):
                self.SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
            else:
                test_db_path = os.path.join(
                    os.path.dirname(__file__), "test.db")
                self.SQLALCHEMY_DATABASE_URI = "sqlite:///%s" % test_db_path
                if not os.path.exists(test_db_path):
                    with open(test_db_path, "a"):
                        os.utime(test_db_path, None)
            self.TESTING = True
            self.WTF_CSRF_ENABLED = False

    @staticmethod
    def _load_oauth_credentials():
        credentials = {}
        for service_name in SERVICES:
            client_id = os.getenv("%s_CLIENT_ID" % service_name.upper())
            client_secret = os.getenv(
                "%s_CLIENT_SECRET" % service_name.upper())
            if client_id and client_secret:
                credentials[service_name.lower()] = dict(
                    client_id=client_id,
                    client_secret=client_secret)
        return credentials

    def _load_secret_key(self):
        if "SECRET_KEY" in os.environ:
            self.SECRET_KEY = os.environ["SECRET_KEY"]
        else:
            secret_path = self.app_root / ".secret_key"
            if not os.path.exists(".secret_key"):
                open(".secret_key", "w").close()
            with secret_path.open("rb+") as secret_file:
                secret_file.seek(0)
                contents = secret_file.read()
                if not contents and len(contents) == 0:
                    key = os.urandom(128)
                    secret_file.write(key)
                    secret_file.flush()
                else:
                    key = contents
            self.SECRET_KEY = key
        return self.SECRET_KEY

    @staticmethod
    def _get_database_url():
        url = os.getenv("DATABASE_URL")
        if url:
            return url
        return "mysql://root:%s@db/%s" % (
            os.getenv("MYSQL_ROOT_PASSWORD"), os.getenv("MYSQL_DATABASE"))
