import os
import pathlib
import sys


class Configuration(object):

    def __init__(self, app_root=None, testing=False):
        if app_root is None:
            self.app_root = pathlib.Path(
                os.path.dirname(os.path.abspath(__file__)))
        else:
            self.app_root = pathlib.Path(app_root)

        self.TESTING = testing
        self.SECRET_KEY = self._get_secret_key()
        self.SQLALCHEMY_DATABASE_URI = self._get_database_url()

        if testing:
            self.WTF_CSRF_ENABLED = False

    def _get_secret_key(self):
        # Key exists in environment.
        key = os.getenv("SECRET_KEY")
        if key:
            return key

        # Generate key and save it (not recommended for scaling).
        secret_path = self.app_root / ".secret_key"
        if not secret_path.exists():
            secret_path.open("w").close()
        with secret_path.open("rb+") as secret_file:
            secret_file.seek(0)
            contents = secret_file.read()
            if not contents and len(contents) == 0:
                key = os.urandom(128)
                secret_file.write(key)
                secret_file.flush()
            else:
                key = contents
        return key

    @staticmethod
    def _get_database_url():
        url = os.getenv("DATABASE_URL")
        if not url:
            sys.stderr.write("DATABASE_URL not set; MySQL database could not be located.")
            sys.exit(1)
        return url
