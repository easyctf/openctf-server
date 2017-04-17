from flask_login import LoginManager
from flask_cache import Cache

cache = Cache()
login_manager = LoginManager()

login_manager.login_view = "users.login"
