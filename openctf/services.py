from flask_cache import Cache
from flask_celery import Celery
from flask_login import LoginManager

cache = Cache()
celery = Celery()
login_manager = LoginManager()

login_manager.login_view = "users.login"
login_manager.login_message_category = "danger"
