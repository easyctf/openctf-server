import logging
import os
import time

from flask import Flask, render_template, request
from flask_login import current_user

import views
from config import Config as AppConfig
from judge_api import judge_api
from logger import CTFLogHandler
from models import Config, breadcrumbs, cache, db, login_manager

app = Flask(__name__)
app.config.from_object(
    AppConfig(app_root=os.path.dirname(os.path.abspath(__file__)),
              testing=False))

if app.config["ENV"] == "dev":
    app.debug = True

breadcrumbs.init_app(app)
db.init_app(app)
login_manager.init_app(app)
cache.init_app(app)
judge_api.init_app(app)
app.db = db
views.importer.create_folders()

handler = CTFLogHandler("logs/app.log")
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

app.register_blueprint(views.admin.blueprint, url_prefix="/admin")
app.register_blueprint(views.base.blueprint)
app.register_blueprint(views.classroom.blueprint, url_prefix="/classroom")
app.register_blueprint(views.importer.blueprint)
app.register_blueprint(views.oauth.blueprint, url_prefix="/oauth")
app.register_blueprint(views.problems.blueprint, url_prefix="/problems")
app.register_blueprint(views.teams.blueprint, url_prefix="/teams")
app.register_blueprint(views.users.blueprint, url_prefix="/users")


@app.context_processor
def inject_config():
    config = dict(
        admin_email=app.config["ADMIN_EMAIL"],
        before_competition=int(time.time()) < int(Config.get("start_time", 0)),
        ctf_name=Config.get("ctf_name", "OpenCTF"),
        ctf_description=Config.get("ctf_description", ""),
        stylesheet_url=Config.get("stylesheet_url",
                                  "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"),
        keywords=Config.get("keywords"),
        noindex=not (app.config["ENV"] == "prod")
    )
    return config


@app.after_request
def log_request(response):
    information = {
        "IP": request.remote_addr,
        "Path": "%s %s" % (request.method, request.path),
        "Endpoint": request.endpoint,
        "Status": response.status_code
    }
    if request.args:
        information["Args"] = repr(dict(request.args))
    if current_user.is_authenticated:
        information["User"] = str(current_user)
        if current_user.team:
            information["Team"] = str(current_user.team)
    app.logger.info(" ".join("%s=(%s)" % (key, value) for key, value in
                             information.items()))
    return response


@app.errorhandler(403)
def page_not_found(e):
    return render_template("error/403.html"), 403


@app.errorhandler(404)
def page_not_found(e):
    return render_template("error/404.html"), 404


if __name__ == "__main__":
    pass
