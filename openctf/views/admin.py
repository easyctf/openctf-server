from flask import Blueprint

blueprint = Blueprint("admin", __name__, template_folder="templates")


@blueprint.route("/settings")
def settings():
    return "hi"
