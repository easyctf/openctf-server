from flask import Blueprint

blueprint = Blueprint("base", __name__, template_folder="templates")


@blueprint.route("/")
def index():
    return "Hello."
