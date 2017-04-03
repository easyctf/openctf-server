import sys
import traceback

from werkzeug.exceptions import *


def handle_errors(app):
    @app.errorhandler(BadRequest)
    def handle_bad_request(e):
        sys.stderr.write(traceback.format_exc())
        return "Bad request."
