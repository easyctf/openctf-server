import os
from flask import Flask


def create_app():
    app = Flask(__name__)
    with app.app_context():
        from openctf.config import Configuration
        app.config.from_object(Configuration(
            app_root=os.path.dirname(os.path.abspath(__file__))))

        from openctf.models import db
        db.init_app(app)

        from openctf import views
        app.register_blueprint(views.base.blueprint)

        return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=3000, use_debugger=True, use_reloader=True)
