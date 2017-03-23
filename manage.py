from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager, Server

import util
from app import app
from models import db

migrate = Migrate(app, app.db)

manager = Manager(app)
manager.add_command("db", MigrateCommand)

ServerCommand = Server(host="0.0.0.0", port=8000,
                       use_debugger=True, use_reloader=True)
manager.add_command("runserver", ServerCommand)

if __name__ == "__main__":
    manager.run()
