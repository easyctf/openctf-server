from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager, Server

from openctf.app import create_app
from openctf.models import db

app = create_app(debug=True)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command("db", MigrateCommand)

ServerCommand = Server(host="0.0.0.0", port=80, use_debugger=True, use_reloader=True)
manager.add_command("runserver", ServerCommand)

if __name__ == "__main__":
    manager.run()
