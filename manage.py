import socket

from celery.bin.celery import main as celery_main
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager, Server

from openctf.app import create_app
from openctf.models import db

HOSTNAME = socket.gethostname()

app = create_app(debug=True)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command("db", MigrateCommand)

ServerCommand = Server(host="0.0.0.0", port=80, use_debugger=True, use_reloader=True)
manager.add_command("runserver", ServerCommand)


@manager.command
def worker():
    """ Start a new Celery worker. """
    with app.app_context():
        celery_args = ["celery", "worker", "-n", HOSTNAME, "-C", "--autoscale=10,1", "--without-gossip"]
        return celery_main(celery_args)

if __name__ == "__main__":
    manager.run()
