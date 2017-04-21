import pytest

from flask_login import login_user
from openctf.app import create_app
from openctf.config import Configuration
from openctf.models import db as Db, User


@pytest.fixture(scope="session")
def app(request):
    app = create_app()
    app.config.from_object(Configuration(testing=True))

    ctx = app.test_request_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope="function")
def client(app, db):
    return app.test_client()


@pytest.fixture(scope="session")
def user(app, db):
    test_user = User()
    test_user.username = "user"
    test_user.password = "pass"
    db.session.add(test_user)
    db.session.commit()
    return test_user


@pytest.fixture(scope="function")
def authed_user(client, user):
    auth = dict(username="user", password="pass", remember=True, submit="Login")
    r = client.post("/users/login", data=auth)
    return user


@pytest.fixture(scope="function")
def admin_user(client, db):
    admin_user = User()
    admin_user.admin = True
    admin_user.username = "admin"
    admin_user.password = "pass"
    db.session.add(admin_user)
    db.session.commit()
    auth = dict(username="admin", password="pass", remember=True, submit="Login")
    r = client.post("/users/login", data=auth)
    return user


@pytest.fixture(scope="session")
def db(request, app):
    Db.create_all()

    def teardown():
        Db.drop_all()

    request.addfinalizer(teardown)
    return Db


@pytest.fixture(scope="class")
def session(request, db):
    connection = db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection, binds={})
    session = db.create_scoped_session(options=options)

    db.session = session

    def teardown():
        transaction.rollback()
        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session
