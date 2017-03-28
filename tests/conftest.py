import pytest

from app import app as ctf_app
from config import Config as CTFConfig
from models import db as ctf_db


@pytest.fixture(scope="session")
def app(request):
    app = ctf_app
    app.config.from_object(CTFConfig(testing=True))
    app.config["TESTING"] = True

    ctx = app.test_request_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope="session")
def client(app, db):
    return app.test_client()


@pytest.fixture(scope="session")
def db(request, app):
    ctf_db.create_all()

    def teardown():
        ctf_db.drop_all()

    request.addfinalizer(teardown)
    return ctf_db


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
