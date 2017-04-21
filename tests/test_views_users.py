from openctf.views.users import register_user


class TestViewsUsers(object):

    def test_forgot_page(self, client):
        r = client.get("/users/forgot")
        assert r.status_code == 200

    def test_login_page(self, client):
        r = client.get("/users/login")
        assert r.status_code == 200

    def test_login_page_authed(self, client, authed_user):
        r = client.get("/users/login")
        assert r.status_code == 302

    def test_login(self, client, user):
        auth = dict(username="user", password="pass", remember=True, submit="Login")
        r = client.post("/users/login", data=auth)
        assert r.status_code == 302

    def test_logout(self, client, authed_user):
        r = client.get("/users/profile")
        assert r.status_code == 302
        client.get("/users/logout")
        r = client.get("/users/profile")
        assert r.status_code == 404

    def test_invalid_username(self, client, user):
        auth = dict(username="user1", password="pass", remember=True, submit="Login")
        r = client.post("/users/login", data=auth)
        assert r.status_code == 200

    def test_invalid_password(self, client, user):
        auth = dict(username="user", password="pass1", remember=True, submit="Login")
        r = client.post("/users/login", data=auth)
        assert r.status_code == 200

    def test_profile_unauthenticated(self, client):
        r = client.get("/users/profile")
        assert r.status_code == 404

    def test_profile_authenticated(self, client, authed_user):
        r = client.get("/users/profile")
        assert r.status_code == 302

    def test_profile_page(self, client, user):
        r = client.get("/users/profile/1")
        assert r.status_code == 200

    def test_register_page(self, client):
        r = client.get("/users/register")
        assert r.status_code == 200

    def test_register_user(self, client):
        info = dict(email="user@easyctf.com", name="user", username="user1", password="pass", confirm_password="pass", level="1")
        r = client.post("/users/register", data=info)
        assert r.status_code == 302

    def test_register_taken_username(self, client):
        info = dict(email="user@easyctf.com", name="user", username="user", password="pass", confirm_password="pass", level="1")
        r = client.post("/users/register", data=info)
        assert r.status_code == 200
        assert r.data.find(b"Username is taken.") >= 0

    def test_register_invalid_username(self, client):
        info = dict(email="user@easyctf.com", name="user", username="H! Th3R#", password="pass", confirm_password="pass", level="1")
        r = client.post("/users/register", data=info)
        assert r.status_code == 200
        assert r.data.find(b"Username must be contain letters, numbers, or _, and not start with a number.") >= 0

    def test_register_page_authed(self, client, authed_user):
        r = client.get("/users/register")
        assert r.status_code == 302

    def test_register_user_function(self, client):
        register_user("name", "mail@example.com", "test", "test", 1)
        auth = dict(username="test", password="test", remember=True, submit="Login")
        r = client.post("/users/login", data=auth)
        assert r.status_code == 302

    def test_verify_email(self, client):
        test = register_user("name", "mail1@example.com", "test1", "test", 1)
        client.post("/users/login", data=dict(username="test1", password="test"))
        code = test.email_token
        r = client.get("/users/verify/garbage", follow_redirects=True)
        assert r.data.find(b"Incorrect code.") >= 0
        r = client.get("/users/verify/" + code, follow_redirects=True)
        assert r.data.find(b"Email verified!") >= 0
        r = client.get("/users/verify/" + code, follow_redirects=True)
        assert r.data.find(b"You&#39;ve already verified your email.") >= 0
