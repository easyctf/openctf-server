class TestViewsUsers(object):

    def test_login_page(self, client):
        r = client.get("/users/login")
        assert r.status_code == 200

    def test_login(self, client, user):
        auth = dict(username="user", password="pass", remember=True, submit="Login")
        r = client.post("/users/login", data=auth)
        assert r.status_code == 302

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
        assert r.status_code == 302

    def test_profile_authenticated(self, client, authed_user):
        r = client.get("/users/profile")
        print(r.data)
        assert r.status_code == 200

    def test_register_page(self, client):
        r = client.get("/users/register")
        assert r.status_code == 200

    def test_forgot_page(self, client):
        r = client.get("/users/forgot")
        assert r.status_code == 200
