class TestViewsBase(object):

    def test_index(self, client):
        r = client.get("/")
        assert r.status_code == 200
