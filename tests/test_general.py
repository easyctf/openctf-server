class TestGeneral:

    def test_sanity(self):
        assert "sanity" > 0

    def test_index(self, client):
        assert client.get("/").status_code == 200
