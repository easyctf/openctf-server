class TestViewsAdmin(object):

    def test_settings_page(self, client, admin_user):
        r = client.get("/admin/settings")
        assert r.status_code == 200
