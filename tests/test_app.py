import unittest

from happyhacks import create_app


class SiteTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_home_lists_products(self):
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn("ZipZip", body)
        self.assertIn("BRB", body)

    def test_product_pages(self):
        self.assertEqual(self.client.get("/products/zipzip").status_code, 200)
        self.assertEqual(self.client.get("/products/doppleganger").status_code, 200)
        self.assertEqual(self.client.get("/products/nope").status_code, 404)

    def test_static_css(self):
        self.assertEqual(self.client.get("/static/css/site.css").status_code, 200)

    def test_healthz(self):
        self.assertEqual(self.client.get("/healthz").json, {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
