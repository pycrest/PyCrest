import requests
from pycrest.weak_ciphers import WeakCiphersAdapter
try:
    import testtools as unittest
except ImportError:
    import unittest


class TestWeakCiphers(unittest.TestCase):

    def setUp(self):
        super(TestWeakCiphers, self).setUp()
        session = requests.Session()
        session.headers.update({"User-Agent": "PyCrest_Cipher_Testing/0.1"})
        adapter = WeakCiphersAdapter()
        session.mount("https://crest-tq.eveonline.com", adapter)
        session.mount("http://example.com", adapter)
        self.session = session

    def test_public_crest(self):
        resp = self.session.get("https://crest-tq.eveonline.com")
        self.assertIsNotNone(resp)

    def test_http(self):
        resp = self.session.get("http://example.com")
        self.assertIsNotNone(resp)
