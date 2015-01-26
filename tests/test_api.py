import base64
import requests
import time
from pycrest.compat import bytes_, text_
from pycrest.errors import APIException

try:
    from urllib.parse import quote, parse_qs
except ImportError:  # pragma: no cover
    from urllib import quote
    from urlparse import parse_qs
try:
    import testtools as unittest
except ImportError:
    import unittest
import httmock
import pycrest


@httmock.urlmatch(scheme="https",
        netloc=r"(public-)?crest(-tq)?\.eveonline\.com",
        path=r"^/?$")
def root_mock(url, request):
    return {
        "status_code": 200,
        "content": {
            "marketData": {
                "href": "https://public-crest.eveonline.com/market/prices/",
            },
            "incursions": {
                "href": "https://public-crest.eveonline.com/incursions/",
            },
            "status": {"eve": "online"}
        },
    }


@httmock.urlmatch(scheme="https",
        netloc=r"(public-)?crest(-tq)?\.eveonline\.com",
        path=r"^/market/prices/?$")
def market_mock(url, request):
    if url.netloc == 'crest-tq.eveonline.com':
        headers = {
            "Authorization": "Bearer 123asd",
        }
    else:
        headers = {}
    body = {
        "totalCount": 2,
        "items": [
            {
                "avg_price": 100,
                "type": {
                    "href": "getPunisher",
                    "name": "Punisher",
                    "id": 597
                }
            },
            {
                "avg_price": 101,
                "type": {
                    "href": "getRifter",
                    "name": "Rifter",
                    "id": 587
                }
            },
            [
                "foo",
                "bar"
            ],
            "baz"
        ]
    }
    return {
        "status_code": 200,
        "content": body,
    }


@httmock.urlmatch(scheme="https",
        netloc=r"^login.eveonline.com$",
        path=r"^/oauth/verify/?$")
def verify_mock(url, request):
    return {
        "status_code": 200,
        "content": {"CharacterName": "Foobar"},
    }


@httmock.all_requests
def fallback_mock(url, request):
    return {
        "status_code": 404,
        "body": {},
    }


all_mocks = [root_mock, market_mock, verify_mock, fallback_mock]


class TestApi(unittest.TestCase):
    def test_public_api(self):
        with httmock.HTTMock(*all_mocks):
            eve = pycrest.EVE()
            self.assertRaises(AttributeError, eve.__getattr__, 'marketData')
            eve()
            self.assertEqual(eve().marketData.href, "https://public-crest.eveonline.com/market/prices/")
            self.assertEqual(eve.marketData().totalCount, 2)
            self.assertEqual(eve.marketData().items[0].avg_price, 100)
            self.assertEqual(eve.marketData().items[2][0], "foo")
            self.assertEqual(eve.marketData().items[3], "baz")
            self.assertEqual(eve().status().eve, "online")
            self.assertRaises(APIException, lambda: eve.incursions())  # Scala's notation would be nice

            testing = pycrest.EVE(testing=True)
            self.assertEqual(testing._public_endpoint, "http://public-crest-sisi.testeveonline.com/")


class TestAuthorization(unittest.TestCase):
    def test_authorize(self):
        client_id = "bar"
        api_key = "foo"
        code = "foobar"
        access_token = "123asd"
        refresh_token = "asd123"

        @httmock.urlmatch(scheme="https",
                netloc=r"^login.eveonline.com$",
                path=r"^/oauth/token/?$",
                method="POST")
        def token_mock(url, request):
            params = parse_qs(url.query)
            if params['grant_type'][0] == 'authorization_code':
                auth = text_(base64.b64encode(bytes_("%s:%s" % (client_id, api_key))))
                self.assertEqual(request.headers['Authorization'], "Basic %s" % auth)
                if params['code'][0] == code:
                    body = {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "expires_in": 1200
                    }
                    return {"status_code": 200, "content": body}
            elif params['grant_type'][0] == 'refresh_token':
                auth = text_(base64.b64encode(bytes_("%s:%s" % (client_id, api_key))))
                self.assertEqual(request.headers['Authorization'], "Basic %s" % auth)
                if params['refresh_token'][0] == refresh_token:
                    body = {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "expires_in": 1200
                    }
                    return {"status_code": 200, "content": body}
            return {"status_code": 403, "content": {}}

        with httmock.HTTMock(token_mock, *all_mocks):
            eve = pycrest.EVE(api_key=api_key, client_id=client_id, redirect_uri="http://foo.bar")
            auth_uri = "%s/authorize?response_type=code&redirect_uri=%s&client_id=%s&scope=publicData" % (
                eve._oauth_endpoint,
                quote("http://foo.bar", safe=''),
                client_id,
            )
            self.assertEqual(eve.auth_uri(scopes=["publicData"]), auth_uri)
            con = eve.authorize(code)
            self.assertRaises(APIException, lambda: eve.authorize("notcode"))
            r = con.refresh()

            self.assertRaises(AttributeError, con.__getattr__, 'marketData')
            con()
            self.assertEqual(con.marketData.href, "https://public-crest.eveonline.com/market/prices/")
            self.assertEqual(con.marketData().totalCount, 2)
            self.assertEqual(con.marketData().items[1].type.name, "Rifter")

            info = con.whoami()
            self.assertEqual(info['CharacterName'], 'Foobar')
            info = con.whoami()
            self.assertEqual(info['CharacterName'], con._cache['whoami']['CharacterName'])
            info = r.whoami()
            self.assertEqual(info['CharacterName'], 'Foobar')

            r.refresh_token = "notright"
            self.assertRaises(APIException, lambda: r.refresh())

            eve = pycrest.EVE(api_key=api_key, client_id=client_id, cache_time=0)
            con = eve.authorize(code)
            self.assertEqual(con().marketData().totalCount, 2)
            self.assertEqual(con().marketData().totalCount, 2)
