import base64
import requests
import time
from pycrest.compat import bytes_, text_
from pycrest.errors import APIException

try:
    from urllib.parse import quote
except ImportError:  # pragma: no cover
    from urllib import quote
try:
    import testtools as unittest
except ImportError:
    import unittest
import mock
import pycrest


class TestApi(unittest.TestCase):
    @mock.patch('requests.get')
    def test_public_api(self, mock_get):
        mock_resp = mock.MagicMock(requests.Response)

        def _get(href, *args, **kwargs):
            if href == "https://public-crest.eveonline.com/":
                body = {
                    "marketData": {"href": "getMarketData"},
                    "incursions": {"href": "getIncursions"},
                    "status": {"eve": "online"}
                }
                res = mock_resp()
                res.status_code = 200
                res.json.return_value = body
                return res
            elif href == "getMarketData":
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
                res = mock_resp()
                res.status_code = 200
                res.json.return_value = body
                return res
            elif href == "getIncursions":
                body = {}
                res = mock_resp()
                res.status_code = 404
                res.json.return_value = body
                return res
            else:
                res = mock_resp()
                res.status_code = 404
                res.json.return_value = {}
                return res

        mock_get.side_effect = _get
        eve = pycrest.EVE()
        self.assertRaises(AttributeError, eve.__getattr__, 'marketData')
        eve()
        self.assertEqual(eve().marketData.href, "getMarketData")
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
        mock_resp = mock.MagicMock(requests.Response)

        def _get(href, *args, **kwargs):
            if href == "https://crest-tq.eveonline.com/":
                body = {
                    "marketData": {"href": "getMarketData"}
                }
                res = mock_resp()
                res.status_code = 200
                res.json.return_value = body
                return res
            elif href == "getMarketData":
                self.assertIn('headers', kwargs)
                self.assertEqual(kwargs['headers']['Authorization'], "Bearer %s" % access_token)
                body = {
                    "totalCount": 2,
                    "foo": {
                        "foo": "Bar"
                    }
                }
                res = mock_resp()
                res.status_code = 200
                res.json.return_value = body
                return res
            elif href == "https://login.eveonline.com/oauth/verify":
                body = {
                    "CharacterName": "Foobar"
                }
                res = mock_resp()
                res.status_code = 200
                res.json.return_value = body
                return res
            else:
                res = mock_resp()
                res.status_code = 404
                res.json.return_value = {}
                return res

        def _post(href, *args, **kwargs):
            if href == "https://login.eveonline.com/oauth/token":
                self.assertIn('headers', kwargs)
                if kwargs['params']['grant_type'] == 'authorization_code':
                    auth = text_(base64.b64encode(bytes_("%s:%s" % (client_id, api_key))))
                    self.assertEqual(kwargs['headers']['Authorization'], "Basic %s" % auth)
                    if kwargs['params']['code'] == code:
                        body = {
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "expires_in": 1200
                        }
                        res = mock_resp()
                        res.status_code = 200
                        res.json.return_value = body
                        return res
                    else:
                        res = mock_resp()
                        res.status_code = 403
                        return res
                elif kwargs['params']['grant_type'] == 'refresh_token':
                    auth = text_(base64.b64encode(bytes_("%s:%s" % (client_id, api_key))))
                    self.assertEqual(kwargs['headers']['Authorization'], "Basic %s" % auth)
                    if kwargs['params']['refresh_token'] == refresh_token:
                        body = {
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "expires_in": 1200
                        }
                        res = mock_resp()
                        res.status_code = 200
                        res.json.return_value = body
                        return res
                    else:
                        res = mock_resp()
                        res.status_code = 403
                        return res
                else:
                    res = mock_resp()
                    res.status_code = 403
                    res.json.return_value = {}
                    return res
            else:
                res = mock_resp()
                res.status_code = 404
                res.json.return_value = {}
                return res

        with mock.patch('requests.get', side_effect=_get):
            with mock.patch('requests.post', side_effect=_post):
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
                self.assertEqual(con.marketData.href, "getMarketData")
                self.assertEqual(con.marketData().totalCount, 2)
                self.assertEqual(con.marketData().foo.foo, "Bar")

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