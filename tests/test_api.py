import base64
import requests
from pycrest.compat import bytes_, text_
from pycrest.errors import APIException

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
                    "incursions": {"href": "getIncursions"}
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
                            "avg_price": 100,
                            "type": {
                                "href": "getRifter",
                                "name": "Rifter",
                                "id": 587
                            }
                        }
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

        mock_get.side_effect = _get
        eve = pycrest.EVE()
        self.assertRaises(AttributeError, eve.__getattr__, 'marketData')
        eve()
        self.assertEqual(eve.marketData.href, "getMarketData")
        self.assertEqual(eve.marketData().totalCount, 2)
        self.assertRaises(APIException, lambda: eve.incursions())  # Scala's notation would be nice


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
                    body = {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "expires_in": 1200
                    }
                    res = mock_resp()
                    res.status_code = 200
                    res.json.return_value = body
                    return res
                elif kwargs['params']['grant_type'] == 'refresh_token':
                    auth = text_(base64.b64encode(bytes_("%s:%s" % (client_id, api_key))))
                    self.assertEqual(kwargs['headers']['Authorization'], "Basic %s" % auth)
                    self.assertEqual(kwargs['params']['refresh_token'], refresh_token)
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
                    res.json.return_value = {}
                    return res
            else:
                res = mock_resp()
                res.status_code = 404
                res.json.return_value = {}
                return res

        with mock.patch('requests.get', side_effect=_get):
            with mock.patch('requests.post', side_effect=_post):
                eve = pycrest.EVE(api_key=api_key, client_id=client_id)
                con = eve.authorize(code)
                r = con.refresh()

                self.assertRaises(AttributeError, con.__getattr__, 'marketData')
                con()
                self.assertEqual(con.marketData.href, "getMarketData")
                self.assertEqual(con.marketData().totalCount, 2)
                self.assertEqual(con.marketData().foo().foo, "Bar")

                info = con.whoami()
                self.assertEqual(info['CharacterName'], 'Foobar')
                info = r.whoami()
                self.assertEqual(info['CharacterName'], 'Foobar')
