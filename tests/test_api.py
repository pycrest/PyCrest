import os
import base64
import requests
import time
import cPickle
import zlib
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


class MockFilesystem(object):
    def __init__(self):
        self.fs = {'/': {}}

    def isdir(self, path):
        return path in self.fs

    def mkdir(self, path, mode=0777):
        if not path:
            raise OSError(2, "No such file or directory: '%s'" % path)

        if path not in self.fs:
            self.fs[path] = {}

    def open(self, path, mode='r'):
        class FileObj(object):
            def __init__(self, elem):
                self.elem = elem
                self.closed = 0
            def __enter__(self):
                return self
            def __exit__(self, type, value, tb):
                self.closed = 1
            def write(self, data):
                self.elem['data'] = data
            def read(self):
                return self.elem['data']
            def close(self):
                self.closed = 1

        if path in self.fs:
            raise IOError(21, "Is a directory: '%s'" % path)

        directory, filename = os.path.split(path)

        if not self.isdir(directory):
            raise IOError(2, "No such file or directory: '%s'" % path)

        if mode in ['r', 'rb', 'r+', 'r+b'] \
                and filename not in self.fs[directory]:
            raise IOError(2, "No such file or directory: '%s'" % path)

        if mode in ['w', 'wb']:
            self.fs[directory][filename] = {'data': ''}

        return FileObj(self.fs[directory][filename])

    def unlink(self, path):
        if path in self.fs:
            raise OSError(5, 'Is a directory')

        directory, filename = os.path.split(path)
        if directory not in self.fs \
                or filename not in self.fs[directory]:
            raise OSError(2, "No such file or directory: '%s'" % path)
        self.fs[directory].pop(filename)


class TestApi(unittest.TestCase):
    @mock.patch('requests.Session.get')
    def test_public_api(self, mock_get):
        mock_resp = mock.MagicMock(requests.Response)

        def _get(href, **kwargs):
            if href == "https://public-crest.eveonline.com/":
                body = {
                    "marketData": {"href": "getMarketData"},
                    "incursions": {"href": "getIncursions"},
                    "status": {"eve": "online"},
                    "queryString": {"href": "getWithQS"},
                    "paginatedData": {"href": "getPage?page=2"}
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
            elif href == "getWithQS":
                params = kwargs.get("params")
                if "query" not in params or params["query"] != "string":
                    body = {}
                    res = mock_resp()
                    res.status_code = 403
                    res.json.return_value = body
                    return res
                else:
                    body = {"result": "ok"}
                    res = mock_resp()
                    res.status_code = 200
                    res.json.return_value = body
                    return res
            elif href == "getPage":
                params = kwargs.get("params")
                if "page" not in params or params["page"] != "2":
                    body = {}
                    res = mock_resp()
                    res.status_code = 403
                    res.json.return_value = body
                    return res
                else:
                    body = {"result": "ok"}
                    res = mock_resp()
                    res.status_code = 200
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
        self.assertEqual(eve.queryString(query="string").result, "ok")
        self.assertRaises(APIException, lambda: eve.queryString())
        self.assertEqual(eve.paginatedData().result, "ok")

        testing = pycrest.EVE(testing=True)
        self.assertEqual(testing._public_endpoint, "http://public-crest-sisi.testeveonline.com/")

        fs = MockFilesystem()
        with mock.patch("os.path.isdir", side_effect=fs.isdir):
            with mock.patch("os.mkdir", side_effect=fs.mkdir):
                with mock.patch("os.unlink", side_effect=fs.unlink):
                    with mock.patch("__builtin__.open", fs.open, create=True):
                        # cache miss
                        eve = pycrest.EVE(cache_dir='/cachedir')
                        eve()

                        # cache hit
                        eve = pycrest.EVE(cache_dir='/cachedir')
                        eve()

                        # stale cache hit
                        for dirpath in fs.fs.keys():
                            if dirpath == '/cachedir':
                                self.assertEquals(len(fs.fs[dirpath].keys()), 1)
                                path = os.path.join(dirpath, fs.fs[dirpath].keys()[0])

                        recf = fs.open(path, 'r')
                        rec = cPickle.loads(zlib.decompress(recf.read()))
                        recf.close()
                        rec['timestamp'] -= eve.cache_time

                        recf = fs.open(path, 'w')
                        recf.write(zlib.compress(cPickle.dumps(rec)))
                        recf.close()

                        eve = pycrest.EVE(cache_dir='/cachedir')
                        eve()


class TestAuthorization(unittest.TestCase):
    def test_authorize(self):
        client_id = "bar"
        api_key = "foo"
        code = "foobar"
        access_token = "123asd"
        refresh_token = "asd123"
        mock_resp = mock.MagicMock(requests.Response)

        def _get(href, **kwargs):
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
                body = {
                    "totalCount": 2,
                    "foo": {
                        "foo": "Bar"
                    }
                }
                res = mock_resp()
                if kwargs['headers']['Authorization'] == "Bearer %s" % access_token:
                    res.status_code = 200
                else:
                    res.status_code = 401
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

        def _post(href, data=None, **kwargs):
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

        with mock.patch('requests.Session.get', side_effect=_get):
            with mock.patch('requests.Session.post', side_effect=_post):
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

                # auth with refresh token
                con = eve.refr_authorize(con.refresh_token)
                self.assertRaises(AttributeError, con.__getattr__, 'marketData')
                con()
                self.assertEqual(con.marketData.href, "getMarketData")
                self.assertEqual(con.marketData().totalCount, 2)
                self.assertEqual(con.marketData().foo.foo, "Bar")

                # fail auth with refresh token
                self.assertRaises(APIException, lambda: eve.refr_authorize('notright'))

                # auth with temp token
                con = eve.temptoken_authorize(con.token,
                                              con.expires - time.time(),
                                              con.refresh_token)
                self.assertRaises(AttributeError, con.__getattr__, 'marketData')
                con()
                self.assertEqual(con.marketData.href, "getMarketData")
                self.assertEqual(con.marketData().totalCount, 2)
                self.assertEqual(con.marketData().foo.foo, "Bar")

                # fail auth with temp token
                con = eve.temptoken_authorize('nottoken',
                                              con.expires - time.time(),
                                              con.refresh_token)()
                self.assertRaises(APIException, lambda: con().marketData())

                # test auto-refresh of expired token
                con = eve.temptoken_authorize(access_token,
                                              -1,
                                              refresh_token)
                con().marketData()
                self.assertGreater(con.expires, time.time())


class TestApiCache(unittest.TestCase):
    def test_apicache(self):
        fs = MockFilesystem()
        with mock.patch("os.path.isdir", side_effect=fs.isdir):
            with mock.patch("os.mkdir", side_effect=fs.mkdir):
                with mock.patch("os.unlink", side_effect=fs.unlink):
                    with mock.patch("__builtin__.open", fs.open, create=True):
                        # with mkdir needed
                        crest = pycrest.EVE(cache_dir="/cachedir")

                        # without mkdir now
                        crest = pycrest.EVE(cache_dir="/cachedir")

                        # cache created?
                        self.assertEqual(type(crest.cache).__name__, "APICache")

                        # invalidate non-existing key
                        crest.cache.invalidate('nxkey')

                        # get non-existing key
                        self.assertEqual(crest.cache.get('nxkey'), None)

                        # cache (key, value) pair and retrieve it
                        crest.cache.put('key', 'value')
                        self.assertEqual(crest.cache.get('key'), 'value')

                        # retrieve from disk
                        crest = pycrest.EVE(cache_dir="/cachedir")
                        self.assertEqual(crest.cache.get('key'), 'value')

                        # invalidate key and check it's removed
                        crest.cache.invalidate('key')
                        self.assertEqual(crest.cache.get('key'), None)

                        # dirname == filename tests
                        fs.mkdir('/cachedir/'+str(hash('key'))+'.cache')
                        with self.assertRaises(OSError):
                            crest.cache.invalidate('key')
                        with self.assertRaises(IOError):
                            crest.cache.get('key')
