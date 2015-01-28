import base64
import os
import zlib
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
try:
    import __builtin__
    builtins_name = __builtin__.__name__
except ImportError:
    import builtins
    builtins_name = builtins.__name__
try:
    import pickle
except ImportError:
    import cPickle as pickle
import httmock
import pycrest
import mock


class MockFilesystem(object):
    def __init__(self):
        self.fs = {'/': {}}

    def isdir(self, path):
        return path in self.fs

    def mkdir(self, path, mode=0o700):
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

    def listdir(self, directory):
        return self.fs[directory].keys()


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
            "status": {"eve": "online"},
            "queryString": {
                "href": "https://public-crest.eveonline.com/queryString/"
            },
            "paginatedData": {
                "href": "https://public-crest.eveonline.com/getPage/?page=2"
            }
        },
        "headers": {
            "Cache-Control": "private, max-age=300"
        }
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
        "headers": {
            "Cache-Control": "private, max-age=300"
        }
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
    print("No mock for: %s" % request.url)
    return {
        "status_code": 404,
        "body": {},
    }


all_mocks = [root_mock, market_mock, verify_mock, fallback_mock]


class TestApi(unittest.TestCase):
    @mock.patch('os.path.isdir')
    @mock.patch('os.mkdir')
    @mock.patch('os.unlink')
    @mock.patch('os.listdir')
    @mock.patch('%s.open' % builtins_name)
    def test_public_api(self, mock_open, mock_listdir, mock_unlink, mock_mkdir, mock_isdir):
        fs = MockFilesystem()
        mock_isdir.side_effect = fs.isdir
        mock_mkdir.side_effect = fs.mkdir
        mock_unlink.side_effect = fs.unlink
        mock_listdir.side_effect = fs.listdir
        mock_open.side_effect = fs.open

        @httmock.urlmatch(scheme="https", netloc=r"^public-crest.eveonline.com$", path=r"^/queryString/?$")
        def test_qs(url, request):
            self.assertEqual(url.query, "query=string")
            return {"status_code": 200, "content": {}}

        @httmock.urlmatch(scheme="https", netloc=r"^public-crest.eveonline.com$", path=r"^/getPage/?$")
        def test_pagination(url, request):
            self.assertEqual(url.query, "page=2")
            return {"status_code": 200, "content": {}}

        with httmock.HTTMock(test_qs, test_pagination, *all_mocks):
            eve = pycrest.EVE()
            eve().queryString(query="string")
            eve.paginatedData()

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
            # cache miss
            eve = pycrest.EVE(cache_dir='/cachedir')
            eve()

            # cache hit
            eve = pycrest.EVE(cache_dir='/cachedir')
            eve()

            # stale cache hit
            ls = list(os.listdir('/cachedir'))
            self.assertEquals(len(ls), 1)
            path = os.path.join('/cachedir', ls[0])

            recf = open(path, 'r')
            rec = pickle.loads(zlib.decompress(recf.read()))
            recf.close()
            rec['expires'] = 1

            recf = open(path, 'w')
            recf.write(zlib.compress(pickle.dumps(rec)))
            recf.close()

            eve = pycrest.EVE(cache_dir='/cachedir')
            eve()


            testing = pycrest.EVE(testing=True)
            self.assertEqual(testing._public_endpoint, "http://public-crest-sisi.testeveonline.com/")

    def test_headers(self):
        _self = self
        @httmock.all_requests
        def custom_header(url, request):
            _self.assertIn("X-PyCrest-Testing", request.headers)
            _self.assertEqual(request.headers["X-PyCrest-Testing"], "True")

        @httmock.all_requests
        def no_custom_header(url, request):
            self.assertNotIn("X-PyCrest-Testing", request.headers)

        with httmock.HTTMock(no_custom_header):
            eve = pycrest.EVE()
            eve()
        with httmock.HTTMock(custom_header):
            eve = pycrest.EVE(additional_headers={"X-PyCrest-Testing": "True"})
            eve()

    def test_user_agent(self):
        @httmock.all_requests
        def default_useragent(url, request):
            self.assertEqual(request.headers["User-Agent"],
                    "PyCrest/{0}".format(pycrest.version))

        @httmock.all_requests
        def custom_useragent(url, request):
            self.assertEqual(request.headers["User-Agent"], "Testing 123")

        with httmock.HTTMock(default_useragent):
            eve = pycrest.EVE()
            eve()
        with httmock.HTTMock(custom_useragent):
            eve = pycrest.EVE(user_agent="Testing 123")
            eve()

    def test_params(self):
        @httmock.all_requests
        def no_params(url, request):
            self.assertEqual(url.query, "")
            return {"status_code": 200, "content": {}}

        @httmock.all_requests
        def with_custom_params(url, request):
            self.assertNotEqual(url.query, "")
            return {"status_code": 200, "content": {}}

        with httmock.HTTMock(no_params):
            eve = pycrest.EVE()
            eve.get("http://example.com")
        with httmock.HTTMock(with_custom_params):
            eve = pycrest.EVE()
            eve.get("http://example.com", params={"Foo": "Bar"})


class TestAuthorization(unittest.TestCase):
    @mock.patch('os.path.isdir')
    @mock.patch('os.mkdir')
    @mock.patch('os.unlink')
    @mock.patch('os.listdir')
    @mock.patch('%s.open' % builtins_name)
    def test_authorize(self, mock_open, mock_listdir, mock_unlink, mock_mkdir, mock_isdir):
        client_id = "bar"
        api_key = "foo"
        code = "foobar"
        access_token = "123asd"
        refresh_token = "asd123"

        fs = MockFilesystem()
        mock_isdir.side_effect = fs.isdir
        mock_mkdir.side_effect = fs.mkdir
        mock_unlink.side_effect = fs.unlink
        mock_listdir.side_effect = fs.listdir
        mock_open.side_effect = fs.open

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

        with httmock.HTTMock(token_mock, *all_mocks) as fake_http:
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

            eve = pycrest.EVE(api_key=api_key, client_id=client_id)
            con = eve.authorize(code)
            self.assertEqual(con().marketData().totalCount, 2)
            self.assertEqual(con().marketData().totalCount, 2)

            # auth with refresh token
            con = eve.refr_authorize(con.refresh_token)
            self.assertRaises(AttributeError, con.__getattr__, 'marketData')
            con()
            self.assertEqual(con.marketData.href, "https://public-crest.eveonline.com/market/prices/")
            self.assertEqual(con.marketData().totalCount, 2)
            self.assertEqual(con.marketData().items[1].type.name, "Rifter")

            # fail auth with refresh token
            self.assertRaises(APIException, lambda: eve.refr_authorize('notright'))

            # auth with temp token
            con = eve.temptoken_authorize(con.token,
                                          con.expires - time.time(),
                                          con.refresh_token)
            self.assertRaises(AttributeError, con.__getattr__, 'marketData')
            con()
            self.assertEqual(con.marketData.href, "https://public-crest.eveonline.com/market/prices/")
            self.assertEqual(con.marketData().totalCount, 2)
            self.assertEqual(con.marketData().items[1].type.name, "Rifter")

            # test auto-refresh of expired token
            con = eve.temptoken_authorize(access_token,
                                          -1,
                                          refresh_token)
            con().marketData()
            self.assertGreater(con.expires, time.time())

            # test cache miss
            eve = pycrest.EVE(api_key=api_key, client_id=client_id, cache_dir='/cachedir')
            con = eve.authorize(code)
            times_get = fake_http.call_count
            con()
            self.assertEqual(fake_http.call_count, times_get + 1)

            # test cache hit
            times_get = fake_http.call_count
            con()
            self.assertEqual(fake_http.call_count, times_get)

            # test cache stale
            ls = list(os.listdir('/cachedir'))
            self.assertEquals(len(ls), 1)
            path = os.path.join('/cachedir', ls[0])

            recf = open(path, 'r')
            rec = pickle.loads(zlib.decompress(recf.read()))
            recf.close()
            rec['expires'] = 1

            recf = open(path, 'w')
            recf.write(zlib.compress(pickle.dumps(rec)))
            recf.close()

            times_get = fake_http.call_count
            con().marketData()
            self.assertEqual(times_get + 1, fake_http.call_count)


class TestApiCache(unittest.TestCase):
    @mock.patch('os.path.isdir')
    @mock.patch('os.mkdir')
    @mock.patch('os.unlink')
    @mock.patch('%s.open' % builtins_name)
    def test_apicache(self, mock_open, mock_unlink, mock_mkdir, mock_isdir):
        fs = MockFilesystem()
        mock_isdir.side_effect = fs.isdir
        mock_mkdir.side_effect = fs.mkdir
        mock_unlink.side_effect = fs.unlink
        mock_open.side_effect = fs.open

        # Just because pragma: no cover is ugly
        cache = pycrest.eve.APICache()
        self.assertRaises(NotImplementedError, lambda: cache.get("foo"))
        self.assertRaises(NotImplementedError, lambda: cache.put("foo", "bar"))
        self.assertRaises(NotImplementedError, lambda: cache.invalidate("foo"))

        # Test default DictCache
        crest = pycrest.EVE()
        self.assertEqual(type(crest.cache).__name__, "DictCache")
        crest.cache.invalidate('nxkey')
        self.assertEqual(crest.cache.get('nxkey'), None)
        crest.cache.put('key', 'value')
        self.assertEqual(crest.cache.get('key'), 'value')


        # with mkdir needed
        crest = pycrest.EVE(cache_dir="/cachedir")

        # without mkdir now
        crest = pycrest.EVE(cache_dir="/cachedir")

        # cache created?
        self.assertEqual(type(crest.cache).__name__, "FileCache")

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
        # Use _getpath for platform independence
        fs.mkdir(crest.cache._getpath('key'))
        self.assertRaises(OSError, lambda: crest.cache.invalidate('key'))
        self.assertRaises(IOError, lambda: crest.cache.get('key'))

    def test_cache_control(self):
        @httmock.all_requests
        def root_m(url, request):
            body = {
                "shouldCache": {
                    "href": "https://foo.bar/shouldCache/"
                },
                "shouldNotCache": {
                    "href": "https://foo.bar/shouldNotCache/"
                },
                "noCache": {
                    "href": "https://foo.bar/noCache/"
                },
                "noStore": {
                    "href": "https://foo.bar/noStore/"
                },
                "brokenInt": {
                    "href": "https://foo.bar/brokenInt"
                }
            }
            return {
                "status_code": 200,
                "content": body
            }

        @httmock.urlmatch(path=r'^/shouldCache/?$')
        def shouldCache(url, request):
            return {
                "status_code": 200,
                "content": {
                    "href": "shouldCache"
                },
                "headers": {
                    "Cache-Control": "private, max-age=300"
                }
            }

        @httmock.urlmatch(path=r'^/shouldNotCache/?$')
        def shouldNotCache(url, request):
            return {
                "status_code": 200,
                "content": {
                    "href": "shouldNotCache"
                }
            }

        @httmock.urlmatch(path=r'^/noCache/?$')
        def noCache(url, request):
            return {
                "status_code": 200,
                "content": {
                    "href": "noCache"
                },
                "headers": {
                    "Cache-Control": "no-cache, max-age=300"
                }
            }

        @httmock.urlmatch(path=r'^/noStore/?$')
        def noStore(url, request):
            return {
                "status_code": 200,
                "content": {
                    "href": "noStore"
                },
                "headers": {
                    "Cache-Control": "no-store, max-age=300"
                }
            }

        @httmock.urlmatch(path=r'^/brokenInt/?$')
        def brokenInt(url, request):
            return {
                "status_code": 200,
                "content": {
                    "href": "brokenInt"
                },
                "headers": {
                    "Cache-Control": "private, max-age=asd"
                }
            }

        with httmock.HTTMock(shouldCache, shouldNotCache, noCache, noStore, brokenInt, root_m) as fake_http:
            eve = pycrest.EVE()
            eve()

            call_count = fake_http.call_count
            eve.shouldCache()
            self.assertEqual(fake_http.call_count, call_count + 1)
            call_count = fake_http.call_count
            eve.shouldCache()
            self.assertEqual(fake_http.call_count, call_count)

            call_count = fake_http.call_count
            eve.shouldNotCache()
            self.assertEqual(fake_http.call_count, call_count + 1)
            call_count = fake_http.call_count
            eve.shouldNotCache()
            self.assertEqual(fake_http.call_count, call_count + 1)

            call_count = fake_http.call_count
            eve.noCache()
            self.assertEqual(fake_http.call_count, call_count + 1)
            call_count = fake_http.call_count
            eve.noCache()
            self.assertEqual(fake_http.call_count, call_count + 1)

            call_count = fake_http.call_count
            eve.noStore()
            self.assertEqual(fake_http.call_count, call_count + 1)
            call_count = fake_http.call_count
            eve.noStore()
            self.assertEqual(fake_http.call_count, call_count + 1)

            call_count = fake_http.call_count
            eve.brokenInt()
            self.assertEqual(fake_http.call_count, call_count + 1)
            call_count = fake_http.call_count
            eve.brokenInt()
            self.assertEqual(fake_http.call_count, call_count + 1)