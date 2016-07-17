'''
Created on Jun 27, 2016

@author: henk
'''
import sys
from pycrest.eve import EVE, DictCache, APICache, FileCache, APIObject,\
    MemcachedCache
import httmock
import pycrest
import mock
import errno
from pycrest.errors import APIException
from requests.models import PreparedRequest
import unittest

try:
    import __builtin__
    builtins_name = __builtin__.__name__
except ImportError:
    import builtins
    builtins_name = builtins.__name__


@httmock.urlmatch(
    scheme="https",
    netloc=r"(api-sisi\.test)?(crest-tq\.)?eveonline\.com$",
    path=r"^/?$")
def root_mock(url, request):
    return httmock.response(
        status_code=200,
        content='''{
    "marketData": {
        "href": "https://crest-tq.eveonline.com/market/prices/"
    },
    "incursions": {
        "href": "https://crest-tq.eveonline.com/incursions/"
    },
    "status": {
        "eve": "online"
    },
    "queryString": {
        "href": "https://crest-tq.eveonline.com/queryString/"
    },
    "paginatedData": {
        "href": "https://crest-tq.eveonline.com/getPage/?page=2"
    },
    "list": [
        "item1",
        {
            "name": "item2"
        },
        [
            "item3"
        ]
    ]
}''', headers={"Cache-Control": "private, max-age=300"})


@httmock.urlmatch(
    scheme="https",
    netloc=r"(sisilogin\.test)?(login\.)?eveonline\.com$",
    path=r"^/oauth/verify/?$")
def verify_mock(url, request):
    return {
        "status_code": 200,
        "content": {"CharacterName": "Foobar"},
    }


@httmock.all_requests
def fallback_mock(url, request):
    print("No mock for: %s" % request.url)
    return httmock.response(
        status_code=404,
        content='{}')


@httmock.urlmatch(
    scheme="https",
    netloc=r"(sisilogin\.test)?(login\.)?eveonline\.com$",
    path=r"^/oauth/?")
def mock_login(url, request):
    return httmock.response(
        status_code=200,
        content='{"access_token": "access_token", "refresh_token": "r'
        'efresh_token", "expires_in": 300}')


@httmock.urlmatch(
    scheme="https",
    netloc=r"(api-sisi\.test)?(crest-tq\.)?eveonline\.com$",
    path=r"^/market/prices/?$")
def market_prices_mock(url, request):
    return httmock.response(
        status_code=200,
        content='{"totalCount_str": "10213", "items": [], "pageCount": 1, "pa'
        'geCount_str": "1", "totalCount": 10213}')

all_httmocks = [
    root_mock,
    mock_login,
    verify_mock,
    market_prices_mock,
    fallback_mock]


class TestEVE(unittest.TestCase):

    def setUp(self):
        self.api = EVE(
            client_id=1,
            redirect_uri='http://localhost:8000/complete/eveonline/')

    def test_endpoint_default(self):
        self.assertEqual(
            self.api._endpoint,
            'https://crest-tq.eveonline.com/')
        self.assertEqual(
            self.api._image_server,
            'https://imageserver.eveonline.com/')
        self.assertEqual(
            self.api._oauth_endpoint,
            'https://login.eveonline.com/oauth')

    def test_endpoint_testing(self):
        api = EVE(testing=True)
        self.assertEqual(
            api._endpoint,
            'https://api-sisi.testeveonline.com/')
        # imageserver. is given an 302 redirect to image. on testeveonline.com
        #   we might just as well keep using the old URL for now
        self.assertEqual(
            api._image_server,
            'https://image.testeveonline.com/')
        self.assertEqual(
            api._oauth_endpoint,
            'https://sisilogin.testeveonline.com/oauth')

    def test_auth_uri(self):
        self.assertEqual(
            self.api.auth_uri(),
            'https://login.eveonline.com/oauth/authorize?response_type=code&r'
            'edirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcomplete%2Feveonline'
            '%2F&client_id=1')

    def test_authorize(self):

        with httmock.HTTMock(*all_httmocks):
            self.api.authorize(code='code')

    def test_authorize_non_200(self):

        @httmock.all_requests
        def mock_login(url, request):
            return httmock.response(status_code=204)

        with httmock.HTTMock(mock_login):
            self.assertRaises(APIException, self.api.authorize, code='code')

    def test_refr_authorize(self):
        with httmock.HTTMock(*all_httmocks):
            self.api.refr_authorize('refresh_token')

    def test_temptoken_authorize(self):
        with httmock.HTTMock(*all_httmocks):
            self.api.temptoken_authorize(access_token='access_token',
                                         expires_in=300,
                                         refresh_token='refresh_token')


class TestAuthedConnection(unittest.TestCase):

    def setUp(self):
        with httmock.HTTMock(*all_httmocks):
            self.api = EVE()

        with httmock.HTTMock(*all_httmocks):
            self.authed = self.api.authorize(code='code')

    def test_call(self):
        with httmock.HTTMock(*all_httmocks):
            self.authed()

    def test_whoami(self):
        with httmock.HTTMock(*all_httmocks):
            self.authed.whoami()

    def test_refresh(self):
        with httmock.HTTMock(*all_httmocks):
            self.authed.refresh()

    def test_refresh_on_get(self):
        self.authed.expires = 0
        with httmock.HTTMock(*all_httmocks):
            self.authed()


class TestAPIConnection(unittest.TestCase):

    def setUp(self):
        self.api = EVE()

    def test_user_agent(self):
        @httmock.all_requests
        def default_user_agent(url, request):
            user_agent = request.headers.get('User-Agent', None)
            self.assertEqual(
                user_agent, 'PyCrest/{0} +https://github.com/pycrest/PyCrest'
                .format(pycrest.version))

        with httmock.HTTMock(default_user_agent):
            EVE()

        @httmock.all_requests
        def customer_user_agent(url, request):
            user_agent = request.headers.get('User-Agent', None)
            self.assertEqual(
                user_agent,
                'PyCrest-Testing/{0} +https://github.com/pycrest/PyCrest'
                .format(pycrest.version))

        with httmock.HTTMock(customer_user_agent):
            EVE(user_agent='PyCrest-Testing/{0} +https://github.com/pycrest/P'
                'yCrest'.format(pycrest.version))

    def test_headers(self):

        # Check default header
        @httmock.all_requests
        def check_default_headers(url, request):
            self.assertNotIn('PyCrest-Testing', request.headers)

        with httmock.HTTMock(check_default_headers):
            EVE()

        # Check custom header
        def check_custom_headers(url, request):
            self.assertIn('PyCrest-Testing', request.headers)

        with httmock.HTTMock(check_custom_headers):
            EVE(additional_headers={'PyCrest-Testing': True})

    def test_default_cache(self):
        self.assertTrue(isinstance(self.api.cache, DictCache))

    def test_callable_cache(self):
        class CustomCache(object):
            pass
        eve = EVE(cache=CustomCache)
        self.assertTrue(isinstance(eve.cache, CustomCache))

    def test_apicache(self):
        eve = EVE(cache=DictCache())
        self.assertTrue(isinstance(eve.cache, DictCache))

    @mock.patch('os.path.isdir', return_value=False)
    @mock.patch('os.mkdir')
    def test_cache_dir(self, mkdir_function, isdir_function):
        eve = EVE(cache_dir=TestFileCache.DIR)
        self.assertEqual(eve.cache_dir, TestFileCache.DIR)
        self.assertTrue(isinstance(eve.cache, FileCache))

    def test_default_url(self):

        @httmock.all_requests
        def root_mock(url, request):
            self.assertEqual(url.path, '/')
            self.assertEqual(url.query, '')
            return {'status_code': 200,
                    'content': '{}'.encode('utf-8')}

        with httmock.HTTMock(root_mock):
            self.api()

    def test_parse_parameters_url(self):

        @httmock.all_requests
        def key_mock(url, request):
            self.assertEqual(url.path, '/')
            self.assertEqual(url.query, 'key=value1')
            return {'status_code': 200,
                    'content': '{}'.encode('utf-8')}

        with httmock.HTTMock(key_mock):
            self.api.get('https://crest-tq.eveonline.com/?key=value1')

    def test_parse_parameters_override(self):

        @httmock.all_requests
        def key_mock(url, request):
            self.assertEqual(url.path, '/')
            self.assertEqual(url.query, 'key=value2')
            return {'status_code': 200,
                    'content': '{}'.encode('utf-8')}

        with httmock.HTTMock(key_mock):
            self.api.get(
                'https://crest-tq.eveonline.com/?key=value1',
                dict(key='value2'))

    def test_cache_hit(self):

        @httmock.all_requests
        def prime_cache(url, request):
            headers = {'content-type': 'application/json',
                       'Cache-Control': 'max-age=300;'}
            return httmock.response(200, '{}'.encode('utf-8'), headers)

        with httmock.HTTMock(prime_cache):
            self.assertEqual(self.api()._dict, {})

        @httmock.all_requests
        def cached_request(url, request):
            raise RuntimeError(
                'A cached request should never yield a HTTP request')

        with httmock.HTTMock(cached_request):
            self.api._data = None
            self.assertEqual(self.api()._dict, {})

    def test_cache_invalidate(self):
        @httmock.all_requests
        def prime_cache(url, request):
            headers = {'content-type': 'application/json',
                       'Cache-Control': 'max-age=300;'}
            return httmock.response(
                200, '{"cached": true}'.encode('utf-8'), headers)

        # Prime cache and force the expiration
        with httmock.HTTMock(prime_cache):
            self.api()
            # Nuke _data so the .get() is actually being called the next call
            self.api._data = None
            for key in self.api.cache._dict:
                # Make sure the cache is concidered 'expired'
                self.api.cache._dict[key]['expires'] = 0

        @httmock.all_requests
        def expired_request(url, request):
            self.assertTrue(isinstance(request, PreparedRequest))
            return httmock.response(200, '{}'.encode('utf-8'))

        with httmock.HTTMock(expired_request):
            self.api()

    def test_non_http_200(self):

        @httmock.all_requests
        def non_http_200(url, request):
            return {'status_code': 404}

        with httmock.HTTMock(non_http_200):
            self.assertRaises(APIException, self.api)

    def test_get_expires(self):
        # No header at all
        r = httmock.response(200, '{}'.encode('utf-8'))
        self.assertEqual(self.api._get_expires(r), 0)

        # Cache-Control header with no-cache
        r = httmock.response(status_code=200,
                             content='{}'.encode('utf-8'),
                             headers={'Cache-Control': 'no-cache'})
        self.assertEqual(self.api._get_expires(r), 0)

        # Cache-Control header with no-store
        r = httmock.response(status_code=200,
                             content='{}'.encode('utf-8'),
                             headers={'Cache-Control': 'no-store'})
        self.assertEqual(self.api._get_expires(r), 0)

        # Cache-Control header with wrong content
        r = httmock.response(status_code=200,
                             content='{}'.encode('utf-8'),
                             headers={'Cache-Control': 'no-way'})
        self.assertEqual(self.api._get_expires(r), 0)

        # Cache-Control header with max-age=300
        r = httmock.response(status_code=200,
                             content='{}'.encode('utf-8'),
                             headers={'Cache-Control': 'max-age=300'})
        self.assertEqual(self.api._get_expires(r), 300)

    def test_session_mock(self):
        # Check default header
        @httmock.all_requests
        def expired_request(url, request):
            print(url)
            print(request)
            self.assertTrue(isinstance(request, PreparedRequest))
            return httmock.response(200, '{}'.encode('utf-8'))

        with httmock.HTTMock(expired_request):
            self.api()


class TestAPICache(unittest.TestCase):

    def setUp(self):
        self.c = APICache()

    def test_put(self):
        self.assertRaises(NotImplementedError, self.c.get, 'key')

    def test_get(self):
        self.assertRaises(NotImplementedError, self.c.put, 'key', 'val')

    def test_invalidate(self):
        self.assertRaises(NotImplementedError, self.c.invalidate, 'key')


class TestDictCache(unittest.TestCase):

    def setUp(self):
        self.c = DictCache()
        self.c.put('key', True)

    def test_put(self):
        self.assertEqual(self.c._dict['key'], True)

    def test_get(self):
        self.assertEqual(self.c.get('key'), True)

    def test_invalidate(self):
        self.c.invalidate('key')
        self.assertIsNone(self.c.get('key'))

    def test_cache_dir(self):
        pass


class TestFileCache(unittest.TestCase):
    '''
    Class for testing the filecache

    TODO: Debug wth this test is creating an SSL connection
    '''

    DIR = '/tmp/TestFileCache'

    @mock.patch('os.path.isdir')
    @mock.patch('os.mkdir')
    @mock.patch('{0}.open'.format(builtins_name))
    def setUp(self, open_function, mkdir_function, isdir_function):
        self.c = FileCache(TestFileCache.DIR)
        self.c.put('key', 'value')

    @mock.patch('os.path.isdir', return_value=False)
    @mock.patch('os.mkdir')
    def test_init(self, mkdir_function, isdir_function):
        c = FileCache(TestFileCache.DIR)

        # Ensure path has been set
        self.assertEqual(c.path, TestFileCache.DIR)

        # Ensure we checked if the dir was already there
        args, kwargs = isdir_function.call_args
        self.assertEqual((TestFileCache.DIR,), args)

        # Ensure we called mkdir with the right args
        args, kwargs = mkdir_function.call_args
        self.assertEqual((TestFileCache.DIR, 0o700), args)

#     @unittest.skip("https://github.com/pycrest/PyCrest/issues/30")
#     def test_getpath(self):
#         self.assertEqual(self.c._getpath('key'),
#                          os.path.join(TestFileCache.DIR,
#                                       '1140801208126482496.cache'))

    def test_get_uncached(self):
        # Check non-existant key
        self.assertIsNone(self.c.get('nope'))

    @mock.patch('builtins.open')
    def test_get_cached(self, open_function):
        self.assertEqual(self.c.get('key'), 'value')

    @unittest.skipIf(
        sys.version_info < (
            3,), 'Python 2.x uses a diffrent protocol')
    @mock.patch('{0}.open'.format(builtins_name), mock.mock_open(
        read_data=b'x\x9ck`\ne-K\xcc)M-d\xd0\x03\x00\x17\xde\x03\x99'))
    def test_get_cached_file_py3(self):
        del(self.c._cache['key'])
        self.assertEqual(self.c.get('key'), 'value')

    @unittest.skipIf(
        sys.version_info > (
            3,), 'Python 3.x uses a diffrent protocol')
    @mock.patch('{0}.open'.format(builtins_name), mock.mock_open(
        read_data='x\x9ck`\ne-K\xcc)M-d\xd0\x03\x00\x17\xde\x03\x99'))
    def test_get_cached_file_py2(self):
        del(self.c._cache['key'])
        self.assertEqual(self.c.get('key'), 'value')

    @mock.patch('os.unlink')
    def test_invalidate(self, unlink_function):
        # Make sure our key is here in the first place
        self.assertIn('key', self.c._cache)

        # Unset the key and ensure unlink() was called
        self.c.invalidate('key')
        self.assertTrue(unlink_function.called)
        # TODO: When paths are predictable check the args
        #   See https://github.com/pycrest/PyCrest/issues/30

    @mock.patch(
        'os.unlink',
        side_effect=OSError(
            errno.ENOENT,
            'No such file or directory'))
    def test_unlink_exception(self, unlink_function):
        self.assertIsNone(self.c.invalidate('key'))


class TestMemcachedCache(unittest.TestCase):
    '''A very basic MemcachedCache TestCase

    Primairy goal of this unittest is to get the coverage up
    to spec. Should probably make use of `mockcache` in the future'''

    memcache_mock = mock.MagicMock()
    memcache_mock.get.return_value = 'value'

    @mock.patch('memcache.Client', return_value=memcache_mock)
    def setUp(self, mock_memcache):
        self.c = MemcachedCache(['127.0.0.1:11211'])

    def test_put(self):
        self.c.put('key', 'value')

    def test_get(self):
        self.assertEqual(self.c.get('key'), 'value')

    def test_invalidate(self):
        self.c.invalidate('key')


class TestAPIObject(unittest.TestCase):

    def setUp(self):
        self.api = EVE()
        with httmock.HTTMock(*all_httmocks):
            self.api()

    def test_getattr(self):
        res = self.api().list
        self.assertEqual(res[0], 'item1')

    def test_getattr_exception(self):
        self.assertRaises(
            AttributeError,
            getattr,
            self.api,
            "invalid_property")

    def test_call(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api().list
        self.assertTrue(isinstance(res, list))

    def test_call_href(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api().marketData()
        self.assertTrue(isinstance(res, APIObject))

if __name__ == "__main__":
    unittest.main()
