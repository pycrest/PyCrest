'''
Created on Jun 27, 2016

@author: henk
'''
import httmock
import mock
import pycrest
import unittest

from pycrest.cache import DictCache
from pycrest.cache import DummyCache
from pycrest.cache import FileCache
from pycrest.errors import APIException
from pycrest.errors import UnsupportedHTTPMethodException
from pycrest.eve import APIObject
from pycrest.eve import EVE
from pycrest.events import after_token_refresh
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest

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
    "writeableEndpoint": {
        "href": "https://crest-tq.eveonline.com/writeableMadeUp/"
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
        content='{"access_token": "access_token",'
                ' "refresh_token": "refresh_token",'
                ' "expires_in": 300}')


@httmock.urlmatch(
    scheme="https",
    netloc=r"(api-sisi\.test)?(crest-tq\.)?eveonline\.com$",
    path=r"^/market/prices/?$")
def market_prices_mock(url, request):
    return httmock.response(
        status_code=200,
        content='{"totalCount_str": "10213",'
                ' "items": [],'
                ' "pageCount": 1,'
                ' "pageCount_str": "1",'
                ' "totalCount": 10213}')


@httmock.urlmatch(
    scheme="https",
    netloc=r"(api-sisi\.test)?(crest-tq\.)?eveonline\.com$",
    path=r"^/writeableMadeUp/?$")
def writeable_endpoint_mock(url, request):
    return httmock.response(
        status_code=200,
        content='{}')


all_httmocks = [
    root_mock,
    mock_login,
    verify_mock,
    market_prices_mock,
    writeable_endpoint_mock,
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
            return httmock.response(status_code=204,
                                    content='{}')

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
        def refresh_event_receiver(access_token, refresh_token, expires_in):
            """ fake event receiver to test the signal trigger """
            self.assertEqual(access_token, 'access_token')
            self.assertEqual(refresh_token, 'refresh_token')
            self.assertEqual(expires_in, 300)
        after_token_refresh.add_receiver(refresh_event_receiver)

        with httmock.HTTMock(*all_httmocks):
            self.authed.refresh()

    def test_refresh_on_get(self):
        self.authed.expires = 0
        with httmock.HTTMock(*all_httmocks):
            self.authed()


class TestAPIConnection(unittest.TestCase):
    TEST_DIR = '/tmp/TestFileCache'

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

    def test_custom_transport_adapter(self):
        """ Check if the transport adapter is the one expected
        (especially if we set it)
        """
        class TestHttpAdapter(HTTPAdapter):
            def __init__(self, *args, **kwargs):
                super(TestHttpAdapter, self).__init__(*args, **kwargs)

        class FakeHttpAdapter(object):
            def __init__(self, *args, **kwargs):
                pass

        eve = EVE()
        self.assertTrue(
            isinstance(eve._session.get_adapter('http://'), HTTPAdapter)
        )
        self.assertTrue(
            isinstance(eve._session.get_adapter('https://'), HTTPAdapter)
        )
        self.assertFalse(
            isinstance(eve._session.get_adapter('http://'), TestHttpAdapter)
        )
        self.assertFalse(
            isinstance(eve._session.get_adapter('https://'), TestHttpAdapter)
        )

        eve = EVE(transport_adapter=TestHttpAdapter())
        self.assertTrue(
            isinstance(eve._session.get_adapter('http://'), TestHttpAdapter)
        )
        self.assertTrue(
            isinstance(eve._session.get_adapter('https://'), TestHttpAdapter)
        )

        # check that the wrong httpadapter is not used
        eve = EVE(transport_adapter=FakeHttpAdapter())
        self.assertTrue(
            isinstance(eve._session.get_adapter('http://'), HTTPAdapter)
        )
        self.assertFalse(
            isinstance(eve._session.get_adapter('http://'), FakeHttpAdapter)
        )

        eve = EVE(transport_adapter='')
        self.assertTrue(
            isinstance(eve._session.get_adapter('http://'), HTTPAdapter)
        )

    def test_default_cache(self):
        self.assertTrue(isinstance(self.api.cache, DictCache))

    def test_no_cache(self):
        eve = EVE(cache=None)
        self.assertTrue(isinstance(eve.cache, DummyCache))

    def test_implements_apiobject(self):
        class CustomCache(object):
            pass
        with self.assertRaises(ValueError):
            EVE(cache=CustomCache)

    def test_apicache(self):
        eve = EVE(cache=DictCache())
        self.assertTrue(isinstance(eve.cache, DictCache))

    @mock.patch('os.path.isdir', return_value=False)
    @mock.patch('os.mkdir')
    def test_file_cache(self, mkdir_function, isdir_function):
        file_cache = FileCache(path=TestAPIConnection.TEST_DIR)
        eve = EVE(cache=file_cache)
        self.assertEqual(file_cache.path, TestAPIConnection.TEST_DIR)
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

    def test_caching_arg_hit(self):
        """ Test the caching argument for ApiConnection
        and ApiObject __call__()
        """

        @httmock.urlmatch(
            scheme="https",
            netloc=r"(api-sisi\.test)?(crest-tq\.)?eveonline\.com$",
            path=r"^/market/prices/?$")
        def market_prices_cached_mock(url, request):
            headers = {
                'content-type': 'application/json',
                'Cache-Control': 'max-age=300;'
            }
            return httmock.response(
                status_code=200,
                headers=headers,
                content='{}'.encode('utf-8'))

        with httmock.HTTMock(root_mock, market_prices_cached_mock):
            self.assertEqual(self.api.cache._dict, {})

            self.api(caching=False)
            self.assertEqual(self.api.cache._dict, {})

            self.api._data = None
            self.api()
            self.assertEqual(len(self.api.cache._dict), 1)

            self.assertEqual(self.api().marketData(caching=False)._dict, {})
            self.assertEqual(len(self.api.cache._dict), 1)

            self.assertEqual(self.api().marketData()._dict, {})
            self.assertEqual(len(self.api.cache._dict), 2)

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
            return {'status_code': 404, 'content': {'message': 'not found'}}

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

    def test_call_post(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api().writeableEndpoint(method='post')
        self.assertTrue(isinstance(res, APIObject))

    def test_call_put(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api().writeableEndpoint(method='put')
        self.assertTrue(isinstance(res, APIObject))

    def test_call_delete(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api().writeableEndpoint(method='delete')
        self.assertTrue(isinstance(res, APIObject))

    def test_non_http_200_201_post(self):

        @httmock.all_requests
        def non_http_200(url, request):
            return {'status_code': 404, 'content': {'message': 'not found'}}

        with httmock.HTTMock(non_http_200):
            self.assertRaises(
                APIException,
                self.api.writeableEndpoint,
                method='post'
            )

    def test_non_http_200_put(self):

        @httmock.all_requests
        def non_http_200(url, request):
            return {
                'status_code': 201,
                'content': {'message': 'created new object'}
            }

        with httmock.HTTMock(non_http_200):
            self.assertRaises(
                APIException,
                self.api.writeableEndpoint,
                method='put'
            )

    def test_non_http_200_delete(self):

        @httmock.all_requests
        def non_http_200(url, request):
            return {
                'status_code': 201,
                'content': {'message': 'created new object'}
            }

        with httmock.HTTMock(non_http_200):
            self.assertRaises(
                APIException,
                self.api.writeableEndpoint,
                method='delete'
            )

    # 201 received from successful contact creation via POST
    def test_http_201_post(self):
        @httmock.all_requests
        def http_201(url, request):
            return {
                'status_code': 201,
                'content': {'message': 'created new object'}
            }

        with httmock.HTTMock(http_201):
            res = self.api.writeableEndpoint(method='post')
        self.assertTrue(isinstance(res, APIObject))

    def test_double_call_self(self):
        with httmock.HTTMock(*all_httmocks):
            r1 = self.api()
            r2 = r1()
        self.assertEqual(r1, r2)

    def test_deprecated_parameter_passing(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api.writeableEndpoint(arg1='val1', arg2='val2')

        self.assertTrue(isinstance(res, APIObject))

    def test_string_parameter_passing(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api.writeableEndpoint(
                method='post',
                data='some (json?) data'
            )

        self.assertTrue(isinstance(res, APIObject))

    def test_dict_parameter_passing(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api.writeableEndpoint(data={'arg1': 'val1'})

        self.assertTrue(isinstance(res, APIObject))

    def test_unhandled_http_method_exception(self):
        with httmock.HTTMock(*all_httmocks):
            self.assertRaises(
                UnsupportedHTTPMethodException,
                self.api.writeableEndpoint,
                method='snip'
             )  # made-up http method

if __name__ == "__main__":
    unittest.main()
