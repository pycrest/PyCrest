import os
import base64
import requests
import time
import urlparse
import zlib
import cPickle
from pycrest import version
from pycrest.compat import bytes_, text_
from pycrest.errors import APIException

try:
    from urllib.parse import quote
except ImportError:  # pragma: no cover
    from urllib import quote
import logging

logger = logging.getLogger("pycrest.eve")


class APICache(object):
    def __init__(self, path):
        self._cache = {}
        self.path = path
        if not os.path.isdir(self.path):
            os.mkdir(self.path, mode=0700)

    def _getpath(self, key):
        return os.path.join(self.path, str(hash(key)), '.cache')

    def put(self, key, value):
        with open(self._getpath(key), 'w') as f:
            f.write(zlib.compress(cPickle.dumps(value, -1)))
        self._cache[key] = value

    def get(self, key):
        if key in self._cache:
            return self._cache[key]

        try:
            with open(self._getpath(key), 'r') as f:
                return cPickle.loads(zlib.decompress(f.read()))
        except IOError, ex:
            if ex.errno == 2:  # file does not exist (yet)
                return None
            else:
                raise ex

    def invalidate(self, key):
        self._cache.pop(key, None)

        try:
            os.unlink(self._getpath(key))
        except OSError, ex:
            if ex.errno == 2:  # does not exist
                pass
            else:
                raise ex


class APIConnection(object):
    def __init__(self, additional_headers=None, user_agent=None, cache_time=300, cache_dir=None):
        self._headers = {} if not additional_headers else additional_headers
        self._useragent = "PyCrest v %s" % version if not user_agent else user_agent
        self.cache_time = cache_time
        self.session = requests.Session()
        if cache_dir:
            self.cache = APICache(cache_dir)
        else:
            self.cache = None

    def get(self, resource, params={}):
        headers = {
            "User-Agent": self._useragent,
            "Accept": "application/json"
        }
        headers.update(self._headers)

        # remove params from resource URI (needed for paginated stuff)
        qs = urlparse.urlparse(resource).query
        prms = {tup[0]: tup[1] for tup in urlparse.parse_qsl(qs)}

        # params supplied to self.get() override parsed params
        for key in params:
            prms[key] = params[key]

        # check cache
        if self.cache:
            key = (resource, frozenset(headers.items()), frozenset(prms.items()))
            cached = self.cache.get(key)
            if cached and time.time() - cached['timestamp'] < self.cache_time:
                return cached['payload']
            elif cached:
                self.cache.invalidate(key)

        logger.debug('Getting resource %s (params=%s)', resource, prms)
        res = self.session.get(resource, headers=headers, params=prms)
        if res.status_code != 200:
            raise APIException("Got unexpected status code from server: %i" % res.status_code)

        ret = res.json()

        # cache result
        if self.cache:
            key = (resource, frozenset(headers.items()), frozenset(prms.items()))
            self.cache.put(key, {'timestamp': time.time(), 'payload': ret})

        return ret


class EVE(APIConnection):
    def __init__(self, **kwargs):
        self.api_key = kwargs.get('api_key', None)
        self.client_id = kwargs.get('client_id', None)
        self.redirect_uri = kwargs.get('redirect_uri', None)
        if kwargs.get('testing', None):
            self._public_endpoint = "http://public-crest-sisi.testeveonline.com/"
            self._authed_endpoint = "https://api-sisi.testeveonline.com/"
            self._image_server = "https://image.testeveonline.com/"
            self._oauth_endpoint = "https://sisilogin.testeveonline.com/oauth"
        else:
            self._public_endpoint = "https://public-crest.eveonline.com/"
            self._authed_endpoint = "https://crest-tq.eveonline.com/"
            self._image_server = "https://image.eveonline.com/"
            self._oauth_endpoint = "https://login.eveonline.com/oauth"
        self._endpoint = self._public_endpoint
        self._cache = {}
        self._data = None

        APIConnection.__init__(self, user_agent=kwargs.get('user_agent', 'PyCrest - v %s' % version),
                               cache_time=kwargs.get('cache_time', 600))

    def __call__(self):
        if not self._data:
            self._data = APIObject(self.get(self._endpoint), self)
        return self._data

    def __getattr__(self, item):
        return self._data.__getattr__(item)
    def auth_uri(self, scopes=None, state=None):
        s = [] if not scopes else scopes
        return "%s/authorize?response_type=code&redirect_uri=%s&client_id=%s%s%s" % (
            self._oauth_endpoint,
            quote(self.redirect_uri, safe=''),
            self.client_id,
            "&scope=%s" % ','.join(s) if scopes else '',
            "&state=%s" % state if state else ''
        )

    def _authorize(self, params):
        auth = text_(base64.b64encode(bytes_("%s:%s" % (self.client_id, self.api_key))))
        headers = {"Authorization": "Basic %s" % auth}
        res = self.session.post("%s/token" % self._oauth_endpoint, params=params, headers=headers)
        if res.status_code != 200:
            raise APIException("Got unexpected status code from API: %i" % res.status_code)
        return res.json()

    def authorize(self, code):
        res = self._authorize(params={"grant_type": "authorization_code", "code": code})
        return AuthedConnection(res, self._authed_endpoint, self._oauth_endpoint, self.client_id, self.api_key)

    def refr_authorize(self, refresh_token):
        res = self._authorize(params={"grant_type": "refresh_token", "refresh_token": refresh_token})
        return AuthedConnection({'access_token': res['access_token'],
                                 'refresh_token': refresh_token,
                                 'expires_in': res['expires_in']},
                                self._authed_endpoint,
                                self._oauth_endpoint,
                                self.client_id,
                                self.api_key)


class AuthedConnection(EVE):
    def __init__(self, res, endpoint, oauth_endpoint, client_id=None, api_key=None, **kwargs):
        EVE.__init__(self, **kwargs)
        self.client_id = client_id
        self.api_key = api_key
        self.token = res['access_token']
        self.refresh_token = res['refresh_token']
        self.expires = int(time.time()) + res['expires_in']
        self._oauth_endpoint = oauth_endpoint
        self._endpoint = endpoint
        self._headers.update({"Authorization": "Bearer %s" % self.token})

    def __call__(self):
        if not self._data:
            if int(time.time()) >= self.expires:
                self.refresh()
            self._data = APIObject(self.get(self._endpoint), self)
        return self._data

    def whoami(self):
        if 'whoami' not in self._cache:
            self._cache['whoami'] = self.get("https://login.eveonline.com/oauth/verify")
        return self._cache['whoami']

    def refresh(self):
        res = self._authorize(params={"grant_type": "refresh_token", "refresh_token": self.refresh_token})
        self.token = res['access_token']
        self.expires = int(time.time()) + res['expires_in']
        self._headers.update({"Authorization": "Bearer %s" % self.token})
        return self  # for backwards compatibility


class APIObject(object):
    def __init__(self, parent, connection):
        self._dict = {}
        self.connection = connection
        self._cache = {}
        for k, v in parent.items():
            if type(v) is dict:
                self._dict[k] = APIObject(v, connection)
            elif type(v) is list:
                self._dict[k] = self._wrap_list(v)
            else:
                self._dict[k] = v

    def _wrap_list(self, list_):
        new = []
        for item in list_:
            if type(item) is dict:
                new.append(APIObject(item, self.connection))
            elif type(item) is list:
                new.append(self._wrap_list(item))
            else:
                new.append(item)
        return new

    def __getattr__(self, item):
        return self._dict[item]

    def __call__(self, **kwargs):
        hkwargs = frozenset(kwargs.items())
        cached = hkwargs in self._cache
        if ((not cached) or int(time.time()) - self._cache[hkwargs][0] > self.connection.cache_time) and 'href' in self._dict:
            logger.debug("%s with params %s not yet loaded", self._dict['href'], kwargs)
            self._cache[hkwargs] = (int(time.time()), APIObject(self.connection.get(self._dict['href'], params=kwargs), self.connection))
            return self._cache[hkwargs][1]
        elif cached:
            return self._cache[hkwargs][1]
        else:
            return self

    def __str__(self):  # pragma: no cover
        return self._dict.__str__()

    def __repr__(self):  # pragma: no cover
        return self._dict.__repr__()
