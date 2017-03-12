import errno
import mock
import sys
import unittest

from pycrest.cache import APICache
from pycrest.cache import DictCache
from pycrest.cache import DummyCache
from pycrest.cache import FileCache
from pycrest.cache import MemcachedCache

try:
    import __builtin__
    builtins_name = __builtin__.__name__
except ImportError:
    import builtins
    builtins_name = builtins.__name__


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


class TestDummyCache(unittest.TestCase):

    def setUp(self):
        self.c = DummyCache()
        self.c.put('never_stored', True)

    def test_put(self):
        self.assertNotIn('never_stored', self.c._dict)

    def test_get(self):
        self.assertEqual(self.c.get('never_stored'), None)

    def test_invalidate(self):
        self.c.invalidate('never_stored')
        self.assertIsNone(self.c.get('never_stored'))


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
