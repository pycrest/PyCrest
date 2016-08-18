from pycrest.errors import APIException, UnsupportedHTTPMethodException
import unittest

try:
    import __builtin__
    builtins_name = __builtin__.__name__
except ImportError:
    import builtins
    builtins_name = builtins.__name__



class TestAPIException(unittest.TestCase):

    def setUp(self):
        pass

    def test_apiexception_data(self):
        e = APIException('http://example.com', 205, {'message' : 'example error'})

        self.assertEqual(
            e.url,
            'http://example.com')

        self.assertEqual(
            e.status_code,
            205)

    def test_apiexception_str_message(self):
        e = APIException('http://example.com', 205, {'message' : 'example error'})

        self.assertIn(
            'example error',
            str(e))

        self.assertIn( '205', str(e) )

    def test_apiexception_str_error(self):
        e = APIException('http://example.com', 205, {'error' : 'example error'})

        self.assertIn(
            'example error',
            str(e))

        self.assertIn( '205', str(e) )



    def test_apiexception_str_no_message(self):
        e = APIException('http://example.com', 205, {'exception_type' : 'wierd'})
        self.assertIn( '205', str(e) )


class TestUnsupportedHTTPMethodException(unittest.TestCase):
    def setUp(self):
        pass

    def test_exception_str(self):
        e = UnsupportedHTTPMethodException('flatten')
        self.assertIn( 'flatten', str(e) )


if __name__ == "__main__":
    unittest.main()
