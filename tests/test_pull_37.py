'''
Created on Jun 27, 2016

@author: henk
'''
from pycrest.eve import EVE, APIObject
import httmock
import unittest

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
    "perverse": {
        "href": "https://crest-tq.eveonline.com/perverse/"
    }}''', headers={"content-type": "application/vnd.ccp.eve.Api-v5+json; charset=utf-8"})


@httmock.urlmatch(
    scheme="https",
    netloc=r"(api-sisi\.test)?(crest-tq\.)?eveonline\.com$",
    path=r"^/market/prices/?$")
def market_prices_mock(url, request):
    return httmock.response(
        status_code=200,
        content='{"result": "10213", "items": [], "status_code": 500, "pa'
        'geCount_str": "1", "totalCount": 10213}',
        headers={"content-type": "application/vnd.ccp.eve.Api-v5+json; charset=utf-8"})

@httmock.urlmatch(
    scheme="https",
    netloc=r"(api-sisi\.test)?(crest-tq\.)?eveonline\.com$",
    path=r"^/perverse/?$")
def perverse_mock(url, request):
    return httmock.response(
        status_code=200,
        content='''{
    "result": {
        "result": "10213",
        "status_code": 500
    },
    "items": [],
    "status_code": {
        "result": "10214",
        "status_code": 501
    },
    "pageCount_str": "1",
    "totalCount": 10213
}''',
        headers={"content-type": "application/vnd.ccp.eve.Api-v5+json; charset=utf-8"})


all_httmocks = [
    root_mock,
    market_prices_mock,
    perverse_mock]


class TestEVE(unittest.TestCase):

    def setUp(self):
        self.api = EVE()

    def test_root(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api()
            self.assertTrue(isinstance(res, APIObject))
            self.assertEqual(res.endpoint_version, 'application/vnd.ccp.eve.Api-v5+json')
            self.assertEqual(res.status_code, 200)

    def test_market_price(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api().marketData()
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.result.status_code, 500)
            self.assertEqual(res.result.result, '10213')

    def test_perverse(self):
        with httmock.HTTMock(*all_httmocks):
            res = self.api().perverse()
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.pageCount_str, '1')
            self.assertEqual(res.result.pageCount_str, '1')
            self.assertEqual(res.totalCount, 10213)
            self.assertEqual(res.result.totalCount, 10213)
            self.assertEqual(res.items, [])
            self.assertEqual(res.result.items, [])
            self.assertEqual(res.result.status_code.status_code, 501)
            self.assertEqual(res.result.status_code.result, '10214')
            self.assertEqual(res.result.result.result, '10213')

if __name__ == "__main__":
    unittest.main()
