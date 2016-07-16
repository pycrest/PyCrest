=======
PyCrest
=======

PyCrest aims to provide a quick and easy way to interact with EVE Online's CREST API

Installation
============

PyCrest can be installed from PyPi with pip::

    $ pip install pycrest


Getting Started
===============

The entry point for the package should be the pycrest.EVE class

.. highlight:: python

>>> import pycrest
>>> eve = pycrest.EVE()

.. highlight:: none

The above code will create an instance of the class that can be used for exploring the EVE public CREST data.  The
connection must be initialized before requests can be made to the CREST API.  Loading is done by calling the class
instance, and consecutive calls will not produce additional overhead:

.. highlight:: python

>>> eve()

.. highlight:: none

Attempting to access CREST resources before the connection is loaded will produce an exception.

Resources for the CREST data are mapped as attributes on the EVE class, allowing you to easily traverse them:

.. highlight:: python

>>> eve.incursions
{u'href': u'https://crest-tq.eveonline.com/incursions/'}

.. highlight:: none

In order to access resources that must be fetched from the API first, you must call the
desired resource:

.. highlight:: python

>>> eve.incursions
{u'href': u'https://crest-tq.eveonline.com/incursions/'}
>>> eve.incursions()
{u'items': [{...}], u'totalCount_str': u'5', u'totalCount': 5, u'pageCount': 1, u'pageCount_str': u'1'}
>>> eve.incursions().totalCount
5

.. highlight:: none

Some useful helper methods to make your life easier / improve readability of next example:

.. highlight:: python

>>> def getByAttrVal(objlist, attr, val):
...     ''' Searches list of dicts for a dict with dict[attr] == val '''
...     matches = [getattr(obj, attr) == val for obj in objlist]
...     index = matches.index(True)  # find first match, raise ValueError if not found
...     return objlist[index]
...
>>> def getAllItems(page):
...     ''' Fetch data from all pages '''
...     ret = page().items
...     while hasattr(page(), 'next'):
...         page = page().next()
...         ret.extend(page().items)
...     return ret
...

.. highlight:: none

You can also pass parameters to resources supporting/requiring them, eg. `type` parameter for the regional
market data endpoint:

.. highlight:: python

>>> region = getByAttrVal(eve.regions().items, 'name', 'Catch')
>>> item = getByAttrVal(getAllItems(eve.itemTypes), 'name', 'Tritanium').href
>>> getAllItems(region().marketSellOrders(type=item))
[{u'price': 9.29, u'volume': 1766874, u'location': {'name': u'V-3YG7 VI - EMMA STONE NUMBER ONE', ...}, ...}, ... ]

.. highlight:: none

By default resources are cached in-memory, you can change this behaviour by passing the `cache_dir` keyword
argument to the EVE class.  If you do so, the responses will be cached in the filesystem, allowing the cache
to persist across multiple instances of the application.

Authorized Connections
======================

PyCrest can also be used for accessing CREST resources that require an authorized connection.  To do so you must
provide the EVE class with a `client_id`, `api_key`, and `redirect_uri` for the OAuth flows for authorizing a client.
Once done, PyCrest can be used for obtaining an authorization token:

.. highlight:: python

>>> eve = pycrest.EVE(client_id="your_client_id", api_key="your_api_key", redirect_uri="https://your.site/crest")
>>> eve.auth_uri(scopes=['publicData'], state="foobar")
'https://login.eveonline.com/oauth/authorize?response_type=code&redirect_uri=...'

.. highlight:: none

Once you have redirected the client to acquire authorization, you may pass the returned code to `EVE.authorize()` to
create an authorized connection.

.. highlight:: python

>>> eve.authorize(code)
<pycrest.eve.AuthedConnection object at 0x024CD8F0>

.. highlight:: none

The authorized API connection functions identically to the public connection, except that requests will be directed
to the authorized CREST endpoint.  You can retrieve information about the authorized character by calling `whoami()`
on an authorized connection:

.. highlight:: python

>>> con = eve.authorize(code)
>>> con.whoami()
{u'Scopes': u'publicData', u'CharacterName': u'Dreae', ...}

.. highlight:: none

Note that currently CREST authorization tokens expire after 1200 seconds and are automatically refreshed upon expiry.
You can also refresh tokens manually by calling `refresh()` on the authorized connection. This refreshes the connection
in-place and also returns `self` for backward compatibility.

.. highlight:: python

>>> con.refresh()
<pycrest.eve.AuthedConnection object at 0x0251F490>

.. highlight:: none
