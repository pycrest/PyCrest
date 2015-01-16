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

>>> eve.motd
{u'dust': {u'href': u'http://newsfeed.eveonline.com/articles/71'}, ...}

.. highlight:: none

In order to access resources that must be fetched from the API first, you must call the
desired resource:

.. highlight:: python

>>> eve.incursions
{u'href': u'https://public-crest.eveonline.com/incursions/'}
>>> eve.incursions()
{u'items': [{...}], u'totalCount_str': u'5', u'totalCount': 5, u'pageCount': 1, u'pageCount_str': u'1'}
>>> eve.incursions().totalCount
5

.. highlight:: none

By default resources are cached for 10 minutes to avoid excessive overhead when accessing nested resources.  This time
can be changed by providing the `cache_time` keyword argument to the EVE constructor.

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

Note that currently CREST authorization tokens expire after 1200 seconds.  You can receive a new connection using the
refresh token by calling `refresh()` on the authorized connection:

.. highlight:: python

>>> con.refresh()
<pycrest.eve.AuthedConnection object at 0x0251F490>

.. highlight:: none