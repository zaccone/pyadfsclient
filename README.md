pyadfsclient
============

ADFS client
-----------

Authenticate with your service Provider and Active Directory Federation
Services (ADFS)
from a command line.

Features:

* Fetch content of the protected resource

Dependencies
------------

pyadfsclient depends on [`requests`](https://pypi.python.org/pypi/requests/)
and [`lxml`](http://lxml.de/) libraries.

The easiest way to install your dependencies is via pip::

    $ pip install --upgrade -r requirements.txt

Installation
------------

Make sure you meet all required dependencies and smply run ./adfs-client

Usage
-----

Simply call ./adfs-client with appripriate options (see --help for more details).

You can also export following environment variables and run your client
params-free::

* ADFS_USER - ADFS user
* ADFS_PASSWORD - ADFS password
* ADFS_URL - ADFS URL, e.g. https://example.com/adfs/services/trust/13/usernamemixed

* SP_ENDPOINT - Service Provider's endpoint, e.g. https://sp.example.com/Shibboleth.sso/ADFS
* SP_URL - Service Provider's protected URL, e.g. https://sp.example.com/secure

