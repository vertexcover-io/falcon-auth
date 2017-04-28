falcon-auth
===========

|version| |docs| |build| |coverage| |license|

A falcon middleware + authentication backends that adds authentication layer
to you app/api service.

Installation
------------

Install the extension with pip, or easy\_install.

.. code:: bash

    $ pip install -U falcon-auth

Usage
-----

This package exposes a falcon middleware which takes an authentication backend
as an input and use it to authenticate requests. You can specify some routes and
methods which are exempted from authentication. Once the middleware authenticates
the request using the specified authentication backend, it add the authenticated
user to the ``request context``

.. code:: python

    import falcon
    from falcon_auth import FalconAuthMiddleware, BasicAuthBackend

    user_loader = lambda username, password: { 'username': username }
    auth_backend = BasicAuthBackend(user_loader)
    auth_middleware = FalconAuthMiddleware(auth_backend,
                        exempt_routes=['/exempt'], exempt_methods=['HEAD'])
    api = falcon.API(middleware=[auth_middleware])

    class ApiResource:

        def on_post(self, req, resp):
            user = req.context['user']
            resp.body = "User Found: {}".format(user['username'])


Override Authentication for a specific resource
-----------------------------------------------

Its possible to customize the exempt routes, exempt methods and
authentication backend on a per resource basis as well


.. code:: python

    import falcon
    from falcon_auth import FalconAuthMiddleware, BasicAuthBackend, TokenAuthBackend

    # a loader function to fetch user from username, password
    user_loader = lambda username, password: { 'username': username }

    # basic auth backend
    basic_auth = BasicAuthBackend(user_loader)

    # Auth Middleware that uses basic_auth for authentication
    auth_middleware = FalconAuthMiddleware(basic_auth)
    api = falcon.API(middleware=[auth_middleware])


    class ApiResource:

        auth = {
            'backend': TokenAuthBackend(user_loader=lambda token: { 'id': 5 }),
            'exempt_methods': ['GET']
        }

        # token auth backend

        def on_post(self, req, resp):
            resp.body = "This resource uses token authentication"

        def on_get(self, req, resp):
            resp.body = "This resource doesn't need authentication"


    api.add_route("/api", ApiResource())


Disable Authentication for a specific resource
----------------------------------------------

.. code:: python

    class ApiResource:
        auth = {
            'auth_disabled': True
        }


Accessing Authenticated User
----------------------------
Once the middleware authenticates
the request using the specified authentication backend, it add the authenticated
user to the `request context`

.. code:: python

    class ApiResource:

        def on_post(self, req, resp):
            user = req.context['user']
            resp.body = "User Found: {}".format(user['username'])

Authentication Backends
-----------------------

+ **Basic Authentication**

Implements `HTTP Basic Authentication <http://tools.ietf.org/html/rfc2617>`__
wherein the HTTP ``Authorization`` header contains the user
credentials(username and password) encoded using ``base64`` and a prefix (typically Basic)

+ **Token Authentication**

Implements a Simple Token Based Authentication Scheme where HTTP ``Authorization``
header contains a prefix (typically Token) followed by an `API Token`

+ **JWT Authentication**

Token based authentication using the `JSON Web Token standard <https://jwt.io/introduction/>`__

+ **Dummy Authentication**

Backend which does not perform any authentication checks

+ **Multi Backend Authentication**

A Backend which comprises of multiple backends and requires any of them to authenticate
the request successfully

Tests
-----

This library comes with a good set of tests which are included in ``tests/``. To run
install ``pytest`` and simply invoke ``py.test`` or ``python setup.py test``
to exercise the tests. You can check the test coverage by running
``py.test --cov falcon_auth``

API
----
.. autoclass:: falcon_auth.FalconAuthMiddleware
    :members:

.. autoclass:: falcon_auth.BasicAuthBackend
    :members:

.. autoclass:: falcon_auth.TokenAuthBackend
    :members:

.. autoclass:: falcon_auth.JWTAuthBackend
    :members:

.. autoclass:: falcon_auth.NoneAuthBackend
    :members:

.. autoclass:: falcon_auth.MultiAuthBackend
    :members:


.. |docs| image:: https://readthedocs.org/projects/docs/badge/?version=latest
    :alt: Documentation Status
    :scale: 100%
    :target: https://falcon-auth.readthedocs.io/en/latest/?badge=latest

.. |version| image:: https://img.shields.io/pypi/v/falcon-auth.svg
    :target: https://pypi.python.org/pypi/falcon-auth

.. |license| image:: http://img.shields.io/:license-mit-blue.svg
    :target: https://pypi.python.org/pypi/falcon-auth/

.. |build| image:: https://travis-ci.org/loanzen/falcon-auth.svg?branch=master
    :target: https://travis-ci.org/loanzen/falcon-auth

.. |coverage| image:: https://coveralls.io/repos/github/loanzen/falcon-auth/badge.svg?branch=master
    :target: https://coveralls.io/github/loanzen/falcon-auth?branch=master
