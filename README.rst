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

If you wish to use the optional backends, specify those dependencies, too.

.. code:: bash

    $ pip install -U falcon-auth[backend-hawk,backend-jwt]

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
    auth_middleware = FalconAuthMiddleware(
        auth_backend,
        exempt_routes=['/exempt'],
        exempt_methods=['HEAD'],
        context_key='auth')
    api = falcon.API(middleware=[auth_middleware])

    class ApiResource:

        def on_post(self, req, resp):
            user = req.context['auth']['user']
            resp.body = "User Found: {}".format(user['username'])

If you wish to place the authentication results under a name other than ``'auth'``
in the ``req.context``, provide the ``context_key`` argument to the middleware
constructor.

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
            user = req.context['auth']['user']
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

+ **JWT Authentication (Python 2.7, 3.4+)**

Token based authentication using the `JSON Web Token standard <https://jwt.io/introduction/>`__
If you wish to use this backend, be sure to add the optional dependency to your requirements
(See Python `"extras" <https://www.python.org/dev/peps/pep-0508/#extras>`__):

.. code:: text

    falcon-auth[backend-jwt]


+ **Hawk Authentication (Python 2.6+, 3.4+)**

Token based authentication using the `Hawk "Holder-Of-Key Authentication Scheme" <https://github.com/hueniverse/hawk>`__
If you wish to use this backend, be sure to add the optional dependency to your requirements
(See Python `"extras" <https://www.python.org/dev/peps/pep-0508/#extras>`__): This backend will
also provide the ``mohawk.Receiver`` object in the ``req.context['auth']`` result.

.. code:: text

    falcon-auth[backend-hawk]


+ **Dummy Authentication**

Backend which does not perform any authentication checks

+ **Multi Backend Authentication**

A Backend which comprises of multiple backends and requires any of them to authenticate
the request successfully.

This backend will iterate over all provided backends until one of the following occurs:

- A backend returns a successful authentication result, containing at least the user object
- A backend raises a non-``BackendNotApplicable`` exception
- The end of the list is reached

The ``BackendNotApplicable`` exception should be raised by a backend when it determines
that it is not the appropriate backend to handle the request. (eg. The ``BasicAuthBackend``
doesn't know how to parse a ``Hawk`` authorization header). In this way, a list of
backends can short-circuit when an appropriate backend is found, rather than traversing
the whole list. Any other exceptions will result in authentication stopping, the optional
``on_failure()`` callback being invoked, and the exception propagating out of the
middleware to be handled by the falcon framework.

Custom Backends
---------------

It is expected that users will want to write their own backends to work with this middleware.
Here are the guidelines to follow when writing your backend:

- Inherit from `AuthBackend`
- Take care to call the base class ``AuthBackend.__init__(user_loader)`` from your `__init__()`
  method
- Return a dictionary from `authenticate()` which includes at least the `'user'` key holding
  the user object returned from ``user_loader()``. Other backend-specific keys can be included
  as well.
- Raise a `BackendNotApplicable` exception if the backend determines that it is not
  equipped to handle the request and should defer to a more appropriate backend.
- Prefer raising a `BackendAuthenticationFailure` in all other cases.


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

.. autoclass:: falcon_auth.HawkAuthBackend
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
