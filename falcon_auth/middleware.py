# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division

import falcon

from falcon_auth.backends import AuthBackend, BackendAuthenticationFailure


class FalconAuthMiddleware(object):

    """
    Creates a falcon auth middleware that uses given authentication backend, and some
    optional configuration to authenticate requests. After initializing the
    authentication backend globally you can override the backend as well as
    other configuration for a particular resource by setting the `auth` attribute
    on it to an instance of this class.

    The authentication backend must return an authenticated user which is then
    set as ``request.context['auth']['user']`` to be used further down by resources
    othewise an ``falcon.HTTPUnauthorized`` exception is raised.

    Args:
        backend(:class:`falcon_auth.backends.AuthBackend`, required): Specifies the auth
            backend to be used to authenticate requests

        exempt_routes(list, optional): A list of paths to be excluded while performing
            authentication. Default is ``None``

        exempt_methods(list, optional): A list of paths to be excluded while performing
            authentication. Default is ``['OPTIONS']``

        context_key(str, optional): The key to be used when adding the successful
            authentication results to the ``req.context`` dictionary. Default is ``'auth'``.

        on_success(function, optional): A callback function that is called with the
            results of the ``authenticate()`` call when authentication succeeds.

            .. code:: python

                def on_success(req, resp, resource, results):
                    ...

        on_failure(function, optional): A callback function that is called with the
            results of the ``authenticate()`` call when authentication fails. This will
            only be called if the backend was deemed appropriate for the request
            (ie. a ``falcon.HTTPUnauthorized`` exception was raised and not a
            ``BackendNotApplicable`` exception).

            .. code:: python

                def on_failure(req, resp, resource, exception):
                    ...
    """

    def __init__(self, backend, exempt_routes=None, exempt_methods=None, context_key='auth',
                 on_success=None, on_failure=None):
        self.backend = backend
        self.on_success = on_success
        self.on_failure = on_failure

        if not isinstance(backend, AuthBackend):
            raise ValueError(
                (
                    'Invalid authentication backend {0}.'
                    ' Must inherit falcon.auth.backends.AuthBackend'
                ).format(backend.__class__.__name__)
            )

        self.exempt_routes = exempt_routes or []
        self.exempt_methods = exempt_methods or ['OPTIONS']
        self.context_key = context_key

    def _get_auth_settings(self, req, resource):
        auth_settings = getattr(resource, 'auth', {})
        auth_settings['exempt_routes'] = self.exempt_routes
        if auth_settings.get('auth_disabled'):
            auth_settings['exempt_routes'].append(req.path)

        for key in ('exempt_methods', 'backend'):
            auth_settings[key] = auth_settings.get(key) or getattr(self, key)

        return auth_settings

    def process_resource(self, req, resp, resource, *args, **kwargs):
        auth_setting = self._get_auth_settings(req, resource)
        if (req.uri_template in auth_setting['exempt_routes'] or
            req.method in auth_setting['exempt_methods']):
            return

        backend = auth_setting['backend']
        try:
            results = backend.authenticate(req, resp, resource, **kwargs)
            # Use setdefault() here to accommodate MultiAuthBackend that
            # sets this value to the successful backend type in its list.
            results.setdefault('backend', backend)
            req.context[self.context_key] = results
            if self.on_success:
                self.on_success(req, resp, resource, results)

        except BackendAuthenticationFailure as ex:
            if self.on_failure:
                # Notify the application about the failure and the backend
                # that raised it before re-raising it.
                self.on_failure(req, resp, resource, ex)
            raise

        except Exception as ex:
            if self.on_failure:
                # As we wish to convey which backend was responsible for
                # the authentication failure, we wrap any
                # non-BackendAuthenticationFailure exceptions in one and
                # provide that to the application. The original exception
                # will be re-raised.
                backend_auth_failure = BackendAuthenticationFailure(
                    backend,
                    'Unexpected authentication error')
                backend_auth_failure.__cause__ = ex
                self.on_failure(req, resp, resource, backend_auth_failure)
            raise
