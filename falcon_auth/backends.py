# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division

import base64
from datetime import timedelta, datetime

import falcon

try:
    # This is an optional dependency. To use JWTAuthBackend be sure to add
    # [backend-jwt] to your falcon-auth requirement.
    # See https://www.python.org/dev/peps/pep-0508/#extras
    import jwt
except ImportError:
    pass

try:
    # This is an optional dependency. To use AuthBackend be sure to add
    # [backend-hawk] to your falcon-auth requirement.
    # See https://www.python.org/dev/peps/pep-0508/#extras
    import mohawk
except ImportError:
    pass

from falcon_auth.serializer import ExtendedJSONEncoder


class AuthBackend(object):
    """
    Base Class for all authentication backends. If successfully authenticated must
    return the authenticated `user` object. In case authorization header is
    not set properly or there is a credential mismatch, results in an
    `falcon.HTTPUnauthoried exception` with proper description of the issue

    Args:
        user_loader(function, required): A callback function that is called with the
            decoded `token` extracted from the `Authorization`
            header. Returns an `authenticated user` if user exists matching the
            credentials or return `None` to indicate if no user found or credentials
            mismatch.

        auth_header_prefix(string, optional): A prefix that is used with the
            bases64 encoded credentials in the `Authorization` header.

    """

    def __init__(self, user_loader, auth_header_prefix='basic'):
        raise NotImplementedError("Must be overridden")

    def parse_auth_token_from_request(self, auth_header):
        """
        Parses and returns Auth token from the request header. Raises
        `falcon.HTTPUnauthoried exception` with proper error message
        """
        if not auth_header:
            raise falcon.HTTPUnauthorized(
                description='Missing Authorization Header')

        parts = auth_header.split()

        if parts[0].lower() != self.auth_header_prefix.lower():
            raise falcon.HTTPUnauthorized(
                description='Invalid Authorization Header: '
                            'Must start with {0}'.format(self.auth_header_prefix))

        elif len(parts) == 1:
            raise falcon.HTTPUnauthorized(
                description='Invalid Authorization Header: Token Missing')
        elif len(parts) > 2:
            raise falcon.HTTPUnauthorized(
                description='Invalid Authorization Header: Contains extra content')

        return parts[1]

    def authenticate(self, req, resp, resource):
        """
        Authenticate the request and return the authenticated user. Must return
        `None` if authentication fails, or raise an exception

        """
        raise NotImplementedError(".authenticate() must be overridden.")

    def get_auth_token(self, user_payload):
        """
        Returns a authentication token created using the provided user details

        Args:
            user_payload(dict, required): A `dict` containing required information
                to create authentication token
        """
        raise NotImplementedError("Must be overridden")

    def get_auth_header(self, user_payload):
        """
        Returns the value for authorization header
        Args:
            user_payload(dict, required): A `dict` containing required information
                to create authentication token
        """
        auth_token = self.get_auth_token(user_payload)
        return '{auth_header_prefix} {auth_token}'.format(
            auth_header_prefix=self.auth_header_prefix, auth_token=auth_token
        )


class JWTAuthBackend(AuthBackend):
    """
    Token based authentication using the `JSON Web Token standard <https://jwt.io/introduction/>`__
    Clients should authenticate by passing the token key in the `Authorization`
    HTTP header, prepended with the string specified in the setting
    `auth_header_prefix`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj

    Args:
        user_loader(function, required): A callback function that is called with the
            decoded `jwt payload` extracted from the `Authorization`
            header. Returns an `authenticated user` if user exists matching the
            credentials or return `None` to indicate if no user found or credentials
            mismatch.

        secrey_key(string, required): A secure key that was used to encode and
            create the `jwt token` from a dictionary payload

        algorithm(string, optional): Specifies the algorithm that was used
            to for cryptographic signing. Default is ``HS256`` which stands for
            HMAC using SHA-256 hash algorithm. Other supported algorithms can be
            found `here <http://pyjwt.readthedocs.io/en/latest/algorithms.html>`__

        auth_header_prefix(string, optional): A prefix that is used with the
            bases64 encoded credentials in the `Authorization` header. Default is
            ``jwt``

        leeway(int, optional): Specifies the timedelta in seconds that is allowed
            as leeway while validating `expiration time` / `nbf(not before) claim`
            /`iat (issued at) claim` which is in past but not very
            far. For example, if you have a JWT payload with an expiration time
            set to 30 seconds after creation but you know that sometimes you will
            process it after 30 seconds, you can set a leeway of 10 seconds in
            order to have some margin. Default is ``0 seconds``

        expiration_delta(int, optional): Specifies the timedelta in seconds that
            will be added to current time to set the expiration for the token.
            Default is ``1 day(24 * 60 * 60 seconds)``

        audience(string, optional): Specifies the string that will be specified
            as value of ``aud`` field in the jwt payload. It will also be checked
            agains the ``aud`` field while decoding.

        issuer(string, optional): Specifies the string that will be specified
            as value of ``iss`` field in the jwt payload. It will also be checked
            agains the ``iss`` field while decoding.

    """

    def __init__(self, user_loader, secret_key,
                 algorithm='HS256', auth_header_prefix='jwt',
                 leeway=0, expiration_delta=24 * 60 * 60,
                 audience=None, issuer=None,
                 verify_claims=None, required_claims=None):

        try:
            jwt
        except NameError:
            raise ImportError('Optional dependency falcon-auth[backend-jwt] not installed')

        self.user_loader = user_loader
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.leeway = timedelta(seconds=leeway)
        self.auth_header_prefix = auth_header_prefix
        self.expiration_delta = timedelta(seconds=expiration_delta)
        self.audience = audience
        self.issuer = issuer
        self.verify_claims = verify_claims or ['signature', 'exp', 'nbf', 'iat']
        self.required_claims = required_claims or ['exp', 'iat', 'nbf']

        if 'aud' in self.verify_claims and not audience:
            raise ValueError('Audience parameter must be provided if '
                             '`aud` claim needs to be verified')

        if 'iss' in self.verify_claims and not issuer:
            raise ValueError('Issuer parameter must be provided if '
                             '`iss` claim needs to be verified')

    def _decode_jwt_token(self, req):

        # Decodes the jwt token into a payload
        auth_header = req.get_header('Authorization')
        token = self.parse_auth_token_from_request(auth_header=auth_header)

        options = dict(('verify_' + claim, True) for claim in self.verify_claims)

        options.update(
            dict(('require_' + claim, True) for claim in self.required_claims)
        )

        try:
            payload = jwt.decode(jwt=token, key=self.secret_key,
                                 options=options,
                                 algorithms=[self.algorithm],
                                 issuer=self.issuer,
                                 audience=self.audience,
                                 leeway=self.leeway)
        except jwt.InvalidTokenError as ex:
            raise falcon.HTTPUnauthorized(
                description=str(ex))

        return payload

    def authenticate(self, req, resp, resource):
        """
        Extract auth token from request `authorization` header, decode jwt token,
        verify configured claims and return either a ``user``
        object if successful else raise an `falcon.HTTPUnauthoried exception`
        """
        payload = self._decode_jwt_token(req)
        user = self.user_loader(payload)
        if not user:
            raise falcon.HTTPUnauthorized(
                description='Invalid JWT Credentials')

        return user

    def get_auth_token(self, user_payload):
        """
        Create a JWT authentication token from ``user_payload``

        Args:
            user_payload(dict, required): A `dict` containing required information
                to create authentication token
        """
        now = datetime.utcnow()
        payload = {
            'user': user_payload
        }
        if 'iat' in self.verify_claims:
            payload['iat'] = now

        if 'nbf' in self.verify_claims:
            payload['nbf'] = now + self.leeway

        if 'exp' in self.verify_claims:
            payload['exp'] = now + self.expiration_delta

        return jwt.encode(payload, self.secret_key,
                          json_encoder=ExtendedJSONEncoder).decode('utf-8')


class BasicAuthBackend(AuthBackend):
    """
    Implements `HTTP Basic Authentication <http://tools.ietf.org/html/rfc2617>`__
    Clients should authenticate by passing the `base64` encoded credentials
    `username:password` in the `Authorization` HTTP header, prepended with the
    string specified in the setting `auth_header_prefix`. For example:

        Authorization: BASIC ZGZkZmY6ZGZkZ2RkZg==

    Args:
        user_loader(function, required): A callback function that is called with the user
            credentials (username and password) extracted from the `Authorization`
            header. Returns an `authenticated user` if user exists matching the
            credentials or return `None` to indicate if no user found or credentials
            mismatch.

        auth_header_prefix(string, optional): A prefix that is used with the
            bases64 encoded credentials in the `Authorization` header. Default is
            ``basic``

    """

    def __init__(self, user_loader,
                 auth_header_prefix='Basic'):

        self.user_loader = user_loader
        self.auth_header_prefix = auth_header_prefix

    def _extract_credentials(self, req):
        auth = req.get_header('Authorization')
        token = self.parse_auth_token_from_request(auth_header=auth)
        try:
            token = base64.b64decode(token).decode('utf-8')

        except Exception:
            raise falcon.HTTPUnauthorized(
                description='Invalid Authorization Header: Unable to decode credentials')

        try:
            username, password = token.split(':', 1)
        except ValueError:
            raise falcon.HTTPUnauthorized(
                description='Invalid Authorization: Unable to decode credentials')

        return username, password

    def authenticate(self, req, resp, resource):
        """
        Extract basic auth token from request `authorization` header,  deocode the
        token, verifies the username/password and return either a ``user``
        object if successful else raise an `falcon.HTTPUnauthoried exception`
        """
        username, password = self._extract_credentials(req)
        user = self.user_loader(username, password)
        if not user:
            raise falcon.HTTPUnauthorized(
                description='Invalid Username/Password')

        return user

    def get_auth_token(self, user_payload):
        """
        Extracts username, password from the `user_payload` and encode the
        credentials `username:password` in `base64` form
        """
        username = user_payload.get('username') or None
        password = user_payload.get('password') or None

        if not username or not password:
            raise ValueError('`user_payload` must contain both username and password')

        token = '{username}:{password}'.format(
            username=username, password=password).encode('utf-8')

        token_b64 = base64.b64encode(token).decode('utf-8', 'ignore')

        return '{auth_header_prefix} {token_b64}'.format(
            auth_header_prefix=self.auth_header_prefix, token_b64=token_b64)


class TokenAuthBackend(BasicAuthBackend):
    """
       Implements Simple Token Based Authentication. Clients should authenticate by passing the token key in the "Authorization"
           HTTP header, prepended with the string "Token ".  For example:

               Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a

       Args:
           user_loader(function, required): A callback function that is called
               with the token extracted from the `Authorization`
               header. Returns an `authenticated user` if user exists matching the
               credentials or return `None` to indicate if no user found or credentials
               mismatch.

           auth_header_prefix(string, optional): A prefix that is used with the
               token in the `Authorization` header. Default is
               ``basic``

       """

    def __init__(self, user_loader,
                 auth_header_prefix='Token'):

        super(TokenAuthBackend, self).__init__(user_loader, auth_header_prefix)

    def _extract_credentials(self, req):
        auth = req.get_header('Authorization')
        return self.parse_auth_token_from_request(auth_header=auth)

    def authenticate(self, req, resp, resource):
        token = self._extract_credentials(req)
        user = self.user_loader(token)
        if not user:
            raise falcon.HTTPUnauthorized(
                description='Invalid Token')

        return user

    def get_auth_token(self, user_payload):
        """
        Extracts token from the `user_payload`
        """
        token = user_payload.get('token') or None
        if not token:
            raise ValueError('`user_payload` must provide api token')

        return '{auth_header_prefix} {token}'.format(
            auth_header_prefix=self.auth_header_prefix, token=token)


class NoneAuthBackend(AuthBackend):
    """
    Dummy authentication backend.

    This backend does not perform any authentication check. It can be used with the
    MultiAuthBackend in order to provide a fallback for an unauthenticated user.

    Args:
        user_loader(function, required): A callback function that is called
            without any arguments and returns an `unauthenticated user`.

    """

    def __init__(self, user_loader):
        self.user_loader = user_loader

    def authenticate(self, req, resp, resource):
        return self.user_loader()


class HawkAuthBackend(AuthBackend):
    """
    Holder-Of-Key Authentication Scheme defined by `Hawk <https://github.com/hueniverse/hawk>`__
    Clients should authenticate by passing a Hawk-formatted header as the `Authorization`
    HTTP header. For example:

        Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="

    Args:
        user_loader(function, required): A callback function that is called with the `id`
            value extracted from the `Hawk` header. Returns an `authenticated user` if the user
            matching the credentials exists or returns `None` to indicate if no user was found.

        receiver_kwargs(dict, required): A dictionary of arguments to be passed through
            to the Receiver. One must provide the `credentials_map` function for the
            purposes of looking up a user's credentials from their user id (the same value
            passed to `user_loader()`). See the `docs <https://mohawk.readthedocs.io/en/latest/usage.html#receiving-a-request>`__
            for further details.
    """
    def __init__(self, user_loader, receiver_kwargs):
        try:
            mohawk
        except NameError:
            raise ImportError('Optional dependency falcon-auth[backend-hawk] not installed')
        self.user_loader = user_loader
        self.auth_header_prefix = 'Hawk'
        self.receiver_kwargs = receiver_kwargs

        if not callable(self.receiver_kwargs.get('credentials_map')):
            raise ValueError('Required "credentials_map" function not provided in receiver_kwargs')

    def parse_auth_token_from_request(self, auth_header):
        """
        Parses and returns the Hawk Authorization header if it is present and well-formed.
        Raises `falcon.HTTPUnauthoried exception` with proper error message
        """
        if not auth_header:
            raise falcon.HTTPUnauthorized(
                description='Missing Authorization Header')

        try:
            auth_header_prefix, _ = auth_header.split(' ', 1)
        except ValueError:
            raise falcon.HTTPUnauthorized(
                description='Invalid Authorization Header: Missing Scheme or Parameters')

        if auth_header_prefix.lower() != self.auth_header_prefix.lower():
            raise falcon.HTTPUnauthorized(
                description='Invalid Authorization Header: '
                            'Must start with {0}'.format(self.auth_header_prefix))

        return auth_header

    def authenticate(self, req, resp, resource):
        request_header = self.parse_auth_token_from_request(req.get_header('Authorization'))

        try:
            # Validate the Authorization header contents and lookup the user's credentials
            # via the provided `credentials_map` function.
            receiver = mohawk.Receiver(
                request_header=request_header,
                method=req.method,
                url=req.forwarded_uri,
                content=req.context.get('body'),
                content_type=req.get_header('Content-Type'),
                **self.receiver_kwargs)
        except mohawk.exc.HawkFail as ex:
            raise falcon.HTTPUnauthorized(
                description='{0}({1!s})'.format(ex.__class__.__name__, ex),
                challenges=(
                    [getattr(ex, 'www_authenticate')]
                    if hasattr(ex, 'www_authenticate')
                    else []))

        # The authentication was successful, get the actual user object now.
        user = self.user_loader(receiver.parsed_header['id'])
        if not user:
            # Should never really happen unless your user objects and their
            # credentials are out of sync.
            raise falcon.HTTPUnauthorized(
                description='Invalid User')


class MultiAuthBackend(AuthBackend):
    """
    A backend which takes two or more ``AuthBackend`` as inputs and successfully
    authenticates if either of them succeeds else raises `falcon.HTTPUnauthoried exception`

    Args:
        backends(AuthBackend, required): A list of `AuthBackend` to be used in
            order to authenticate the user.

    """

    def __init__(self, *backends):
        if len(backends) <= 1:
            raise ValueError('Invalid authentication backend. Must pass more than one backend')

        for backend in backends:
            if not isinstance(backend, AuthBackend):
                raise ValueError(('Invalid authentication backend {0}.'
                                 'Must inherit `falcon.auth.backends.AuthBackend`')
                                 .format(backend))

        self.backends = backends

    def authenticate(self, req, resp, resource):
        challenges = []
        for backend in self.backends:
            try:
                user = backend.authenticate(req, resp, resource)
                if user:
                    return user
            except falcon.HTTPUnauthorized as ex:
                www_authenticate = ex.headers.get('WWW-Authenticate')
                if www_authenticate:
                    challenges.append(www_authenticate)

        raise falcon.HTTPUnauthorized(
            description='Authorization Failed',
            challenges=challenges)

    def get_auth_token(self, user_payload):
        for backend in self.backends:
            try:
                return backend.get_auth_token(user_payload)
            except Exception:
                pass

        return None
