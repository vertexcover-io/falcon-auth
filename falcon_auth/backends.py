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


class BackendAuthenticationFailure(falcon.HTTPUnauthorized):
    """
    Raised when the authentication backend fails to authenticate the request.
    """
    def __init__(self, backend, *args, **kwargs):
        super(BackendAuthenticationFailure, self).__init__(*args, **kwargs)
        self.backend = backend


class BackendNotApplicable(BackendAuthenticationFailure):
    """
    Raised when the authentication backend would fail because the request data indicates that a
    different backend should be applied.
    """


class UserNotFound(BackendNotApplicable):
    """
    Raised when the authentication backend would fail because the user record indicated by
    the credentials could not be found.
    """


class AuthBackend(object):
    """
    Base Class for all authentication backends. If successfully authenticated must
    return the authenticated `user` object. In case authorization header is
    not set properly or there is a credential mismatch, results in an
    `BackendAuthenticationFailure` exception with proper description of the issue.

    Args:
        user_loader(function, required): A callback function that is called with the
            decoded `token` extracted from the `Authorization`
            header. Returns an `authenticated user` if user exists matching the
            credentials or return `None` to indicate if no user found or credentials
            mismatch.
    """

    def __init__(self, user_loader):
        self.user_loader = user_loader

    def load_user(self, *args, **kwargs):
        """
        Invoke the provided `user_loader()` function to allow the app to retrieve
        the user record. If no such record is found, raise a `BackendNotApplicable`
        exception to indicate that another AuthBackend may be more viable.

        This is to account for cases where an application may require the use of
        multiple AuthBackends of the same type and the users may be namespaced
        somehow. We wouldn't want to preclude another AuthBackend of the same type
        from attempting authentication.
        """
        user = self.user_loader(*args, **kwargs)
        if not user:
            # We raise the less severe "not applicable" error here to allow other
            # AuthBackends a shot (if any). It will still result in a 401 if no
            # other backend can authenticate the user.
            raise UserNotFound(
                backend=self,
                description='User not found for provided credentials')
        return user

    def parse_auth_token_from_request(self, auth_header):
        """
        Parses and returns Auth token from the request header. Raises
        `BackendNotApplicable` exception with proper error message
        """
        if not auth_header:
            raise BackendNotApplicable(
                backend=self,
                description='Missing Authorization Header')

        parts = auth_header.split()

        if parts[0].lower() != self.auth_header_prefix.lower():
            raise BackendNotApplicable(
                backend=self,
                description='Invalid Authorization Header: '
                            'Must start with {0}'.format(self.auth_header_prefix))

        elif len(parts) == 1:
            raise BackendNotApplicable(
                backend=self,
                description='Invalid Authorization Header: Token Missing')
        elif len(parts) > 2:
            raise BackendNotApplicable(
                backend=self,
                description='Invalid Authorization Header: Contains extra content')

        return parts[1]

    def authenticate(self, req, resp, resource):
        """
        Authenticate the request and return the authenticated user. Must raise an
        a `BackendAuthenticationFailure` exception if authentication fails. It is
        preferred that it raise an `BackendNotApplicable` exception if it's determined
        that the provided credentials cannot be handled by this backend.
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


class NoneAuthBackend(AuthBackend):
    """
    Dummy authentication backend.

    This backend does not perform any authentication check. It can be used with the
    MultiAuthBackend in order to provide a fallback for an unauthenticated user.

    Args:
        user_loader(function, required): A callback function that is called
            without any arguments and returns an `unauthenticated user`.

    """

    def authenticate(self, req, resp, resource):
        return {
            'user': self.load_user(),
        }


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

    def __init__(self, user_loader, auth_header_prefix='Basic'):
        super(BasicAuthBackend, self).__init__(user_loader)
        self.auth_header_prefix = auth_header_prefix

    def _extract_credentials(self, req):
        auth = req.get_header('Authorization')
        token = self.parse_auth_token_from_request(auth_header=auth)
        try:
            token = base64.b64decode(token).decode('utf-8')

        except Exception:
            raise BackendNotApplicable(
                backend=self,
                description='Invalid Authorization Header: Unable to decode credentials')

        try:
            username, password = token.split(':', 1)
        except ValueError:
            raise BackendNotApplicable(
                backend=self,
                description='Invalid Authorization: Unable to decode credentials')

        return username, password

    def authenticate(self, req, resp, resource):
        """
        Extract basic auth token from request `authorization` header,  deocode the
        token, verifies the username/password and return either a ``user`` object
        if successful else raise an `BackendAuthenticationFailure` exception
        """
        username, password = self._extract_credentials(req)
        return {
            'user': self.load_user(username, password),
        }

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
       Implements Simple Token Based Authentication. Clients should authenticate by passing the
       token key in the "Authorization" HTTP header, prepended with the string "Token ".
       For example:

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

    def __init__(self, user_loader, auth_header_prefix='Token'):
        super(TokenAuthBackend, self).__init__(user_loader, auth_header_prefix)

    def _extract_credentials(self, req):
        auth = req.get_header('Authorization')
        return self.parse_auth_token_from_request(auth_header=auth)

    def authenticate(self, req, resp, resource):
        token = self._extract_credentials(req)
        return {
            'user': self.load_user(token),
        }

    def get_auth_token(self, user_payload):
        """
        Extracts token from the `user_payload`
        """
        token = user_payload.get('token') or None
        if not token:
            raise ValueError('`user_payload` must provide api token')

        return '{auth_header_prefix} {token}'.format(
            auth_header_prefix=self.auth_header_prefix, token=token)


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

        super(JWTAuthBackend, self).__init__(user_loader)
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
        token = self.parse_auth_token_from_request(auth_header=req.get_header('Authorization'))

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
            raise BackendAuthenticationFailure(
                backend=self,
                description=str(ex))

        return payload

    def authenticate(self, req, resp, resource):
        """
        Extract auth token from request `authorization` header, decode jwt token,
        verify configured claims and return either a ``user`` object if successful
        else raise an `BackendAuthenticationFailure` exception.
        """
        payload = self._decode_jwt_token(req)
        return {
            'user': self.load_user(payload),
        }

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

        if self.audience is not None:
            payload['aud'] = self.audience

        if self.issuer is not None:
            payload['iss'] = self.issuer

        return jwt.encode(
            payload,
            self.secret_key,
            algorithm=self.algorithm,
            json_encoder=ExtendedJSONEncoder).decode('utf-8')


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

        receiver_kwargs(dict, optional): A dictionary of arguments to be passed through
            to the Receiver. One must provide the `credentials_map` function for the
            purposes of looking up a user's credentials from their user id (the same value
            passed to `user_loader()`). See the `docs <https://mohawk.readthedocs.io/en/latest/usage.html#receiving-a-request>`__
            for further details.
    """

    def __init__(self, user_loader, credentials_loader, receiver_kwargs=None):
        try:
            mohawk
        except NameError:
            raise ImportError('Optional dependency falcon-auth[backend-hawk] not installed')
        super(HawkAuthBackend, self).__init__(user_loader)
        self.auth_header_prefix = 'Hawk'
        self.load_credentials = credentials_loader
        self.receiver_kwargs = receiver_kwargs or {}

    def parse_auth_token_from_request(self, auth_header):
        """
        Parses and returns the Hawk Authorization header if it is present and well-formed.
        Raises `BackendNotApplicable` exception with proper error message
        """
        if not auth_header:
            raise BackendNotApplicable(
                backend=self,
                description='Missing Authorization Header')

        try:
            auth_header_prefix, _ = auth_header.split(' ', 1)
        except ValueError:
            raise BackendNotApplicable(
                backend=self,
                description='Invalid Authorization Header: Missing Scheme or Parameters')

        if auth_header_prefix.lower() != self.auth_header_prefix.lower():
            raise BackendNotApplicable(
                backend=self,
                description='Invalid Authorization Header: '
                            'Must start with {0}'.format(self.auth_header_prefix))

        return auth_header

    def credentials_map(self, user_id):
        """
        Look up the user from the application and allow the application to extract/generate
        Hawk credentials from the user object. It then drops the user object into the
        credentials map as a way of memoizing this object for fast retrieval once authentication
        succeeds (we want to avoid another round trip to the backing datastore to get the user
        again).
        """
        user = self.load_user(user_id)
        credentials = self.load_credentials(user)
        credentials['user'] = user
        return credentials

    def authenticate(self, req, resp, resource):
        request_header = self.parse_auth_token_from_request(req.get_header('Authorization'))

        try:
            # Validate the Authorization header contents and lookup the user's credentials
            # via the provided `credentials_map` function.
            receiver = mohawk.Receiver(
                credentials_map=self.credentials_map,
                request_header=request_header,
                method=req.method,
                url=req.forwarded_uri,
                content=req.context.get('body'),
                content_type=req.get_header('Content-Type'),
                **self.receiver_kwargs)
        except mohawk.exc.HawkFail as ex:
            raise BackendAuthenticationFailure(
                backend=self,
                description='{0}({1!s})'.format(ex.__class__.__name__, ex),
                challenges=(
                    [getattr(ex, 'www_authenticate')]
                    if hasattr(ex, 'www_authenticate')
                    else []))

        # The authentication was successful, return the previously retrieved user now
        return {
            'user': receiver.resource.credentials['user'],
            'receiver': receiver,
        }


class MultiAuthBackend(AuthBackend):
    """
    A backend which takes two or more ``AuthBackend`` as inputs and successfully
    authenticates if any of them succeeds else raises a `BackendNotApplicable`
    exception.

    Args:
        backends(list[AuthBackend], required): A list of `AuthBackend` to be used in
            order to authenticate the user.
        early_exit(bool, optional): If early_exit is True, the iteration through the list of
            backends will stop upon the first non-`BackendNotApplicable`
            `BackendAuthenticationFailure` exception it encounters. Otherwise, it will treate all
            `falcon.HTTPUnauthorized` exceptions the same: just move on to the next backend in the
            list. Default is False.
    """

    def __init__(self, *backends, **kwargs):
        if len(backends) <= 1:
            raise ValueError('Invalid authentication backend. Must pass more than one backend')

        for backend in backends:
            if not isinstance(backend, AuthBackend):
                raise ValueError(
                    (
                        'Invalid authentication backend {0}.'
                        ' Must inherit falcon.auth.backends.AuthBackend'
                    )
                    .format(backend.__class__.__name__)
                )
        self.backends = backends
        # Examine kwargs since python 2.7 doesn't support keyword args after *args
        self.early_exit = kwargs.get('early_exit', False)

    @staticmethod
    def _append_challenges(challenges, exception):
        """
        Extract any WWW-Authenticate headers from `exception` and append them
        to `challenges`
        """
        assert isinstance(exception, falcon.HTTPUnauthorized)

        www_authenticate = exception.headers.get('WWW-Authenticate')
        if www_authenticate:
            challenges.append(www_authenticate)

    def authenticate(self, req, resp, resource):
        challenges = []
        for backend in self.backends:
            try:
                results = backend.authenticate(req, resp, resource)
                # Use setdefault() here to accomodate nested MultiAuthBackends,
                # though it's unclear when that strategy would be advisable.
                results.setdefault('backend', backend)
                return results

            except BackendNotApplicable as ex:
                # This backend didn't understand the Authorization header
                # (or other attributes of the request) or could not find the user
                # indicated by the credentials provided on the request and so
                # declined to handle authentication. If no other backend attempts
                # to authenticate the request and fails with a challenge, we
                # collect any  challenges presented by these skipped backends and
                # send them back on the 401 response as the WWW-Authenticate header.
                self._append_challenges(challenges, ex)

            except BackendAuthenticationFailure as ex:
                if self.early_exit:
                    # We're operating in the more strict (and thus more optimized)
                    # mode. End authentication now, since we believe no other
                    # backend will apply.
                    raise

                self._append_challenges(challenges, ex)

            except falcon.HTTPUnauthorized as ex:
                # Unspeciallized falcon.HTTPUnauthorized will always allow iteration
                # to continue.
                self._append_challenges(challenges, ex)

            # Any other exceptions will cause authentication (and possibly
            # the entire request) to fail, most likely with a 5XX rather than
            # 401.

        else:
            raise BackendNotApplicable(
                backend=self,
                description='Authentication Failed',
                challenges=challenges)

    def get_auth_token(self, user_payload):
        for backend in self.backends:
            try:
                return backend.get_auth_token(user_payload)
            except Exception:
                pass

        return None
