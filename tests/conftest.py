# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division

import base64
import binascii
import json
import os
from datetime import datetime, timedelta

import falcon
import pytest
from falcon import testing

from falcon_auth import BasicAuthBackend, TokenAuthBackend, \
    JWTAuthBackend, NoneAuthBackend, MultiAuthBackend, HawkAuthBackend
from falcon_auth import FalconAuthMiddleware
from falcon_auth.backends import AuthBackend
from falcon_auth.serializer import ExtendedJSONEncoder

try:
    import jwt
    import json
    from jwt.algorithms import RSAAlgorithm
    jwt_available = pytest.mark.skipif(False, reason="jwt not installed")
except ImportError:
    jwt_available = pytest.mark.skipif(True, reason="jwt not installed")

try:
    import mohawk
    hawk_available = pytest.mark.skipif(False, reason="hawk not installed")
except ImportError:
    hawk_available = pytest.mark.skipif(True, reason="hawk not installed")

EXPIRATION_DELTA = 30 * 60

SECRET_KEY = 'SecretKey123'

LEEWAY = 0


class User(object):

    def __init__(self, _id, username, password):
        self.id = _id
        self.username = username
        self.password = password
        self.token = binascii.hexlify(os.urandom(20)).decode()

    def clone(self):
        return User(self.id, self.username, self.password)

    def __str__(self):
        return "User(id='%s')" % self.id

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username
        }

    def serialize(self):
        return json.dumps(self.to_dict())


@pytest.fixture(scope='function')
def user():
    return User(_id=1, username='joe', password='pass')


@pytest.fixture(scope='function')
def none_user():
    return User(_id=0, username='anonymous', password=None)


def create_app(auth_middleware, resource):

    api = falcon.API(middleware=[auth_middleware])

    api.add_route('/auth', resource)
    api.add_route('/posts/{post_id}', resource)
    return api


class AuthResource:

    def on_post(self, req, resp):
        user = req.context['user']
        resp.body = user.serialize()

    def on_get(self, req, resp, **kwargs):
        resp.body = 'Success'


def get_basic_auth_token(username, password, prefix='Basic'):
    token = '{username}:{password}'.format(
                username=username, password=password).encode('utf-8')

    token_b64 = base64.b64encode(token).decode('utf-8', 'ignore')
    return '{prefix} {token_b64}'.format(prefix=prefix, token_b64=token_b64)


@pytest.fixture(scope='function')
def basic_auth_backend(user):
    def user_loader(username, password):
        if user.username == username and user.password == password:
            return user
        return None

    return BasicAuthBackend(user_loader)


class BasicAuthFixture:

    @pytest.fixture(scope='function')
    def backend(self, user):
        return basic_auth_backend(user)

    @pytest.fixture(scope='function')
    def auth_token(self, user):
        return get_basic_auth_token(user.username, user.password)


@pytest.fixture(scope='function')
def token_backend(user):
    def user_loader(token):
        if user.token == token:
            return user
        return None

    return TokenAuthBackend(user_loader)


def get_token_auth(user):
    return 'Token {token}'.format(token=user.token)


class TokenAuthFixture:

    @pytest.fixture(scope='function')
    def backend(self, user):
        return token_backend(user)

    @pytest.fixture(scope='function')
    def auth_token(self, user):
        return get_token_auth(user)


@pytest.fixture(scope='function')
def secret_key():
    return 'SecretKey123'


@pytest.fixture(scope='function')
def jwt_backend(user):
    def user_loader(payload):
        if user.id == payload['user']['id']:
            return user
        return None

    return JWTAuthBackend(user_loader, SECRET_KEY)


def get_jwt_token(user, prefix='JWT', algorithm = "HS256", secret_key = SECRET_KEY):
    now = datetime.utcnow()
    payload = {
        'user': {
            'id': user.id,
            'username': user.username
        },
        'iat': now,
        'nbf': now,
        'exp': now + timedelta(seconds=EXPIRATION_DELTA)
    }

    jwt_token = jwt.encode(payload, secret_key,
                           json_encoder=ExtendedJSONEncoder, algorithm=algorithm, headers={'kid':'KeyID'}).decode('utf-8')
    return '{prefix} {jwt_token}'.format(prefix=prefix, jwt_token=jwt_token)


class JWTAuthFixture:

    @pytest.fixture(scope='function')
    def backend(self, user):
        return jwt_backend(user)

    @pytest.fixture(scope='function')
    def auth_token(self, user):

        return get_jwt_token(user)

        
class KeyDiscoveryJWTAuthFixture:

    @pytest.fixture(scope='function')
    def auth_token(self, user):
		# Need to sign the generated JWT with a known private key so it can be verified later
        return get_jwt_token(user, algorithm = "RS256", secret_key = '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqOvwMnXHNjseNWf1La5cnD3O3KCiFCafRuQYXtHMPZbzge3D
i9MVoXzoDveXbxGGJtLWoIrEy2OXfzTxP5z5irLvAVRca6h3/d4Fe37x0PH8Atel
nYZu3lKZGGPCVRwitX23qqqA/WWHfxUdrflD1V2ipUmWxYsb/NV8MZ9pUmedwpG7
GjAOrpNP+9aSwUrYys08iCHCwLQpLEiwtneHxdVUvd44mJtpBsxbBLQjwHW2CkPq
mkZv4Tb7451EOCMRIGMJLnUrc0ESGmXm8NMmdL3Hbdu0sg3lrIZiiG1twLaO4Y6z
JSRjvkXKpMakFiJTH+FsGI0/U+ntxXC1F4wL1wIDAQABAoIBAQCHuoSW1wIJtjjQ
qsZbPTXWqOc1abCxxlLG0HIwhhy5BDiHFre/+wzvZADGPfUk3ozPVyvzdW0pC83n
/W83MPdlld7rT5CvRH+dsa7wCxFcVYOr+QBu8VzWMMIo0ceNQX02HVzdugDJGrJj
z2C4sIfrwj/01YtbESqc3iDbcn5bIezwVmWunAv0JtszGecwVaTHw//7meXIRRFT
/jzf7dIiNQCX8UbI4/XsL29iNEL6uaK9V3uYN0kEWhBtRoShYWI2M8zOr98u1SQd
JIe+vaxTpFwYQI39tArcjZCL0D6rK8Fvx1YxzGDMsmddjKxkIUU3AWe604ord1xZ
z1p892PZAoGBAOTNMxJOubO0eLaJZkHIZ2SyLO3ryxxlADUT3N+wuRV+ovGZ/bbI
sC7kaAwCJilC79uIlOVFsIijkM5HjdP7l+I9nSEv5o2mO5GzdP+oz6srR23iDuqD
O2F1Q9sAfwWCjFHmFPdsTzIkVLOdGgWHUCoBSc1dVqS6UtlIF0pcngj1AoGBAL0A
fvuwB8dQVSnuFvOO11zLDsVC+IA0YRd8kIunQggLkf0uTPQB2itKpJ5DbEIpukXB
aVx1hwasBgNqUCyW9QnpWb+N52RtYVl61fxtZ+3MGyUkMHBe82CS1BJQdoQmhsc0
sPRvar/AEbrDsPw5iHMKqECd9eXWA/9K9ixo1HIbAoGAX6lv5gKmX/1fzyoJaA2r
NQ3N/Tft9xQ/jvGcEqan69XDuPIigy7Lgv+ahRLM88l50bb8UhPeKHMC00xVf0Ed
EsmiDcMiSS0skNGQZGgnU7DHr6ipheGSjT/jPAisExivJHrnXz+YqSVJiMNxosgd
e0KIoeWZmUwR4ajjnAK3TJUCgYBG/6e0DpVtdyz22ly+07rtPc5npdfJ+WM7umxm
OcehVA9cZ4c65nM5bgnW9gb198zkpVpaBEBb7kU4BTjm9zJHreQsBDeXT0uRnIZE
FClFeDX+RtD3dYPBlIab9qP+0qYwsQeEW1Jjg9hlK1wR897hMHCyDWSxGStZPKSr
XBnqXwKBgQDGu4MZlszh2tZrlQBoJEQwWJWQi3JT3W3FQYVtRNhJD9op8l2aBERU
Ia750TQvkhiTz537ukiHFBZRZAwaus85XLXGHqyXf2DboEjpGc/Tfy0PgogRGrLN
BTyTyCCAxb88aYZ9XCibjNA/ik8wB2jvfz7dOTv2Jop1imRYOmauww==
-----END RSA PRIVATE KEY-----
''')

    @pytest.fixture(scope='function')
    def backend(self, user):
        return self.key_discovery_jwt_backend(user)
        
    @pytest.fixture(scope='function')
    def key_discovery_json(self):
        return {
            'keys':[
                {
                    "kty": "RSA",
                    "e": "AQAB",
                    "use": "sig",
                    "kid": "KeyID",
                    "alg": "RS256",
                    "n": "qOvwMnXHNjseNWf1La5cnD3O3KCiFCafRuQYXtHMPZbzge3Di9MVoXzoDveXbxGGJtLWoIrEy2OXfzTxP5z5irLvAVRca6h3_d4Fe37x0PH8AtelnYZu3lKZGGPCVRwitX23qqqA_WWHfxUdrflD1V2ipUmWxYsb_NV8MZ9pUmedwpG7GjAOrpNP-9aSwUrYys08iCHCwLQpLEiwtneHxdVUvd44mJtpBsxbBLQjwHW2CkPqmkZv4Tb7451EOCMRIGMJLnUrc0ESGmXm8NMmdL3Hbdu0sg3lrIZiiG1twLaO4Y6zJSRjvkXKpMakFiJTH-FsGI0_U-ntxXC1F4wL1w"
                }
            ]
        }
        
    def key_discovery_jwt_backend(self, user):
        def user_loader(payload):
            if user.id == payload['user']['id']:
                return user
            return None

        return JWTAuthBackend(user_loader, "", "RS256", key_discovery_url="https://test.discovery.com")


@pytest.fixture(scope='function')
def hawk_backend(user):
    def user_loader(username):
        return user if user.username == username else None

    def credentials_map(username):
        # Our backend will only know about the one user
        creds = {
            user.username: {
                'id': user.username,
                'key': user.password,
                'algorithm': 'sha256',
            }
        }

        return creds[username]

    return HawkAuthBackend(
        user_loader,
        receiver_kwargs=dict(credentials_map=credentials_map))


def get_hawk_token(user):
    sender = mohawk.Sender(
        credentials={
            'id': user.username,
            'key': user.password,
            'algorithm': 'sha256',
        },
        url='http://falconframework.org/auth',
        method='GET',
        nonce='ABC123',
        always_hash_content=False
    )
    return str(sender.request_header)


class HawkAuthFixture:

    @pytest.fixture(scope='function')
    def backend(self, hawk_backend):
        return hawk_backend

    @pytest.fixture(scope='function')
    def auth_token(self, user):
        return get_hawk_token(user)


@pytest.fixture(scope='function')
def none_backend(none_user):
    return NoneAuthBackend(lambda: none_user)


class NoneAuthFixture:

    @pytest.fixture(scope='function')
    def backend(self, none_user):
        return none_backend(none_user)


class CustomException(Exception):
    pass


class MultiBackendAuthFixture:
    class ErrorBackend(AuthBackend):
        def __init__(self, user_loader=None):
            pass

        def authenticate(self, req, resp, resource):
            if req.get_param_as_bool('exception'):
                raise CustomException
            else:
                raise falcon.HTTPUnauthorized

    @pytest.fixture(scope='function')
    def backend(self, basic_auth_backend, token_backend, hawk_backend, jwt_backend):
        return MultiAuthBackend(
            self.ErrorBackend(),
            basic_auth_backend,
            token_backend,
            hawk_backend,
            jwt_backend,
        )


class ResourceFixture:

    @pytest.fixture(scope='function')
    def resource(self):
        return AuthResource()


class ResourceAuthDisabled:

    @pytest.fixture(scope='function')
    def resource(self):
        resource = AuthResource()
        resource.auth = {'auth_disabled': True}
        return resource


class ResourceExemptGet:
    @pytest.fixture(scope='function')
    def resource(self):
        resource = AuthResource()
        resource.auth = {'exempt_methods': ['GET']}
        return resource


class ResourceCustomBackend:
    @pytest.fixture(scope='function')
    def resource(self, token_backend):
        resource = AuthResource()
        resource.auth = {'backend': token_backend}
        return resource


@pytest.fixture(scope='function')
def auth_middleware(backend):
    return FalconAuthMiddleware(backend)


@pytest.fixture(scope='function')
def app(auth_middleware, resource):
    return create_app(auth_middleware, resource)


@pytest.fixture(scope='function')
def client(app):
    return testing.TestClient(app)
