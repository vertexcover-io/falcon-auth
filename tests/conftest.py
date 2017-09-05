# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division

import base64
import binascii
import json
import os
from datetime import datetime, timedelta

import falcon
import jwt
import pytest
from falcon import testing

from falcon_auth.backends import AuthBackend, BasicAuthBackend, \
    JWTAuthBackend, NoneAuthBackend, MultiAuthBackend
from falcon_auth.middleware import FalconAuthMiddleware
from falcon_auth.backends import TokenAuthBackend


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
    return api


class AuthResource:

    def on_post(self, req, resp):
        user = req.context['user']
        resp.body = user.serialize()

    def on_get(self, req, resp):
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


def get_jwt_token(user, prefix='JWT'):
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

    jwt_token = jwt.encode(payload, SECRET_KEY).decode('utf-8')
    return '{prefix} {jwt_token}'.format(prefix=prefix, jwt_token=jwt_token)


class JWTAuthFixture:

    @pytest.fixture(scope='function')
    def backend(self, user):
        return jwt_backend(user)

    @pytest.fixture(scope='function')
    def auth_token(self, user):

        return get_jwt_token(user)


@pytest.fixture(scope='function')
def none_backend(none_user):
    return NoneAuthBackend(lambda: none_user)


class NoneAuthFixture:

    @pytest.fixture(scope='function')
    def backend(self, none_user):
        return none_backend(none_user)


class MultiBackendAuthFixture:

    class ErroBackend(AuthBackend):

        def __init__(self, user_loader=None):
            pass

        def authenticate(self, req, resp, resource):
            if req.get_param_as_bool('exception'):
                raise falcon.HTTPInternalServerError('A custom error occured.')
            else:
                raise falcon.HTTPUnauthorized

    @pytest.fixture(scope='function')
    def backend(self, basic_auth_backend, token_backend):
        return MultiAuthBackend(
            self.ErroBackend(),
            basic_auth_backend,
            token_backend,
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
