# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division

from tests.conftest import *


def simulate_request(client, url, method='POST', **kwargs):
    headers = {'Content-Type': 'application/json'}
    auth_token = kwargs.pop('auth_token', None)
    if auth_token:
        headers['Authorization'] = auth_token

    return client.simulate_request(method=method, path=url,
                                   headers=headers, **kwargs)


class TestWithBasicAuth(BasicAuthFixture, ResourceFixture):

    def test_valid_auth_success(self, client, auth_token, user):
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

    def test_invalid_prefix_fail(self, client, user):
        auth_token = get_basic_auth_token(user.username, user.password, 'ABC')
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Must start with Basic' in resp.text

    def test_non_bas64_encoded_fail(self, client, user):
        auth_token = 'Basic {username}_{password}'.format(
            username=user.username, password=user.password)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Unable to decode credentials' in resp.text

    def test_invalid_token_format_fail(self, client):
        b64 = base64.b64encode(b'invalid_token').decode('utf-8', 'ignore')
        auth_token = 'Basic {b64}'.format(b64=b64)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Unable to decode credentials' in resp.text

    def test_invalid_creds_fail(self, client, user):
        auth_token = get_basic_auth_token('invalid', user.password)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Invalid Username/Password' in resp.text

    def test_valid_auth_custom_prefix_success(self, client,
                                                 backend, user):
        backend.auth_header_prefix = 'Token'
        auth_token = get_basic_auth_token(user.username, user.password,
                                          backend.auth_header_prefix)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

    def test_backend_get_auth_token(self, user, backend, auth_token):
        user_payload = {'username': user.username, 'password': user.password}
        assert backend.get_auth_token(user_payload) == auth_token


class TestWithTokenAuth(TokenAuthFixture, ResourceFixture):

    def test_valid_auth_success(self, client, auth_token, user):
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

    def test_invalid_prefix_fail(self, client, user):
        auth_token = 'Invalid {token}'.format(token=user.token)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Must start with Token' in resp.text

    def test_token_missing_fail(self, client, user):
        auth_token = 'Token'
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Token Missing' in resp.text

    def test_invalid_creds_fail(self, client, user):
        auth_token = 'Token InvalidToken'
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Invalid Token' in resp.text

    def test_valid_auth_custom_prefix_success(self, client,
                                              backend, user):
        backend.auth_header_prefix = 'ApiToken'
        auth_token = '{auth_header_prefix} {token}'.format(
            auth_header_prefix=backend.auth_header_prefix, token=user.token)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

    def test_backend_get_auth_token(self, user, backend, auth_token):
        user_payload = {'token': user.token}
        assert backend.get_auth_token(user_payload) == auth_token


class TestWithJWTAuth(JWTAuthFixture, ResourceFixture):

    def test_valid_auth_success(self, client, auth_token, user):
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

    def test_invalid_prefix_fail(self, client, user, auth_token):
        auth_token = auth_token.replace('JWT', 'Invalid')
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Must start with jwt' in resp.text

    def test_invalid_creds_fail(self, client, user):
        cloned_user = user.clone()
        cloned_user.id = user.id + 1
        auth_token = get_jwt_token(cloned_user)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Invalid JWT Credentials' in resp.text

    def test_valid_auth_custom_prefix_success(self, client,
                                              backend, user, auth_token):
        backend.auth_header_prefix = 'CustomJWT'
        auth_token = auth_token.replace('JWT', backend.auth_header_prefix)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

    def test_init_aud_claim_none_audience_fails(self):
        with pytest.raises(ValueError) as ex:
            JWTAuthBackend(lambda u: u, SECRET_KEY, verify_claims=['aud'])

        assert 'Audience parameter must be provided' in str(ex.value)

    def test_init_iss_claim_none_issuer_fails(self):
        with pytest.raises(ValueError) as ex:
            JWTAuthBackend(lambda u: u, SECRET_KEY, verify_claims=['iss'])

        assert 'Issuer parameter must be provided' in str(ex.value)


class TestWithNoneAuth(NoneAuthFixture, ResourceFixture):

    def test_valid_auth_success(self, client, none_user):
        resp = simulate_request(client, '/auth')
        assert resp.status_code == 200
        assert resp.json == none_user.to_dict()


class TestWithMultiBackendAuth(MultiBackendAuthFixture, ResourceFixture):
    def test_valid_auth_success_any_backend(self, client, user):
        basic_auth_token = get_basic_auth_token(user.username, user.password)
        resp = simulate_request(client, '/auth', auth_token=basic_auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

        auth_token = get_token_auth(user)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

    def test_invalid_auth_fails(self, client, user):
        auth_token = get_basic_auth_token('Invalid', 'Invalid')
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Authorization Failed' in resp.text

    def test_backend_get_auth_token(self, user, backend):
        auth_token = get_basic_auth_token(user.username, user.password)
        user_payload = {'username': user.username, 'password': user.password}
        assert backend.get_auth_token(user_payload) == auth_token

    def test_backend_raises_exception(self, client, user, backend):
        auth_token = get_basic_auth_token('Invalid', 'Invalid')
        with pytest.raises(CustomException):
            resp = simulate_request(client, '/auth', auth_token=auth_token,
                                    query_string='exception=True')


class TestWithExemptRoute(BasicAuthFixture, ResourceFixture):
    def test_no_auth_required(self, auth_middleware, client):
        auth_middleware.exempt_routes = ['/auth']
        resp = simulate_request(client, '/auth', method='GET')
        assert resp.status_code == 200
        assert resp.text == 'Success'


class TestWithExemptMethod(BasicAuthFixture, ResourceFixture):
    def test_no_auth_required(self, auth_middleware, client):
        auth_middleware.exempt_methods = ['GET']
        resp = simulate_request(client, '/auth', method='GET')
        assert resp.status_code == 200
        assert resp.text == 'Success'


class TestInvalidAuthorizationHeader(BasicAuthFixture, ResourceFixture):
    def test_missing_auth_header_fails(self, auth_middleware, client):
        resp = simulate_request(client, '/auth')
        assert resp.status_code == 401
        assert 'Missing Authorization Header' in resp.text

    def test_auth_header_extra_content(self, auth_token, client):
        auth_token = '{auth_token} extra'.format(auth_token=auth_token)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'contains extra content' in resp.text.lower()


class TestWithCustomResourceBackend(BasicAuthFixture, ResourceCustomBackend):

    def test_with_token_auth_success(self, client, user):

        auth_token = 'Token {token}'.format(token=user.token)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()

    def test_with_basic_auth_fail(self, client, user, auth_token):

        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Must start with Token' in resp.text


class TestWithResourceAuthDisabled(BasicAuthFixture, ResourceAuthDisabled):

    def test_auth_endpoint_no_auth_success(self, client):
        resp = simulate_request(client, '/auth', method='GET')
        assert resp.status_code == 200
        assert resp.text == 'Success'


class TestWithResourceExemptMethod(BasicAuthFixture, ResourceExemptGet):

    def test_auth_endpoint_no_auth_success(self, client):
        resp = simulate_request(client, '/auth', method='GET')
        assert resp.status_code == 200
        assert resp.text == 'Success'


def test_auth_middleware_invalid_backend():
    class A(object):
        pass

    with pytest.raises(ValueError) as ex:
        FalconAuthMiddleware(backend=A())

    assert 'Invalid authentication backend' in str(ex.value)


def test_auth_middleware_none_backend():
    with pytest.raises(ValueError) as ex:
        FalconAuthMiddleware(backend=None)

    assert 'Invalid authentication backend' in str(ex.value)
