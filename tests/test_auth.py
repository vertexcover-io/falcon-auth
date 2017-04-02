# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division

from tests.conftest import *


def simulate_request(client, url, method='POST', data=None, auth_token=None):
    data = json.dumps(data) if data else None
    headers = {'Content-Type': 'application/json'}
    if auth_token:
        headers['Authorization'] = auth_token

    return client.simulate_request(method=method, path=url,
                                   body=data, headers=headers)


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
        auth_token = f'Basic {user.username}_{user.password}'
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Unable to decode credentials' in resp.text

    def test_invalid_token_format_fail(self, client):
        b64 = base64.b64encode(b'invalid_token').decode('utf-8', 'ignore')
        auth_token = f'Basic {b64}'
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
        auth_token = f'Invalid {user.token}'
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Must start with Token' in resp.text

    def test_token_missing_fail(self, client, user):
        auth_token = f'Token'
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Token Missing' in resp.text

    def test_invalid_creds_fail(self, client, user):
        auth_token = f'Token InvalidToken'
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Invalid Token' in resp.text

    def test_valid_auth_custom_prefix_success(self, client,
                                              backend, user):
        backend.auth_header_prefix = 'ApiToken'
        auth_token = f'{backend.auth_header_prefix} {user.token}'
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
        auth_token = f'{auth_token} extra'
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'contains extra content' in resp.text.lower()


class TestWithCustomResourceBackend(BasicAuthFixture, ResourceCustomBackend):

    def test_with_token_auth_success(self, client, user):

        auth_token = f'Token {user.token}'
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
