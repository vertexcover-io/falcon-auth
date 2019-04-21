# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division

import time
from tests.conftest import *


def simulate_request(client, url, method='POST', **kwargs):
    if method == 'POST':
        headers = {'Content-Type': 'application/json'}
    else:
        headers = {}
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
        assert 'User not found for provided credentials' in resp.text

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

    def test_on_success_callback(self, user, backend, resource, auth_token):
        callback_called = [False]

        def on_success(req, resp, resrc, results):
            callback_called[0] = True
            assert results['backend'] is backend
            assert results['user'] is user

        app = create_app(FalconAuthMiddleware(backend, on_success=on_success), resource)
        client = testing.TestClient(app)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert callback_called[0], 'on_success() not called'

    def test_on_failure_callback(self, user, backend, resource):
        callback_called = [False]

        def on_failure(req, resp, resrc, exception):
            callback_called[0] = True
            assert isinstance(exception, BackendAuthenticationFailure)
            assert not hasattr(exception, '__cause__') or not exception.__cause__

        app = create_app(FalconAuthMiddleware(backend, on_failure=on_failure), resource)
        client = testing.TestClient(app)
        auth_token = get_basic_auth_token('invalid', user.password)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert callback_called[0], 'on_failure() not called'

    def test_on_failure_callback_called_even_if_not_applicable(self, user, backend, resource):
        callback_called = [False]

        def on_failure(req, resp, resrc, exception):
            callback_called[0] = True
            assert isinstance(exception, BackendNotApplicable)

        app = create_app(FalconAuthMiddleware(backend, on_failure=on_failure), resource)
        client = testing.TestClient(app)
        auth_token = get_token_auth(user)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert callback_called[0], 'on_failure() not called'


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
        assert 'User not found for provided credentials' in resp.text

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

    def test_on_success_callback(self, user, backend, resource, auth_token):
        callback_called = [False]

        def on_success(req, resp, resrc, results):
            callback_called[0] = True
            assert results['backend'] is backend
            assert results['user'] is user

        app = create_app(FalconAuthMiddleware(backend, on_success=on_success), resource)
        client = testing.TestClient(app)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert callback_called[0], 'on_success() not called'

    def test_on_failure_callback(self, user, backend, resource):
        callback_called = [False]

        def on_failure(req, resp, resrc, exception):
            callback_called[0] = True
            assert isinstance(exception, UserNotFound)

        app = create_app(FalconAuthMiddleware(backend, on_failure=on_failure), resource)
        client = testing.TestClient(app)
        auth_token = 'Token InvalidToken'
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert callback_called[0], 'on_failure() not called'


@jwt_available
class TestWithJWTAuth(JWTAuthFixture, ResourceFixture):

    def test_get_auth_header(self, jwt_backend, user):
        auth_header = jwt_backend.get_auth_header(user.to_dict())
        prefix, data = auth_header.split()
        assert prefix == 'jwt'

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
        assert 'User not found for provided credentials' in resp.text

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

    def test_jwt_fields_and_alg_in_token(self):
        backend = JWTAuthBackend(
            lambda u:u,
            SECRET_KEY,
            algorithm='HS512',
            audience="test-aud", issuer="test-iss",
            required_claims=['aud', 'iss'])
        token = backend.get_auth_token({})

        header = jwt.get_unverified_header(token)
        assert header['alg'] == 'HS512' # check algorithm

        payload = jwt.decode(
            token,
            SECRET_KEY,
            audience="test-aud",
            issuer="test-iss")
        assert payload['aud'] == 'test-aud'
        assert payload['iss'] == 'test-iss'

    def test_backend_get_auth_token(self, user, backend):
        user_payload = {
            'id': user.id,
            'username': user.username
        }
        auth_token = backend.get_auth_token(user_payload)
        decoded_token = jwt.decode(auth_token, SECRET_KEY)
        assert decoded_token['user'] == user_payload

    def test_on_success_callback(self, user, backend, resource, auth_token):
        callback_called = [False]

        def on_success(req, resp, resrc, results):
            callback_called[0] = True
            assert results['backend'] is backend
            assert results['user'] is user

        app = create_app(FalconAuthMiddleware(backend, on_success=on_success), resource)
        client = testing.TestClient(app)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert callback_called[0], 'on_success() not called'

    def test_on_failure_callback(self, user, backend, resource):
        callback_called = [False]

        def on_failure(req, resp, resrc, exception):
            callback_called[0] = True
            assert isinstance(exception, UserNotFound)

        app = create_app(FalconAuthMiddleware(backend, on_failure=on_failure), resource)
        client = testing.TestClient(app)
        cloned_user = user.clone()
        cloned_user.id = user.id + 1
        auth_token = get_jwt_token(cloned_user)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert callback_called[0], 'on_failure() not called'


@hawk_available
class TestWithHawkAuth(HawkAuthFixture, ResourceFixture):

    def test_valid_auth_success(self, client, auth_token, user):
        resp = simulate_request(client, '/auth', method='GET', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.text == 'Success'

    def test_invalid_prefix_fail(self, client, user, auth_token):
        auth_token = auth_token.replace('Hawk', 'Invalid')
        resp = simulate_request(client, '/auth', method='GET', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'Must start with Hawk' in resp.text

    def test_unrecognized_user_fails(self, client, user):
        cloned_user = user.clone()
        cloned_user.username = 'jane'
        auth_token = get_hawk_token(cloned_user)
        resp = simulate_request(client, '/auth', method='GET', auth_token=auth_token)
        assert resp.status_code == 401
        assert resp.json['description'] == 'User not found for provided credentials'

    def test_invalid_password_fails(self, client, user):
        cloned_user = user.clone()
        cloned_user.password = 'incorrect password'
        auth_token = get_hawk_token(cloned_user)
        resp = simulate_request(client, '/auth', method='GET', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'MacMismatch(MACs do not match' in resp.json['description']

    def test_on_success_callback(self, user, backend, resource, auth_token):
        callback_called = [False]

        def on_success(req, resp, resrc, results):
            callback_called[0] = True
            assert results['backend'] is backend
            assert results['user'] is user

        app = create_app(FalconAuthMiddleware(backend, on_success=on_success), resource)
        client = testing.TestClient(app)
        resp = simulate_request(client, '/auth', method='GET', auth_token=auth_token)
        assert resp.status_code == 200
        assert callback_called[0], 'on_success() not called'

    def test_on_failure_callback(self, user, backend, resource):
        callback_called = [False]

        def on_failure(req, resp, resrc, exception):
            callback_called[0] = True
            assert isinstance(exception, falcon.HTTPUnauthorized)
            assert not isinstance(exception, BackendNotApplicable)

        app = create_app(FalconAuthMiddleware(backend, on_failure=on_failure), resource)
        client = testing.TestClient(app)
        cloned_user = user.clone()
        cloned_user.password = 'incorrect password'
        auth_token = get_hawk_token(cloned_user)
        resp = simulate_request(client, '/auth', method='GET', auth_token=auth_token)
        assert resp.status_code == 401
        assert callback_called[0], 'on_failure() not called'


class TestWithNoneAuth(NoneAuthFixture, ResourceFixture):

    def test_valid_auth_success(self, client, none_user):
        resp = simulate_request(client, '/auth')
        assert resp.status_code == 200
        assert resp.json == none_user.to_dict()


@hawk_available
@jwt_available
class TestWithMultiBackendAuth(MultiBackendAuthFixture, ResourceFixture):
    def test_valid_auth_success_basic_backend(self, user, backend, resource):
        callback_called = [False]

        def on_success(req, resp, resrc, results):
            callback_called[0] = True
            assert isinstance(results['backend'], BasicAuthBackend)
            assert results['user'] is user

        app = create_app(FalconAuthMiddleware(backend, on_success=on_success), resource)
        client = testing.TestClient(app)
        auth_token = get_basic_auth_token(user.username, user.password)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()
        assert callback_called[0], 'on_success() not called'

    def test_valid_auth_success_token_backend(self, user, backend, resource):
        callback_called = [False]

        def on_success(req, resp, resrc, results):
            callback_called[0] = True
            assert isinstance(results['backend'], TokenAuthBackend)
            assert results['user'] is user

        app = create_app(FalconAuthMiddleware(backend, on_success=on_success), resource)
        client = testing.TestClient(app)
        auth_token = get_token_auth(user)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()
        assert callback_called[0], 'on_success() not called'

    def test_valid_auth_success_hawk_backend(self, user, backend, resource):
        callback_called = [False]

        def on_success(req, resp, resrc, results):
            callback_called[0] = True
            assert isinstance(results['backend'], HawkAuthBackend)
            assert results['user'] is user
            assert 'receiver' in results

        app = create_app(FalconAuthMiddleware(backend, on_success=on_success), resource)
        client = testing.TestClient(app)
        auth_token = get_hawk_token(user)
        resp = simulate_request(client, '/auth', method='GET', auth_token=auth_token)
        assert resp.status_code == 200
        assert callback_called[0], 'on_success() not called'

    def test_valid_auth_success_jwt_backend(self, user, backend, resource):
        callback_called = [False]

        def on_success(req, resp, resrc, results):
            callback_called[0] = True
            assert isinstance(results['backend'], JWTAuthBackend)
            assert results['user'] is user

        app = create_app(FalconAuthMiddleware(backend, on_success=on_success), resource)
        client = testing.TestClient(app)
        auth_token = get_jwt_token(user)
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 200
        assert resp.json == user.to_dict()
        assert callback_called[0], 'on_success() not called'

    def test_invalid_auth_fails(self, client, user):
        auth_token = get_basic_auth_token('Invalid', 'Invalid')
        resp = simulate_request(client, '/auth', auth_token=auth_token)
        assert resp.status_code == 401
        assert resp.json['description'] == 'Authentication Failed'

    def test_backend_get_auth_token(self, user, backend):
        auth_token = get_basic_auth_token(user.username, user.password)
        user_payload = {'username': user.username, 'password': user.password}
        assert backend.get_auth_token(user_payload) == auth_token

    def test_backend_raises_unexpected_exception(self, user, backend, resource):
        callback_called = [False]

        def on_failure(req, resp, resrc, exception):
            callback_called[0] = True
            assert isinstance(exception, BackendAuthenticationFailure)
            assert isinstance(exception.__cause__, CustomException)
            assert exception.backend is backend

        app = create_app(FalconAuthMiddleware(backend, on_failure=on_failure), resource)
        client = testing.TestClient(app)
        auth_token = get_basic_auth_token('Invalid', 'Invalid')
        with pytest.raises(CustomException):
            simulate_request(client, '/auth', auth_token=auth_token,
                             query_string='exception=custom')
        assert callback_called[0], 'on_failure() not called'

    def test_backend_raises_expected_exception(self, client, user, backend):
        auth_token = get_basic_auth_token('Invalid', 'Invalid')
        resp = simulate_request(client, '/auth', auth_token=auth_token,
                                query_string='exception=unauthorized')
        assert resp.status_code == 401


@hawk_available
@jwt_available
class TestWithEarlyExitMultiAuthBackend(EarlyExitMultiBackendAuthFixture, ResourceFixture):

    def test_invalid_auth_fails_and_exits(self, user, backend, resource):
        callback_called = [False]

        def on_failure(req, resp, resrc, exception):
            callback_called[0] = True
            assert isinstance(exception, BackendAuthenticationFailure)
            assert isinstance(exception.backend, HawkAuthBackend)

        app = create_app(FalconAuthMiddleware(backend, on_failure=on_failure), resource)
        client = testing.TestClient(app)
        auth_token = get_hawk_token(user, timestamp=int(time.time()) + 3600)
        resp = simulate_request(client, '/auth', method='GET', auth_token=auth_token)
        assert resp.status_code == 401
        assert 'TokenExpired' in resp.json['description']
        assert callback_called[0], 'on_failure() not called'




class TestWithExemptRoute(BasicAuthFixture, ResourceFixture):
    def test_exempt_static_route(self, auth_middleware, client):
        auth_middleware.exempt_routes = ['/auth']
        resp = simulate_request(client, '/auth', method='GET')
        assert resp.status_code == 200
        assert resp.text == 'Success'

    def test_exempt_template_route(self, auth_middleware, client):
        auth_middleware.exempt_routes = ['/posts/{post_id}']
        resp = simulate_request(client, '/posts/1234', method='GET')
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


def test_auth_middleware_invalid_backend_type():
    class A(object):
        pass

    with pytest.raises(ValueError) as ex:
        FalconAuthMiddleware(backend=A())

    assert 'Invalid authentication backend' in str(ex.value)
    assert 'Must inherit falcon.auth.backends.AuthBackend' in str(ex.value)


def test_auth_middleware_none_backend():
    with pytest.raises(ValueError) as ex:
        FalconAuthMiddleware(backend=None)

    assert 'Invalid authentication backend' in str(ex.value)


@jwt_available
def test_optional_jwt_not_present(monkeypatch):
    monkeypatch.delattr('falcon_auth.backends.jwt')
    with pytest.raises(ImportError):
        JWTAuthBackend(lambda _: None, SECRET_KEY)


@hawk_available
def test_optional_hawk_not_present(monkeypatch):
    monkeypatch.delattr('falcon_auth.backends.mohawk')
    with pytest.raises(ImportError):
        HawkAuthBackend(lambda _: None, lambda _: None, {})
