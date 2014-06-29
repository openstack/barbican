# Copyright (c) 2013-2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This test module focuses on RBAC interactions with the API resource classes.
For typical-flow business logic tests of these classes, see the
'resources_test.py' module.
"""

import os

import testtools

import mock
from oslo.config import cfg
from webob import exc

from barbican.api.controllers import orders
from barbican.api.controllers import secrets
from barbican.api.controllers import versions
from barbican import context
from barbican.openstack.common import policy


CONF = cfg.CONF

# Point to the policy.json file located in source control.
TEST_VAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            '../../../etc', 'barbican'))

ENFORCER = policy.Enforcer()


class TestableResource(object):

    def __init__(self, *args, **kwargs):
        self.controller = self.controller_cls(*args, **kwargs)

    def on_get(self, req, resp, *args, **kwargs):
        with mock.patch('pecan.request', req):
            with mock.patch('pecan.response', resp):
                return self.controller.index(*args, **kwargs)

    def on_post(self, req, resp, *args, **kwargs):
        with mock.patch('pecan.request', req):
            with mock.patch('pecan.response', resp):
                return self.controller.on_post(*args, **kwargs)

    def on_put(self, req, resp, *args, **kwargs):
        with mock.patch('pecan.request', req):
            with mock.patch('pecan.response', resp):
                return self.controller.on_put(*args, **kwargs)

    def on_delete(self, req, resp, *args, **kwargs):
        with mock.patch('pecan.request', req):
            with mock.patch('pecan.response', resp):
                return self.controller.on_delete(*args, **kwargs)


class VersionResource(TestableResource):
    controller_cls = versions.VersionController


class SecretsResource(TestableResource):
    controller_cls = secrets.SecretsController


class SecretResource(TestableResource):
    controller_cls = secrets.SecretController


class OrdersResource(TestableResource):
    controller_cls = orders.OrdersController


class OrderResource(TestableResource):
    controller_cls = orders.OrderController


class BaseTestCase(testtools.TestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        CONF(args=['--config-dir', TEST_VAR_DIR])
        self.policy_enforcer = ENFORCER
        self.policy_enforcer.load_rules(True)
        self.resp = mock.MagicMock()

    def _generate_req(self, roles=None, accept=None):
        """Generate a fake HTTP request with security context added to it."""
        req = mock.MagicMock()
        req.get_param.return_value = None

        kwargs = {
            'user': None,
            'tenant': None,
            'roles': roles or [],
            'policy_enforcer': self.policy_enforcer,
        }
        req.environ = {}
        req.environ['barbican.context'] = context.RequestContext(**kwargs)
        if accept:
            req.accept.header_value.return_value = accept
        else:
            req.accept = None

        return req

    def _generate_stream_for_exit(self):
        """Mock HTTP stream generator, to force RBAC-pass exit.

        Generate a fake HTTP request stream that forces an IOError to
        occur, which short circuits API resource processing when RBAC
        checks under test here pass.
        """
        stream = mock.MagicMock()
        read = mock.MagicMock(return_value=None, side_effect=IOError())
        stream.read = read
        return stream

    def _assert_post_rbac_exception(self, exception, role):
        """Assert that we received the expected RBAC-passed exception."""
        self.assertEqual(500, exception.status_int)

    def _generate_get_error(self):
        """Falcon exception generator to throw from early-exit mocks.

        Creates an exception that should be raised by GET tests that pass
        RBAC. This allows such flows to short-circuit normal post-RBAC
        processing that is not tested in this module.

        :return: Python exception that should be raised by repo get methods.
        """
        # The 'Read Error' clause needs to match that asserted in
        #    _assert_post_rbac_exception() above.
        return exc.HTTPInternalServerError(message='Read Error')

    def _assert_pass_rbac(self, roles, method_under_test, accept=None):
        """Assert that RBAC authorization rules passed for the specified roles.

        :param roles: List of roles to check, one at a time
        :param method_under_test: The test method to invoke for each role.
        :param accept Optional Accept header to set on the HTTP request
        :return: None
        """
        for role in roles:
            self.req = self._generate_req(roles=[role] if role else [],
                                          accept=accept)

            # Force an exception early past the RBAC passing.
            self.req.body_file = self._generate_stream_for_exit()
            exception = self.assertRaises(exc.HTTPInternalServerError,
                                          method_under_test)
            self._assert_post_rbac_exception(exception, role)

            self.setUp()  # Need to re-setup

    def _assert_fail_rbac(self, roles, method_under_test, accept=None):
        """Assert that RBAC rules failed for one of the specified roles.

        :param roles: List of roles to check, one at a time
        :param method_under_test: The test method to invoke for each role.
        :param accept Optional Accept header to set on the HTTP request
        :return: None
        """
        for role in roles:
            self.req = self._generate_req(roles=[role] if role else [],
                                          accept=accept)

            exception = self.assertRaises(exc.HTTPForbidden, method_under_test)
            self.assertEqual(403, exception.status_int)

            self.setUp()  # Need to re-setup


class WhenTestingVersionResource(BaseTestCase):
    """RBAC tests for the barbican.api.resources.VersionResource class."""
    def setUp(self):
        super(WhenTestingVersionResource, self).setUp()

        self.resource = VersionResource()

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_get_version(self):
        # Can't use base method that short circuits post-RBAC processing here,
        # as version GET is trivial
        for role in ['admin', 'observer', 'creator', 'audit']:
            self.req = self._generate_req(roles=[role] if role else [])
            self._invoke_on_get()
            self.setUp()  # Need to re-setup

    def test_should_pass_get_version_with_bad_roles(self):
        self.req = self._generate_req(roles=[None, 'bunkrolehere'])
        self._invoke_on_get()

    def test_should_pass_get_version_with_no_roles(self):
        self.req = self._generate_req()
        self._invoke_on_get()

    def test_should_pass_get_version_multiple_roles(self):
        self.req = self._generate_req(roles=['admin', 'observer', 'creator',
                                             'audit'])
        self._invoke_on_get()

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp)


class WhenTestingSecretsResource(BaseTestCase):
    """RBAC tests for the barbican.api.resources.SecretsResource class."""
    def setUp(self):
        super(WhenTestingSecretsResource, self).setUp()

        self.keystone_id = '12345'

        # Force an error on GET calls that pass RBAC, as we are not testing
        #   such flows in this test module.
        self.secret_repo = mock.MagicMock()
        get_by_create_date = mock.MagicMock(return_value=None,
                                            side_effect=self
                                            ._generate_get_error())
        self.secret_repo.get_by_create_date = get_by_create_date

        self.resource = SecretsResource(tenant_repo=mock.MagicMock(),
                                        secret_repo=self.secret_repo,
                                        tenant_secret_repo=mock
                                        .MagicMock(),
                                        datum_repo=mock.MagicMock(),
                                        kek_repo=mock.MagicMock(),
                                        secret_meta_repo=mock.MagicMock())

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_create_secret(self):
        self._assert_pass_rbac(['admin', 'creator'], self._invoke_on_post)

    def test_should_fail_create_secret(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'bogus'],
                               self._invoke_on_post)

    def test_should_pass_get_secrets(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator'],
                               self._invoke_on_get)

    def test_should_fail_get_secrets(self):
        self._assert_fail_rbac([None, 'audit', 'bogus'],
                               self._invoke_on_get)

    def _invoke_on_post(self):
        self.resource.on_post(self.req, self.resp, self.keystone_id)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)


class WhenTestingSecretResource(BaseTestCase):
    """RBAC tests for the barbican.api.resources.SecretResource class."""
    def setUp(self):
        super(WhenTestingSecretResource, self).setUp()

        self.keystone_id = '12345tenant'
        self.secret_id = '12345secret'

        # Force an error on GET and DELETE calls that pass RBAC,
        #   as we are not testing such flows in this test module.
        self.secret_repo = mock.MagicMock()
        fail_method = mock.MagicMock(return_value=None,
                                     side_effect=self._generate_get_error())
        self.secret_repo.get = fail_method
        self.secret_repo.delete_entity_by_id = fail_method

        self.resource = SecretResource(self.secret_id,
                                       tenant_repo=mock.MagicMock(),
                                       secret_repo=self.secret_repo,
                                       datum_repo=mock.MagicMock(),
                                       kek_repo=mock.MagicMock())

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_decrypt_secret(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype')

    def test_should_fail_decrypt_secret(self):
        self._assert_fail_rbac([None, 'audit', 'bogus'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype')

    def test_should_pass_get_secret(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get)

    def test_should_fail_get_secret(self):
        self._assert_fail_rbac([None, 'bogus'],
                               self._invoke_on_get)

    def test_should_pass_put_secret(self):
        self._assert_pass_rbac(['admin', 'creator'], self._invoke_on_put)

    def test_should_fail_put_secret(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'bogus'],
                               self._invoke_on_put)

    def test_should_pass_delete_secret(self):
        self._assert_pass_rbac(['admin'], self._invoke_on_delete)

    def test_should_fail_delete_secret(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'creator', 'bogus'],
                               self._invoke_on_delete)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp,
                             self.keystone_id)

    def _invoke_on_put(self):
        self.resource.on_put(self.req, self.resp,
                             self.keystone_id)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp,
                                self.keystone_id)


class WhenTestingOrdersResource(BaseTestCase):
    """RBAC tests for the barbican.api.resources.OrdersResource class."""
    def setUp(self):
        super(WhenTestingOrdersResource, self).setUp()

        self.keystone_id = '12345'

        # Force an error on GET calls that pass RBAC, as we are not testing
        #   such flows in this test module.
        self.order_repo = mock.MagicMock()
        get_by_create_date = mock.MagicMock(return_value=None,
                                            side_effect=self
                                            ._generate_get_error())
        self.order_repo.get_by_create_date = get_by_create_date

        self.resource = OrdersResource(tenant_repo=mock.MagicMock(),
                                       order_repo=self.order_repo,
                                       queue_resource=mock.MagicMock())

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_create_order(self):
        self._assert_pass_rbac(['admin', 'creator'], self._invoke_on_post)

    def test_should_fail_create_order(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'bogus'],
                               self._invoke_on_post)

    def test_should_pass_get_orders(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator'],
                               self._invoke_on_get)

    def test_should_fail_get_orders(self):
        self._assert_fail_rbac([None, 'audit', 'bogus'],
                               self._invoke_on_get)

    def _invoke_on_post(self):
        self.resource.on_post(self.req, self.resp, self.keystone_id)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)


class WhenTestingOrderResource(BaseTestCase):
    """RBAC tests for the barbican.api.resources.OrderResource class."""
    def setUp(self):
        super(WhenTestingOrderResource, self).setUp()

        self.keystone_id = '12345tenant'
        self.order_id = '12345order'

        # Force an error on GET and DELETE calls that pass RBAC,
        #   as we are not testing such flows in this test module.
        self.order_repo = mock.MagicMock()
        fail_method = mock.MagicMock(return_value=None,
                                     side_effect=self._generate_get_error())
        self.order_repo.get = fail_method
        self.order_repo.delete_entity_by_id = fail_method

        self.resource = OrderResource(self.order_id,
                                      order_repo=self.order_repo)

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_get_order(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get)

    def test_should_fail_get_order(self):
        self._assert_fail_rbac([None, 'bogus'],
                               self._invoke_on_get)

    def test_should_pass_delete_order(self):
        self._assert_pass_rbac(['admin'], self._invoke_on_delete)

    def test_should_fail_delete_order(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'creator', 'bogus'],
                               self._invoke_on_delete)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp, self.keystone_id)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp, self.keystone_id)
