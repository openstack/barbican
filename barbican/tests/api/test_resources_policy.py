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

import mock
from oslo_config import cfg
from webob import exc

from barbican.api.controllers import consumers
from barbican.api.controllers import orders
from barbican.api.controllers import secrets
from barbican.api.controllers import versions
from barbican import context
from barbican.openstack.common import policy
from barbican.tests.api import common as api_common
from barbican.tests import utils


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
                return self.controller.on_get(*args, **kwargs)

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


class ConsumersResource(TestableResource):
    controller_cls = consumers.ContainerConsumersController


class ConsumerResource(TestableResource):
    controller_cls = consumers.ContainerConsumerController


class BaseTestCase(utils.BaseTestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        CONF(args=['--config-dir', TEST_VAR_DIR])
        self.policy_enforcer = ENFORCER
        self.policy_enforcer.load_rules(True)
        self.resp = mock.MagicMock()

    def _generate_req(self, roles=None, accept=None, content_type=None):
        """Generate a fake HTTP request with security context added to it."""
        req = mock.MagicMock()
        req.get_param.return_value = None

        kwargs = {
            'user': None,
            'project': None,
            'roles': roles or [],
            'policy_enforcer': self.policy_enforcer,
        }
        req.environ = {}
        req.environ['barbican.context'] = context.RequestContext(**kwargs)
        req.content_type = content_type
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
        return exc.HTTPServerError(message='Read Error')

    def _assert_pass_rbac(self, roles, method_under_test, accept=None,
                          content_type=None):
        """Assert that RBAC authorization rules passed for the specified roles.

        :param roles: List of roles to check, one at a time
        :param method_under_test: The test method to invoke for each role.
        :param accept Optional Accept header to set on the HTTP request
        :return: None
        """
        for role in roles:
            self.req = self._generate_req(roles=[role] if role else [],
                                          accept=accept,
                                          content_type=content_type)

            # Force an exception early past the RBAC passing.
            self.req.body_file = self._generate_stream_for_exit()
            exception = self.assertRaises(exc.HTTPServerError,
                                          method_under_test)
            self._assert_post_rbac_exception(exception, role)

    def _assert_fail_rbac(self, roles, method_under_test, accept=None,
                          content_type=None):
        """Assert that RBAC rules failed for one of the specified roles.

        :param roles: List of roles to check, one at a time
        :param method_under_test: The test method to invoke for each role.
        :param accept Optional Accept header to set on the HTTP request
        :return: None
        """
        for role in roles:
            self.req = self._generate_req(roles=[role] if role else [],
                                          accept=accept,
                                          content_type=content_type)

            exception = self.assertRaises(exc.HTTPForbidden, method_under_test)
            self.assertEqual(403, exception.status_int)


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


class WhenTestingSecretsResource(BaseTestCase,
                                 api_common.MockModelRepositoryMixin):
    """RBAC tests for the barbican.api.resources.SecretsResource class."""
    def setUp(self):
        super(WhenTestingSecretsResource, self).setUp()

        self.external_project_id = '12345'

        # Force an error on GET calls that pass RBAC, as we are not testing
        #   such flows in this test module.
        self.secret_repo = mock.MagicMock()
        get_by_create_date = mock.MagicMock(return_value=None,
                                            side_effect=self
                                            ._generate_get_error())
        self.secret_repo.get_by_create_date = get_by_create_date
        self.setup_secret_repository_mock(self.secret_repo)

        self.setup_encrypted_datum_repository_mock()
        self.setup_kek_datum_repository_mock()
        self.setup_project_repository_mock()
        self.setup_project_secret_repository_mock()
        self.setup_secret_meta_repository_mock()
        self.setup_transport_key_repository_mock()

        self.resource = SecretsResource()

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_create_secret(self):
        self._assert_pass_rbac(['admin', 'creator'], self._invoke_on_post,
                               content_type='application/json')

    def test_should_raise_create_secret(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'bogus'],
                               self._invoke_on_post,
                               content_type='application/json')

    def test_should_pass_get_secrets(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator'],
                               self._invoke_on_get,
                               content_type='application/json')

    def test_should_raise_get_secrets(self):
        self._assert_fail_rbac([None, 'audit', 'bogus'],
                               self._invoke_on_get,
                               content_type='application/json')

    def _invoke_on_post(self):
        self.resource.on_post(self.req, self.resp, self.external_project_id)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp, self.external_project_id)


class WhenTestingSecretResource(BaseTestCase,
                                api_common.MockModelRepositoryMixin):
    """RBAC tests for the barbican.api.resources.SecretResource class."""
    def setUp(self):
        super(WhenTestingSecretResource, self).setUp()

        self.external_project_id = '12345project'
        self.secret_id = '12345secret'

        # Force an error on GET and DELETE calls that pass RBAC,
        #   as we are not testing such flows in this test module.
        self.secret_repo = mock.MagicMock()
        fail_method = mock.MagicMock(return_value=None,
                                     side_effect=self._generate_get_error())
        self.secret_repo.get = fail_method
        self.secret_repo.delete_entity_by_id = fail_method
        self.setup_secret_repository_mock(self.secret_repo)

        self.setup_encrypted_datum_repository_mock()
        self.setup_kek_datum_repository_mock()
        self.setup_project_repository_mock()
        self.setup_secret_meta_repository_mock()
        self.setup_transport_key_repository_mock()

        self.resource = SecretResource(self.secret_id)

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_decrypt_secret(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json')

    def test_should_raise_decrypt_secret(self):
        self._assert_fail_rbac([None, 'audit', 'bogus'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype')

    def test_should_pass_get_secret(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get)

    def test_should_raise_get_secret(self):
        self._assert_fail_rbac([None, 'bogus'],
                               self._invoke_on_get)

    def test_should_pass_put_secret(self):
        self._assert_pass_rbac(['admin', 'creator'], self._invoke_on_put,
                               content_type="application/octet-stream")

    def test_should_raise_put_secret(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'bogus'],
                               self._invoke_on_put,
                               content_type="application/octet-stream")

    def test_should_pass_delete_secret(self):
        self._assert_pass_rbac(['admin'], self._invoke_on_delete)

    def test_should_raise_delete_secret(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'creator', 'bogus'],
                               self._invoke_on_delete)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp,
                             self.external_project_id)

    def _invoke_on_put(self):
        self.resource.on_put(self.req, self.resp,
                             self.external_project_id)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp,
                                self.external_project_id)


class WhenTestingOrdersResource(BaseTestCase,
                                api_common.MockModelRepositoryMixin):
    """RBAC tests for the barbican.api.resources.OrdersResource class."""
    def setUp(self):
        super(WhenTestingOrdersResource, self).setUp()

        self.external_project_id = '12345'

        # Force an error on GET calls that pass RBAC, as we are not testing
        #   such flows in this test module.
        self.order_repo = mock.MagicMock()
        get_by_create_date = mock.MagicMock(return_value=None,
                                            side_effect=self
                                            ._generate_get_error())
        self.order_repo.get_by_create_date = get_by_create_date

        self.setup_order_repository_mock(self.order_repo)
        self.setup_project_repository_mock()

        self.resource = OrdersResource(queue_resource=mock.MagicMock())

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_create_order(self):
        self._assert_pass_rbac(['admin', 'creator'], self._invoke_on_post,
                               content_type='application/json')

    def test_should_raise_create_order(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'bogus'],
                               self._invoke_on_post)

    def test_should_pass_get_orders(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator'],
                               self._invoke_on_get)

    def test_should_raise_get_orders(self):
        self._assert_fail_rbac([None, 'audit', 'bogus'],
                               self._invoke_on_get)

    def _invoke_on_post(self):
        self.resource.on_post(self.req, self.resp, self.external_project_id)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp, self.external_project_id)


class WhenTestingOrderResource(BaseTestCase,
                               api_common.MockModelRepositoryMixin):
    """RBAC tests for the barbican.api.resources.OrderResource class."""
    def setUp(self):
        super(WhenTestingOrderResource, self).setUp()

        self.external_project_id = '12345project'
        self.order_id = '12345order'

        # Force an error on GET and DELETE calls that pass RBAC,
        #   as we are not testing such flows in this test module.
        self.order_repo = mock.MagicMock()
        fail_method = mock.MagicMock(return_value=None,
                                     side_effect=self._generate_get_error())
        self.order_repo.get = fail_method
        self.order_repo.delete_entity_by_id = fail_method

        self.setup_order_repository_mock(self.order_repo)

        self.resource = OrderResource(self.order_id)

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_get_order(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get)

    def test_should_raise_get_order(self):
        self._assert_fail_rbac([None, 'bogus'],
                               self._invoke_on_get)

    def test_should_pass_delete_order(self):
        self._assert_pass_rbac(['admin'], self._invoke_on_delete)

    def test_should_raise_delete_order(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'creator', 'bogus'],
                               self._invoke_on_delete)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp, self.external_project_id)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp, self.external_project_id)


class WhenTestingConsumersResource(BaseTestCase,
                                   api_common.MockModelRepositoryMixin):
    """RBAC tests for the barbican.api.resources.ConsumersResource class."""
    def setUp(self):
        super(WhenTestingConsumersResource, self).setUp()

        self.external_project_id = '12345project'
        self.container_id = '12345container'

        # Force an error on GET calls that pass RBAC, as we are not testing
        #   such flows in this test module.
        self.consumer_repo = mock.MagicMock()
        get_by_container_id = mock.MagicMock(return_value=None,
                                             side_effect=self
                                             ._generate_get_error())
        self.consumer_repo.get_by_container_id = get_by_container_id

        self.setup_project_repository_mock()
        self.setup_container_consumer_repository_mock(self.consumer_repo)
        self.setup_container_repository_mock()

        self.resource = ConsumersResource(container_id=self.container_id)

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_create_consumer(self):
        self._assert_pass_rbac(['admin'], self._invoke_on_post,
                               content_type='application/json')

    def test_should_raise_create_consumer(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'creator', 'bogus'],
                               self._invoke_on_post,
                               content_type='application/json')

    def test_should_pass_delete_consumer(self):
        self._assert_pass_rbac(['admin'], self._invoke_on_delete,
                               content_type='application/json')

    def test_should_raise_delete_consumer(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'creator', 'bogus'],
                               self._invoke_on_delete)

    def test_should_pass_get_consumers(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               content_type='application/json')

    def test_should_raise_get_consumers(self):
        self._assert_fail_rbac([None, 'bogus'],
                               self._invoke_on_get,
                               content_type='application/json')

    def _invoke_on_post(self):
        self.resource.on_post(self.req, self.resp, self.external_project_id)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp, self.external_project_id)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp, self.external_project_id)


class WhenTestingConsumerResource(BaseTestCase,
                                  api_common.MockModelRepositoryMixin):
    """RBAC tests for the barbican.api.resources.ConsumerResource class."""
    def setUp(self):
        super(WhenTestingConsumerResource, self).setUp()

        self.external_project_id = '12345project'
        self.consumer_id = '12345consumer'

        # Force an error on GET calls that pass RBAC, as we are not testing
        #   such flows in this test module.
        self.consumer_repo = mock.MagicMock()
        fail_method = mock.MagicMock(return_value=None,
                                     side_effect=self._generate_get_error())
        self.consumer_repo.get = fail_method

        self.setup_project_repository_mock()
        self.setup_container_consumer_repository_mock(self.consumer_repo)
        self.resource = ConsumerResource(consumer_id=self.consumer_id)

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_get_consumer(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get)

    def test_should_raise_get_consumer(self):
        self._assert_fail_rbac([None, 'bogus'],
                               self._invoke_on_get)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp, self.external_project_id)
