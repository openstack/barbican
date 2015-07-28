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
from oslo_policy import policy
from webob import exc

from barbican.api.controllers import consumers
from barbican.api.controllers import containers
from barbican.api.controllers import orders
from barbican.api.controllers import secrets
from barbican.api.controllers import versions
from barbican.common import config
from barbican import context
from barbican.model import models
from barbican.tests import utils


# Point to the policy.json file located in source control.
TEST_VAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            '../../../etc', 'barbican'))

CONF = config.new_config()

ENFORCER = policy.Enforcer(CONF)


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


class VersionsResource(TestableResource):
    controller_cls = versions.VersionsController


class SecretsResource(TestableResource):
    controller_cls = secrets.SecretsController


class SecretResource(TestableResource):
    controller_cls = secrets.SecretController


class OrdersResource(TestableResource):
    controller_cls = orders.OrdersController


class OrderResource(TestableResource):
    controller_cls = orders.OrderController


class ContainerResource(TestableResource):
    controller_cls = containers.ContainerController


class ConsumersResource(TestableResource):
    controller_cls = consumers.ContainerConsumersController


class ConsumerResource(TestableResource):
    controller_cls = consumers.ContainerConsumerController


class BaseTestCase(utils.BaseTestCase, utils.MockModelRepositoryMixin):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        CONF(args=['--config-dir', TEST_VAR_DIR])
        self.policy_enforcer = ENFORCER
        self.policy_enforcer.load_rules(True)
        self.resp = mock.MagicMock()

    def _generate_req(self, roles=None, accept=None, content_type=None,
                      user_id=None, project_id=None):
        """Generate a fake HTTP request with security context added to it."""
        req = mock.MagicMock()
        req.get_param.return_value = None

        kwargs = {
            'user': user_id,
            'project': project_id,
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
                          content_type=None, user_id=None, project_id=None):
        """Assert that RBAC authorization rules passed for the specified roles.

        :param roles: List of roles to check, one at a time
        :param method_under_test: The test method to invoke for each role.
        :param accept Optional Accept header to set on the HTTP request
        :return: None
        """
        for role in roles:
            self.req = self._generate_req(roles=[role] if role else [],
                                          accept=accept,
                                          content_type=content_type,
                                          user_id=user_id,
                                          project_id=project_id)

            # Force an exception early past the RBAC passing.
            type(self.req).body = mock.PropertyMock(side_effect=IOError)
            self.req.body_file = self._generate_stream_for_exit()
            exception = self.assertRaises(exc.HTTPServerError,
                                          method_under_test)
            self._assert_post_rbac_exception(exception, role)

    def _assert_fail_rbac(self, roles, method_under_test, accept=None,
                          content_type=None, user_id=None, project_id=None):
        """Assert that RBAC rules failed for one of the specified roles.

        :param roles: List of roles to check, one at a time
        :param method_under_test: The test method to invoke for each role.
        :param accept Optional Accept header to set on the HTTP request
        :return: None
        """
        for role in roles:
            self.req = self._generate_req(roles=[role] if role else [],
                                          accept=accept,
                                          content_type=content_type,
                                          user_id=user_id,
                                          project_id=project_id)

            exception = self.assertRaises(exc.HTTPForbidden, method_under_test)
            self.assertEqual(403, exception.status_int)


class WhenTestingVersionsResource(BaseTestCase):
    """RBAC tests for the barbican.api.resources.VersionsResource class."""
    def setUp(self):
        super(WhenTestingVersionsResource, self).setUp()

        self.resource = VersionsResource()

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_get_versions(self):
        # Can't use base method that short circuits post-RBAC processing here,
        # as version GET is trivial
        for role in ['admin', 'observer', 'creator', 'audit']:
            self.req = self._generate_req(roles=[role] if role else [])
            self._invoke_on_get()

    def test_should_pass_get_versions_with_bad_roles(self):
        self.req = self._generate_req(roles=[None, 'bunkrolehere'])
        self._invoke_on_get()

    def test_should_pass_get_versions_with_no_roles(self):
        self.req = self._generate_req()
        self._invoke_on_get()

    def test_should_pass_get_versions_multiple_roles(self):
        self.req = self._generate_req(roles=['admin', 'observer', 'creator',
                                             'audit'])
        self._invoke_on_get()

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp)


class WhenTestingSecretsResource(BaseTestCase):
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
        self.resource.on_post(self.req, self.resp)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp)


class WhenTestingSecretResource(BaseTestCase):
    """RBAC tests for SecretController class."""

    def setUp(self):
        super(WhenTestingSecretResource, self).setUp()

        self.external_project_id = '12345project'
        self.secret_id = '12345secret'
        self.user_id = '123456user'
        self.creator_user_id = '123456CreatorUser'

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

        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=True,
                                    user_ids=[self.user_id, 'anyRandomId'])
        self.acl_list = [acl_read]
        secret = mock.MagicMock()
        secret.secret_acls.__iter__.return_value = self.acl_list
        secret.project.external_id = self.external_project_id
        secret.creator_id = self.creator_user_id

        self.resource = SecretResource(secret)

        # self.resource.controller.get_acl_tuple = mock.MagicMock(
        #    return_value=(None, None))

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_decrypt_secret(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_decrypt_secret(self):

        self._assert_fail_rbac([None, 'audit', 'bogus'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype')

    def test_should_pass_decrypt_secret_for_same_project_with_no_acl(self):
        """Token and secret project needs to be same in no ACL defined case."""
        self.acl_list.pop()  # remove read acl from default setup
        self._assert_pass_rbac(['admin', 'observer', 'creator'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_decrypt_secret_with_project_access_disabled(self):
        """Should raise authz error as secret is marked private.

        As secret is private so project users should not be able to access
        the secret. Admin project user can still access it.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=False,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_fail_rbac(['observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_pass_decrypt_secret_for_admin_user_project_access_disabled(self):
        """Should pass authz for admin role user as secret is marked private.

        Even when secret is private, admin user should still have access to
        the secret.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=False,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_pass_rbac(['admin'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_decrypt_secret_for_with_project_access_nolist(self):
        """Should raise authz error as secret is marked private.

        As secret is private so project users should not be able to access
        the secret.  This test passes user_ids as empty list, which is a
        valid and common case. Admin project user can still access it.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=False,
                                    user_ids=[])
        self.acl_list.append(acl_read)
        self._assert_fail_rbac(['observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_pass_decrypt_secret_private_enabled_with_read_acl(self):
        """Should pass authz as user has read acl for private secret.

        Even though secret is private, user with read acl should be able to
        access the secret.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=False,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit',
                                'bogusRole'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id='aclUser1',
                               project_id=self.external_project_id)

    def test_should_pass_decrypt_secret_different_user_valid_read_acl(self):
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=True,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        # token project_id is different from secret's project id but another
        # user (from different project) has read acl for secret so should pass
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit',
                                'bogusRole'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id='aclUser1',
                               project_id='different_project_id')

    def test_should_raise_decrypt_secret_for_different_user_no_read_acl(self):
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id,
                                    operation='write',
                                    project_access=True,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        # token project_id is different from secret's project id but another
        # user (from different project) has read acl for secret so should pass
        self._assert_fail_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id='aclUser1',
                               project_id='different_project_id')

    def test_fail_decrypt_secret_for_creator_user_with_different_project(self):
        """Check for creator user rule for secret decrypt/get call.

        If token's user is creator of secret but its scoped to different
        project, then he/she is not allowed access to secret when project
        is marked private.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id,
                                    operation='write',
                                    project_access=True,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self.resource.controller.secret.creator_id = 'creatorUserX'
        # token user is creator but scoped to project different from secret
        # project so don't allow decrypt secret call to creator of that secret
        self._assert_fail_rbac(['admin', 'observer', 'creator', 'audit',
                                'bogusRole'],
                               self._invoke_on_get,
                               accept='notjsonaccepttype',
                               content_type='application/json',
                               user_id='creatorUserX',
                               project_id='different_project_id')

    def test_should_pass_get_secret(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_pass_get_secret_with_no_context(self):
        """In unauthenticated flow, get secret should work."""
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get_without_context,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_get_secret_for_different_project_no_acl(self):
        """Should raise error when secret and token's project is different."""
        self.acl_list.pop()  # remove read acl from default setup
        # token project_id is different from secret's project id so should fail
        self._assert_fail_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id='different_id')

    def test_should_pass_get_secret_for_same_project_but_different_user(self):
        # user id should not matter as long token and secret's project match
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id='different_user_id',
                               project_id=self.external_project_id)

    def test_should_pass_get_secret_for_same_project_with_no_acl(self):
        self.acl_list.pop()  # remove read acl from default setup
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_get_secret_for_with_project_access_disabled(self):
        """Should raise authz error as secret is marked private.

        As secret is private so project users should not be able to access
        the secret.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=False,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_fail_rbac(['observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_pass_get_secret_for_admin_user_with_project_access_disabled(self):
        """Should pass authz for admin user as secret is marked private.

        Even when secret is private, admin user should have access
        the secret.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=False,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_pass_rbac(['admin'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_pass_get_secret_for_private_enabled_with_read_acl(self):
        """Should pass authz as user has read acl for private secret.

        Even though secret is private, user with read acl should be able to
        access the secret.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=False,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit',
                                'bogusRole'],
                               self._invoke_on_get,
                               user_id='aclUser1',
                               project_id=self.external_project_id)

    def test_should_pass_get_secret_different_user_with_valid_read_acl(self):
        """Should allow when read ACL is defined for a user.

        Secret's own project and token's project is different but read is
        allowed because of valid read ACL.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id, operation='read',
                                    project_access=True,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        # token project_id is different from secret's project id but another
        # user (from different project) has read acl for secret so should pass
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit',
                                'bogusRole'],
                               self._invoke_on_get,
                               user_id='aclUser1',
                               project_id='different_project_id')

    def test_should_raise_get_secret_for_different_user_with_no_read_acl(self):
        """Get secret fails when no read acl is defined.

        With different secret and token's project, read is not allowed without
        a read ACL.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.SecretACL(secret_id=self.secret_id,
                                    operation='write',
                                    project_access=True,
                                    user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        # token project_id is different from secret's project id but another
        # user (from different project) has read acl for secret so should pass
        self._assert_fail_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id='aclUser1',
                               project_id='different_project_id')

    def test_fail_get_secret_for_creator_user_with_different_project(self):
        """Check for creator user rule for secret get call.

        If token's user is creator of secret but its scoped to different
        project, then he/she is not allowed access to secret when project
        is marked private.
        """
        self.acl_list.pop()  # remove read acl from default setup
        self.resource.controller.secret.creator_id = 'creatorUserX'

        self._assert_fail_rbac(['admin', 'observer', 'creator', 'audit',
                                'bogusRole'],
                               self._invoke_on_get,
                               user_id='creatorUserX',
                               project_id='different_project_id')

    def test_should_raise_get_secret(self):
        self._assert_fail_rbac([None, 'bogus'],
                               self._invoke_on_get)

    def test_should_pass_put_secret(self):
        self._assert_pass_rbac(['admin', 'creator'], self._invoke_on_put,
                               content_type="application/octet-stream",
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_put_secret(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'bogus'],
                               self._invoke_on_put,
                               content_type="application/octet-stream")

    def test_should_pass_delete_secret(self):
        self._assert_pass_rbac(['admin'], self._invoke_on_delete,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_delete_secret(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'creator', 'bogus'],
                               self._invoke_on_delete)

    # @mock.patch.object(secrets.SecretController, 'get_acl_tuple',
    #                   return_value=(None, None))
    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp)

    def _invoke_on_get_without_context(self):
        # Adding this to get code coverage around context check lines
        self.req.environ.pop('barbican.context')
        self.resource.on_get(self.req, self.resp,
                             self.external_project_id)

    def _invoke_on_put(self):
        self.resource.on_put(self.req, self.resp)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp)


class WhenTestingContainerResource(BaseTestCase):
    """RBAC tests for ContainerController class.

    Container controller tests are quite similar to SecretController as
    policy logic is same. Just adding them here to make sure logic related to
    acl gathering data works as expected.
    """

    def setUp(self):
        super(WhenTestingContainerResource, self).setUp()

        self.external_project_id = '12345project'
        self.container_id = '12345secret'
        self.user_id = '123456user'
        self.creator_user_id = '123456CreatorUser'

        # Force an error on GET and DELETE calls that pass RBAC,
        #   as we are not testing such flows in this test module.
        self.container_repo = mock.MagicMock()
        fail_method = mock.MagicMock(return_value=None,
                                     side_effect=self._generate_get_error())
        self.container_repo.get = fail_method
        self.container_repo.delete_entity_by_id = fail_method

        acl_read = models.ContainerACL(
            container_id=self.container_id, operation='read',
            project_access=True, user_ids=[self.user_id, 'anyRandomId'])
        self.acl_list = [acl_read]
        container = mock.MagicMock()
        container.to_dict_fields = mock.MagicMock(side_effect=IOError)
        container.id = self.container_id
        container.container_acls.__iter__.return_value = self.acl_list
        container.project.external_id = self.external_project_id
        container.creator_id = self.creator_user_id

        self.container_repo.get_container_by_id.return_value = container

        self.setup_container_repository_mock(self.container_repo)

        self.resource = ContainerResource(container)

    def test_rules_should_be_loaded(self):
        self.assertIsNotNone(self.policy_enforcer.rules)

    def test_should_pass_get_container(self):
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_pass_get_container_with_no_context(self):
        """In unauthenticated flow, get container should work."""
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get_without_context,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_get_container_for_different_project_no_acl(self):
        """Raise error when container and token's project is different."""
        self.acl_list.pop()  # remove read acl from default setup
        # token project_id is different from secret's project id so should fail
        self._assert_fail_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id='different_id')

    def test_should_pass_get_container_for_same_project_but_different_user(
            self):
        """Should pass if token and secret's project match.

        User id should not matter as long token and container's project match.
        """
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id='different_user_id',
                               project_id=self.external_project_id)

    def test_should_pass_get_container_for_same_project_with_no_acl(self):
        self.acl_list.pop()  # remove read acl from default setup
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_get_container_for_with_project_access_disabled(self):
        """Should raise authz error as container is marked private.

        As container is private so project users should not be able to access
        the secret (other than admin user).
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.ContainerACL(
            container_id=self.container_id, operation='read',
            project_access=False, user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_fail_rbac(['observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_pass_get_container_for_admin_user_project_access_disabled(self):
        """Should pass authz for admin user when container is marked private.

        For private container, admin user should still be able to access
        the secret.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.ContainerACL(
            container_id=self.container_id, operation='read',
            project_access=False, user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_pass_rbac(['admin'],
                               self._invoke_on_get,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_pass_get_container_for_private_enabled_with_read_acl(self):
        """Should pass authz as user has read acl for private container.

        Even though container is private, user with read acl should be able to
        access the container.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.ContainerACL(
            container_id=self.container_id, operation='read',
            project_access=False, user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit',
                                'bogusRole'],
                               self._invoke_on_get,
                               user_id='aclUser1',
                               project_id=self.external_project_id)

    def test_should_pass_get_container_different_user_with_valid_read_acl(
            self):
        """Should allow when read ACL is defined for a user.

        Container's own project and token's project is different but read is
        allowed because of valid read ACL. User can read regardless of what is
        token's project as it has necessary ACL.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.ContainerACL(
            container_id=self.container_id, operation='read',
            project_access=True, user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_pass_rbac(['admin', 'observer', 'creator', 'audit',
                                'bogusRole'],
                               self._invoke_on_get,
                               user_id='aclUser1',
                               project_id='different_project_id')

    def test_should_raise_get_container_for_different_user_with_no_read_acl(
            self):
        """Get secret fails when no read acl is defined.

        With different container and token's project, read is not allowed
        without a read ACL.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.ContainerACL(
            container_id=self.container_id, operation='write',
            project_access=True, user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        # token project_id is different from secret's project id but another
        # user (from different project) has read acl for secret so should pass
        self._assert_fail_rbac(['admin', 'observer', 'creator', 'audit'],
                               self._invoke_on_get,
                               user_id='aclUser1',
                               project_id='different_project_id')

    def test_fail_get_container_for_creator_user_different_project(self):
        """Check for creator user rule for container get call.

        If token's user is creator of container but its scoped to different
        project, then he/she is not allowed access to container when project
        is marked private.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.ContainerACL(
            container_id=self.container_id, operation='read',
            project_access=False, user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_fail_rbac(['creator'],
                               self._invoke_on_get,
                               user_id=self.creator_user_id,
                               project_id='differet_project_id')

    def test_pass_get_container_for_creator_user_project_access_disabled(self):
        """Should pass authz for creator user when container is marked private.

        As container is private so user who created the container can still
        access it as long as user has 'creator' role in container project.
        """
        self.acl_list.pop()  # remove read acl from default setup
        acl_read = models.ContainerACL(
            container_id=self.container_id, operation='read',
            project_access=False, user_ids=['anyRandomUserX', 'aclUser1'])
        self.acl_list.append(acl_read)
        self._assert_pass_rbac(['creator'],
                               self._invoke_on_get,
                               user_id=self.creator_user_id,
                               project_id=self.external_project_id)

    def test_should_raise_get_container(self):
        self._assert_fail_rbac([None, 'bogus'],
                               self._invoke_on_get)

    def test_should_pass_delete_container(self):
        self._assert_pass_rbac(['admin'], self._invoke_on_delete,
                               user_id=self.user_id,
                               project_id=self.external_project_id)

    def test_should_raise_delete_container(self):
        self._assert_fail_rbac([None, 'audit', 'observer', 'creator', 'bogus'],
                               self._invoke_on_delete)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp)

    def _invoke_on_get_without_context(self):
        # Adding this to get code coverage around context check lines
        self.req.environ.pop('barbican.context')
        self.resource.on_get(self.req, self.resp)

    def _invoke_on_put(self):
        self.resource.on_put(self.req, self.resp)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp)


class WhenTestingOrdersResource(BaseTestCase):
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
        self.resource.on_post(self.req, self.resp)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp)


class WhenTestingOrderResource(BaseTestCase):
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
        self.resource.on_get(self.req, self.resp)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp)


class WhenTestingConsumersResource(BaseTestCase):
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
        self.resource.on_post(self.req, self.resp)

    def _invoke_on_delete(self):
        self.resource.on_delete(self.req, self.resp)

    def _invoke_on_get(self):
        self.resource.on_get(self.req, self.resp)


class WhenTestingConsumerResource(BaseTestCase):
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
        self.resource.on_get(self.req, self.resp)
