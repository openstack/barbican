# Copyright (c) 2015 Rackspace, Inc.
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
import os
import uuid

from barbican.api.controllers import acls
from barbican.model import repositories
from barbican.tests import utils


class WhenTestingSecretACLsResource(utils.BarbicanAPIBaseTestCase):

    def test_can_create_new_secret_acls(self):
        """Create secret acls and compare stored values with request data."""
        secret_uuid, _ = create_secret(self.app)

        resp = create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'])
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/secrets/{0}/acl'.format(secret_uuid),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])

    def test_create_new_secret_acls_with_creator_only_true(self):
        """Should allow creating acls for a new secret with creator-only."""
        secret_uuid, _ = create_secret(self.app)

        resp = create_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only=True)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/secrets/{0}/acl'.format(secret_uuid),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        self.assertTrue(acl_map['read']['creator_only'])

    def test_new_secret_acls_with_invalid_creator_only_value_should_fail(self):
        """Should fail if creator-only flag is provided as string value."""
        secret_uuid, _ = create_secret(self.app)

        resp = create_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only="False",
            read_user_ids=['u1', 'u3', 'u4'],
            expect_errors=True)
        self.assertEqual(400, resp.status_int)

        resp = create_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only="None",
            expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_get_secret_acls_with_complete_acl_data(self):
        """Read existing acls for a with complete acl data."""
        secret_id, _ = create_secret(self.app)
        create_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u3'], read_creator_only=True)

        resp = self.app.get(
            '/secrets/{0}/acl'.format(secret_id),
            expect_errors=False)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)

        self.assertIn('read', resp.json)
        self.assertTrue(resp.json['read']['creator-only'])
        self.assertIsNotNone(resp.json['read']['created'])
        self.assertIsNotNone(resp.json['read']['updated'])
        self.assertEqual(set(['u1', 'u3']), set(resp.json['read']['users']))

    def test_get_secret_acls_with_creator_only_data(self):
        """Read existing acls for acl when only creator-only flag is set."""
        secret_id, _ = create_secret(self.app)
        create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=True)

        resp = self.app.get(
            '/secrets/{0}/acl'.format(secret_id),
            expect_errors=False)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)

        self.assertEqual([], resp.json['read']['users'])
        self.assertTrue(resp.json['read']['creator-only'])
        self.assertIsNotNone(resp.json['read']['created'])
        self.assertIsNotNone(resp.json['read']['updated'])

    def test_get_secret_acls_invalid_secret_should_fail(self):
        """Get secret acls should fail for invalid secret id.

        This test applies to all secret ACLs methods as secret entity is
        populated in same manner for get, put, patch, delete methods.
        """
        secret_id, _ = create_secret(self.app)
        create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            read_user_ids=['u1', 'u3', 'u4'])

        resp = self.app.get(
            '/secrets/{0}/acl'.format(uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_get_secret_acls_no_acls_defined_return_default_acl(self):
        """Get secret acls should pass when no acls defined for a secret."""
        secret_id, _ = create_secret(self.app)

        resp = self.app.get(
            '/secrets/{0}/acl'.format(secret_id),
            expect_errors=True)
        self.assertEqual(200, resp.status_int)
        self.assertEqual(acls.DEFAULT_ACL, resp.json)

    def test_get_secret_acls_with_incorrect_uri_should_fail(self):
        """Get secret acls should fail when no acls defined for a secret."""
        secret_id, _ = create_secret(self.app)

        resp = self.app.get(
            '/secrets/{0}/incorrect_acls'.format(secret_id),
            expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_full_update_secret_acls_modify_creator_only_value(self):
        """ACLs full update with user ids where creator-only flag modified."""
        secret_uuid, _ = create_secret(self.app)

        create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'],
            read_creator_only=True)

        # update acls with no user input so  it should delete existing users
        resp = update_acls(
            self.app, 'secrets', secret_uuid, partial_update=False,
            read_creator_only=False)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/secrets/{0}/acl'.format(secret_uuid),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertIsNone(acl_map['read'].to_dict_fields().get('users'))

    def test_full_update_secret_acls_modify_users_only(self):
        """ACLs full update where specific operation acl is modified."""
        secret_uuid, _ = create_secret(self.app)

        create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'], read_creator_only=True)

        resp = update_acls(
            self.app, 'secrets', secret_uuid, partial_update=False,
            read_user_ids=['u1', 'u3', 'u5'])

        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/secrets/{0}/acl'.format(secret_uuid),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertNotIn('u2', acl_map['read'].to_dict_fields()['users'])
        self.assertEqual(set(['u1', 'u3', 'u5']),
                         set(acl_map['read'].to_dict_fields()['users']))

    def test_full_update_secret_acls_with_read_users_only(self):
        """Acls full update where specific operation acl is modified."""
        secret_uuid, _ = create_secret(self.app)

        create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'])

        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        # ACL api does not support 'list' operation so making direct db update
        # in acl operation data to make sure full update removes this existing
        # ACL.
        secret_acl = acl_map['read']
        secret_acl.operation = 'list'
        secret_acl.save()
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        # check 'list' operation is there in db
        self.assertIn('list', acl_map)
        resp = update_acls(
            self.app, 'secrets', secret_uuid, partial_update=False,
            read_user_ids=['u1', 'u3', 'u5'])

        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/secrets/{0}/acl'.format(secret_uuid),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        # make sure 'list' operation is no longer after full update
        self.assertNotIn('list', acl_map)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertEqual(set(['u1', 'u3', 'u5']),
                         set(acl_map['read'].to_dict_fields()['users']))
        self.assertNotIn('u2', acl_map['read'].to_dict_fields()['users'])

    def test_partial_update_secret_acls_with_read_users_only(self):
        """Acls update where specific operation acl is modified."""
        secret_uuid, _ = create_secret(self.app)

        create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'])

        acl_map = _get_acl_map(secret_uuid, is_secret=True)

        secret_acl = acl_map['read']
        secret_acl.operation = 'list'
        secret_acl.save()
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        # check 'list' operation is there in db
        self.assertIn('list', acl_map)
        resp = update_acls(
            self.app, 'secrets', secret_uuid, partial_update=True,
            read_user_ids=['u1', 'u3', 'u5'])

        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/secrets/{0}/acl'.format(secret_uuid),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        # For partial update, existing other operation ACL is not tocuhed.
        self.assertIn('list', acl_map)
        self.assertEqual(set(['u1', 'u2']),
                         set(acl_map['list'].to_dict_fields()['users']))
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertEqual(set(['u1', 'u3', 'u5']),
                         set(acl_map['read'].to_dict_fields()['users']))

    def test_partial_update_secret_acls_when_no_acls_defined_should_pass(self):
        """Acls partial update pass when no acls are defined for a secret.

        Partial update (PATCH) is applicable even when no explicit ACL has been
        set as by default every secret has implicit acl definition. If PUT
        is used, then new ACL is created instead.
        """
        secret_id, _ = create_secret(self.app)

        resp = update_acls(
            self.app, 'secrets', secret_id, partial_update=True,
            read_user_ids=['u1', 'u3', 'u5'], expect_errors=False)

        self.assertEqual(200, resp.status_int)
        acl_map = _get_acl_map(secret_id, is_secret=True)
        self.assertFalse(acl_map['read']['creator_only'])

    def test_partial_update_secret_acls_modify_creator_only_values(self):
        """Acls partial update where creator-only flag is modified."""
        secret_uuid, _ = create_secret(self.app)

        create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'],
            read_creator_only=True)

        resp = update_acls(
            self.app, 'secrets', secret_uuid, partial_update=True,
            read_creator_only=False)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/secrets/{0}/acl'.format(secret_uuid),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertEqual(set(['u1', 'u2']),
                         set(acl_map['read'].to_dict_fields()['users']))

    def test_delete_secret_acls_with_valid_secret_id(self):
        """Delete existing acls for a given secret."""
        secret_id, _ = create_secret(self.app)
        create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=True)

        resp = self.app.delete(
            '/secrets/{0}/acl'.format(secret_id),
            expect_errors=False)
        content = resp.json
        self.assertIsNone(content)  # make sure there is no response
        self.assertEqual(200, resp.status_int)
        acl_map = _get_acl_map(secret_id, is_secret=True)
        self.assertFalse(acl_map)

    def test_delete_secret_acls_no_acl_defined_should_pass(self):
        """Delete acls should pass when no acls are defined for a secret."""
        secret_id, _ = create_secret(self.app)

        resp = self.app.delete(
            '/secrets/{0}/acl'.format(secret_id),
            expect_errors=False)
        self.assertEqual(200, resp.status_int)

    def test_invoke_secret_acls_head_should_fail(self):
        """Should fail as put request to secret acls URI is not supported."""
        secret_id, _ = create_secret(self.app)
        resp = self.app.head(
            '/secrets/{0}/acl'.format(secret_id),
            expect_errors=True)
        self.assertEqual(405, resp.status_int)


class WhenTestingContainerAclsResource(utils.BarbicanAPIBaseTestCase):

    def test_can_create_new_container_acls(self):
        """Create container acls and compare db values with request data."""
        container_id, _ = create_container(self.app)

        resp = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'])
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/containers/{0}/acl'.format(container_id),
                      resp.json['acl_ref'])

        acl_map = _get_acl_map(container_id, is_secret=False)
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertEqual(set(['u1', 'u2']),
                         set(acl_map['read'].to_dict_fields()['users']))

    def test_create_new_container_acls_with_creator_only_false(self):
        """Should allow creating acls for a new container with creator-only."""
        container_id, _ = create_container(self.app)

        resp = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            read_user_ids=['u1', 'u3', 'u4'])
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/containers/{0}/acl'.format(container_id),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertFalse(acl_map['read']['creator_only'])

    def test_create_new_container_acls_with_creator_only_true(self):
        """Should allow creating acls for a new container with creator-only."""
        container_id, _ = create_container(self.app)

        resp = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=True,
            read_user_ids=['u1', 'u3', 'u4'])
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/containers/{0}/acl'.format(container_id),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertTrue(acl_map['read']['creator_only'])

    def test_container_acls_with_invalid_creator_only_value_should_fail(self):
        """Should fail if creator-only flag is provided as string value."""
        container_id, _ = create_container(self.app)

        resp = create_acls(
            self.app, 'containers', container_id,
            read_creator_only="False",
            read_user_ids=['u1', 'u3', 'u4'],
            expect_errors=True)
        self.assertEqual(400, resp.status_int)

        resp = create_acls(
            self.app, 'containers', container_id,
            read_creator_only="None",
            expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_get_container_acls_with_complete_acl_data(self):
        """Read existing acls for a with complete acl data."""
        container_id, _ = create_container(self.app)
        create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u3'], read_creator_only=True)

        resp = self.app.get(
            '/containers/{0}/acl'.format(container_id),
            expect_errors=False)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)

        self.assertIn('read', resp.json)
        self.assertTrue(resp.json['read']['creator-only'])
        self.assertIsNotNone(resp.json['read']['created'])
        self.assertIsNotNone(resp.json['read']['updated'])
        self.assertEqual(set(['u1', 'u3']), set(resp.json['read']['users']))

    def test_get_container_acls_with_creator_only_data(self):
        """Read existing acls for acl when only creator-only flag is set."""
        container_id, _ = create_container(self.app)
        create_acls(
            self.app, 'containers', container_id,
            read_creator_only=True)

        resp = self.app.get(
            '/containers/{0}/acl'.format(container_id),
            expect_errors=False)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)

        self.assertEqual([], resp.json['read']['users'])
        self.assertTrue(resp.json['read']['creator-only'])
        self.assertIsNotNone(resp.json['read']['created'])
        self.assertIsNotNone(resp.json['read']['updated'])

    def test_get_container_acls_invalid_container_id_should_fail(self):
        """Get container acls should fail for invalid secret id.

        This test applies to all container ACLs methods as secret entity is
        populated in same manner for get, put, patch, delete methods.
        """
        container_id, _ = create_container(self.app)
        create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False)

        resp = self.app.get(
            '/containers/{0}/acl'.format(uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_get_container_acls_invalid_non_uuid_secret_should_fail(self):
        """Get container acls should fail for invalid (non-uuid) id."""
        container_id, _ = create_container(self.app)
        create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False)

        resp = self.app.get(
            '/containers/{0}/acl'.format('my_container_id'),
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_get_container_acls_no_acls_defined_return_default_acl(self):
        """Get container acls should pass when no acls defined for a secret."""
        container_id, _ = create_container(self.app)

        resp = self.app.get(
            '/containers/{0}/acl'.format(container_id),
            expect_errors=True)
        self.assertEqual(200, resp.status_int)
        self.assertEqual(acls.DEFAULT_ACL, resp.json)

    def test_full_update_container_acls_modify_all_acls(self):
        """Acls update where only user ids list is modified."""
        container_id, _ = create_container(self.app)

        create_acls(
            self.app, 'containers', container_id, read_creator_only=True,
            read_user_ids=['u1', 'u2'])

        resp = update_acls(
            self.app, 'containers', container_id, partial_update=False,
            read_user_ids=['u1', 'u2', 'u5'])

        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/containers/{0}/acl'.format(container_id),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertIn('u5', acl_map['read'].to_dict_fields()['users'])

    def test_full_update_container_acls_modify_creator_only_values(self):
        """Acls update where user ids and creator-only flag is modified."""
        container_id, _ = create_container(self.app)

        create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'])

        resp = update_acls(
            self.app, 'containers', container_id, partial_update=False,
            read_creator_only=True)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/containers/{0}/acl'.format(container_id),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertTrue(acl_map['read']['creator_only'])
        self.assertIsNone(acl_map['read'].to_dict_fields().get('users'))

    def test_full_update_container_acls_with_read_users_only(self):
        """Acls full update where specific operation acl is modified."""
        container_id, _ = create_container(self.app)

        create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'])

        acl_map = _get_acl_map(container_id, is_secret=False)
        # ACL api does not support 'list' operation so making direct db update
        # in acl operation data to make sure full update removes this existing
        # ACL.
        container_acl = acl_map['read']
        container_acl.operation = 'list'
        container_acl.save()
        acl_map = _get_acl_map(container_id, is_secret=False)
        # check 'list' operation is there in db
        self.assertIn('list', acl_map)
        resp = update_acls(
            self.app, 'containers', container_id, partial_update=False,
            read_user_ids=['u1', 'u3', 'u5'])

        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/containers/{0}/acl'.format(container_id),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        # make sure 'list' operation is no longer after full update
        self.assertNotIn('list', acl_map)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertEqual(set(['u1', 'u3', 'u5']),
                         set(acl_map['read'].to_dict_fields()['users']))
        self.assertNotIn('u2', acl_map['read'].to_dict_fields()['users'])

    def test_partial_update_container_acls_with_read_users_only(self):
        """Acls update where specific operation acl is modified."""
        container_id, _ = create_container(self.app)

        create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'])

        acl_map = _get_acl_map(container_id, is_secret=False)

        secret_acl = acl_map['read']
        secret_acl.operation = 'list'
        secret_acl.save()
        acl_map = _get_acl_map(container_id, is_secret=False)
        # check 'list' operation is there in db
        self.assertIn('list', acl_map)
        resp = update_acls(
            self.app, 'containers', container_id, partial_update=True,
            read_user_ids=['u1', 'u3', 'u5'])

        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/containers/{0}/acl'.format(container_id),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        # For partial update, existing other operation ACL is not tocuhed.
        self.assertIn('list', acl_map)
        self.assertEqual(set(['u1', 'u2']),
                         set(acl_map['list'].to_dict_fields()['users']))
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertEqual(set(['u1', 'u3', 'u5']),
                         set(acl_map['read'].to_dict_fields()['users']))

    def test_partial_update_container_acls_when_no_acls_defined(self):
        """Acls partial update pass when no acls are defined for container.

        Partial update (PATCH) is applicable even when no explicit ACL has been
        set as by default every container has implicit acl definition. If PUT
        is used, then new ACL is created instead.
        """
        container_id, _ = create_container(self.app)

        resp = update_acls(
            self.app, 'containers', container_id, partial_update=True,
            read_user_ids=['u1', 'u3', 'u5'], expect_errors=False)

        self.assertEqual(200, resp.status_int)
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertFalse(acl_map['read']['creator_only'])

    def test_partial_update_container_acls_modify_creator_only_values(self):
        """Acls partial update where creator-only flag is modified."""
        container_id, _ = create_container(self.app)

        create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            read_creator_only=True)

        resp = update_acls(
            self.app, 'containers', container_id, partial_update=True,
            read_creator_only=False)
        self.assertEqual(200, resp.status_int)
        self.assertIsNotNone(resp.json)
        self.assertIn('/containers/{0}/acl'.format(container_id),
                      resp.json['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertEqual(set(['u1', 'u2']),
                         set(acl_map['read'].to_dict_fields()['users']))

    def test_delete_container_acls_with_valid_container_id(self):
        """Delete existing acls for a given container."""
        container_id, _ = create_container(self.app)
        create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False)

        resp = self.app.delete(
            '/containers/{0}/acl'.format(container_id),
            expect_errors=False)
        content = resp.json
        self.assertIsNone(content)  # make sure there is no response
        self.assertEqual(200, resp.status_int)
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertFalse(acl_map)

    def test_delete_container_acls_no_acl_defined_should_pass(self):
        """Delete acls should pass when no acls are defined for a container."""
        container_id, _ = create_container(self.app)
        resp = self.app.delete(
            '/containers/{0}/acl'.format(container_id),
            expect_errors=False)
        self.assertEqual(200, resp.status_int)

    def test_invoke_container_acls_head_should_fail(self):
        """PUT request to container acls URI is not supported."""
        container_id, _ = create_container(self.app)
        resp = self.app.head(
            '/containers/{0}/acl/'.format(container_id),
            expect_errors=True)
        self.assertEqual(405, resp.status_int)


# ----------------------- Helper Functions ---------------------------
def create_secret(app, name=None, algorithm=None, bit_length=None, mode=None,
                  expiration=None, payload=b'not-encrypted',
                  content_type='text/plain',
                  content_encoding=None, transport_key_id=None,
                  transport_key_needed=None, expect_errors=False):
    request = {
        'name': name,
        'algorithm': algorithm,
        'bit_length': bit_length,
        'mode': mode,
        'expiration': expiration,
        'payload': payload,
        'payload_content_type': content_type,
        'payload_content_encoding': content_encoding,
        'transport_key_id': transport_key_id,
        'transport_key_needed': transport_key_needed
    }
    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    resp = app.post_json(
        '/secrets/',
        cleaned_request,
        expect_errors=expect_errors
    )
    created_uuid = None
    if resp.status_int == 201:
        secret_ref = resp.json.get('secret_ref', '')
        _, created_uuid = os.path.split(secret_ref)

    return created_uuid, resp


def create_container(app):
    _, resp = create_secret(app)
    secret_ref = resp.json['secret_ref']
    request = {
        "name": "container name",
        "type": "generic",
        "secret_refs": [
            {
                "name": "any_key",
                "secret_ref": secret_ref
            }
        ]
    }
    resp = app.post_json(
        '/containers/',
        request,
        expect_errors=False
    )
    created_uuid = None
    if resp.status_int == 201:
        container_ref = resp.json.get('container_ref', '')
        _, created_uuid = os.path.split(container_ref)

    return created_uuid, resp


def create_acls(app, entity_type, entity_id, read_user_ids=None,
                read_creator_only=None,
                expect_errors=False):
    return manage_acls(app, entity_type, entity_id,
                       read_user_ids=read_user_ids,
                       read_creator_only=read_creator_only,
                       is_update=False, partial_update=False,
                       expect_errors=expect_errors)


def update_acls(app, entity_type, entity_id, read_user_ids=None,
                read_creator_only=None, partial_update=False,
                expect_errors=False):
    return manage_acls(app, entity_type, entity_id,
                       read_user_ids=read_user_ids,
                       read_creator_only=read_creator_only,
                       is_update=True, partial_update=partial_update,
                       expect_errors=expect_errors)


def manage_acls(app, entity_type, entity_id, read_user_ids=None,
                read_creator_only=None, is_update=False,
                partial_update=None, expect_errors=False):
    request = {}

    _append_acl_to_request(request, 'read', read_user_ids,
                           read_creator_only)

    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    if is_update and partial_update:  # patch for partial update
        resp = app.patch_json(
            '/{0}/{1}/acl'.format(entity_type, entity_id),
            cleaned_request,
            expect_errors=expect_errors)
    else:  # put (for create or complete update)
        resp = app.put_json(
            '/{0}/{1}/acl'.format(entity_type, entity_id),
            cleaned_request,
            expect_errors=expect_errors)

    return resp


def _append_acl_to_request(req, operation, user_ids=None, creator_only=None):
    op_dict = {}
    if user_ids is not None:
        op_dict['users'] = user_ids
    if creator_only is not None:
        op_dict['creator-only'] = creator_only
    if op_dict:
        req[operation] = op_dict


def _get_acl_map(entity_id, is_secret=True):
    """Provides map of operation: acl_entity for given entity id."""
    if is_secret:
        acl_repo = repositories.get_secret_acl_repository()
        acl_map = {acl.operation: acl for acl in
                   acl_repo.get_by_secret_id(entity_id)}
    else:
        acl_repo = repositories.get_container_acl_repository()
        acl_map = {acl.operation: acl for acl in
                   acl_repo.get_by_container_id(entity_id)}
    return acl_map
