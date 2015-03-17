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

from barbican.model import repositories
from barbican.tests import utils

project_repo = repositories.get_project_repository()
secrets_repo = repositories.get_secret_repository()
tkey_repo = repositories.get_transport_key_repository()


class WhenTestingSecretACLsResource(utils.BarbicanAPIBaseTestCase):

    def test_can_create_new_secret_acls(self):
        """Create secret acls and compare stored values with request data."""
        secret_uuid, _ = create_secret(self.app)

        resp, acls = create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])
        self.assertEqual(resp.status_int, 201)
        self.assertIsNotNone(acls)
        self.assertTrue(2, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/secrets/{0}/acls'.format(secret_uuid),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertFalse(acl_map['list']['creator_only'])

    def test_create_new_secret_acls_with_creator_only_values(self):
        """Should allow creating acls for a new secret with creator-only."""
        secret_uuid, _ = create_secret(self.app)

        resp, acls = create_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)
        self.assertEqual(resp.status_int, 201)
        self.assertIsNotNone(acls)
        self.assertTrue(3, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/secrets/{0}/acls'.format(secret_uuid),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertFalse(acl_map['list']['creator_only'])
        self.assertTrue(acl_map['write']['creator_only'])

    def test_new_secret_acls_with_invalid_creator_should_fail(self):
        """Should fail if creator-only flag is provided as string value."""
        secret_uuid, _ = create_secret(self.app)

        resp, acls = create_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only="False",
            read_user_ids=['u1', 'u3', 'u4'],
            expect_errors=True)
        self.assertEqual(resp.status_int, 400)
        self.assertIsNone(acls)

        resp, acls = create_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only="None",
            expect_errors=True)
        self.assertEqual(resp.status_int, 400)
        self.assertIsNone(acls)

    def test_new_secret_acls_with_missing_secret_id_should_fail(self):
        """Should fail if invalid secret id is provided in create request."""
        resp, acls = create_acls(
            self.app, 'secrets', uuid.uuid4().hex,
            read_creator_only="False",
            read_user_ids=['u1', 'u3', 'u4'],
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)
        self.assertIsNone(acls)

    def test_existing_acl_post_request_should_fail(self):
        """Should fail if trying to add acls for secret with existing acls."""
        secret_uuid, _ = create_secret(self.app)
        resp, acls = create_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only=False,
            read_user_ids=['u1', 'u3', 'u4'])
        self.assertEqual(resp.status_int, 201)
        self.assertIsNotNone(acls)

        resp, acls = create_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only=False,
            read_user_ids=['u1', 'u3', 'u4'],
            expect_errors=True)
        self.assertEqual(resp.status_int, 400)
        self.assertIsNone(acls)
        self.assertIn("Existing ACL cannot be updated",
                      resp.json['description'])

    def test_get_secret_acls_with_valid_secret_id(self):
        """Read existing acls for a given valid secret id."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.get(
            '/secrets/{0}/acls'.format(secret_id),
            expect_errors=False)
        acls = resp.json
        self.assertEqual(resp.status_int, 200)
        self.assertTrue(3, len(acls))
        for acl_ref in acls:
            self.assertIn('/secrets/{0}/acls'.format(secret_id),
                          acl_ref['acl_ref'])

    def test_get_secret_acls_invalid_secret_should_fail(self):
        """Get secret acls should fail for invalid secret id."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.get(
            '/secrets/{0}/acls'.format(uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_get_secret_acls_no_acls_defined_should_fail(self):
        """Get secret acls should fail when no acls defined for a secret."""
        secret_id, _ = create_secret(self.app)

        resp = self.app.get(
            '/secrets/{0}/acls'.format(secret_id),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_update_secret_acls_modify_all_acls(self):
        """Acls update where only user ids list is modified."""
        secret_uuid, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        resp, acls = update_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2', 'u5'],
            list_user_ids=['u1', 'u3', 'u4'])

        self.assertEqual(resp.status_int, 200)
        self.assertIsNotNone(acls)
        self.assertTrue(2, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/secrets/{0}/acls'.format(secret_uuid),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertFalse(acl_map['list']['creator_only'])
        self.assertIn('u5', acl_map['read'].to_dict_fields()['users'])

    def test_update_secret_acls_modify_creator_only_values(self):
        """Acls update where user ids and creator-only flag is modified."""
        secret_uuid, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        resp, acls = update_acls(
            self.app, 'secrets', secret_uuid,
            read_creator_only=False,
            list_user_ids=['u1', 'u3'],
            list_creator_only=None,
            write_creator_only=True)
        self.assertEqual(resp.status_int, 200)
        self.assertIsNotNone(acls)
        self.assertTrue(3, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/secrets/{0}/acls'.format(secret_uuid),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertFalse(acl_map['list']['creator_only'])
        self.assertTrue(acl_map['write']['creator_only'])
        self.assertIn('u3', acl_map['list'].to_dict_fields()['users'])
        self.assertNotIn('u4', acl_map['list'].to_dict_fields()['users'])

    def test_update_secret_acls_partial_modify_read_users_only(self):
        """Acls update where specific operation acl is modified."""
        secret_uuid, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4', 'u4'])

        resp, acls = update_acls(
            self.app, 'secrets', secret_uuid,
            read_user_ids=['u1', 'u3', 'u5'])

        self.assertEqual(resp.status_int, 200)
        self.assertIsNotNone(acls)
        self.assertTrue(2, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/secrets/{0}/acls'.format(secret_uuid),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(secret_uuid, is_secret=True)
        list_users = acl_map['list'].to_dict_fields()['users']
        self.assertEqual(set(['u1', 'u3', 'u4']), set(list_users))
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertIn('u3', acl_map['read'].to_dict_fields()['users'])
        self.assertIn('u5', acl_map['read'].to_dict_fields()['users'])
        self.assertNotIn('u2', acl_map['read'].to_dict_fields()['users'])

    def test_update_secret_acls_invalid_secret_should_fail(self):
        """Acls update should fail when invalid secret is provided."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        resp, acls = update_acls(
            self.app, 'secrets', uuid.uuid4().hex,
            read_user_ids=['u1', 'u3', 'u5'], expect_errors=True)

        self.assertEqual(resp.status_int, 404)
        self.assertIsNone(acls)

    def test_update_secret_acls_when_no_acls_defined_should_fail(self):
        """Acls update should fail when acls are defined for a secret."""
        secret_id, _ = create_secret(self.app)

        resp, acls = update_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u3', 'u5'], expect_errors=True)

        self.assertEqual(resp.status_int, 404)
        self.assertIsNone(acls)

    def test_delete_secret_acls_with_valid_secret_id(self):
        """Delete existing acls for a given secret."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.delete(
            '/secrets/{0}/acls'.format(secret_id),
            expect_errors=False)
        content = resp.json
        self.assertIsNone(content)  # make sure there is no response
        self.assertEqual(resp.status_int, 200)
        acl_map = _get_acl_map(secret_id, is_secret=True)
        self.assertFalse(acl_map)

    def test_delete_secret_acls_invalid_secret_should_fail(self):
        """Delete acls should fail when invalid secret id is provided."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.delete(
            '/secrets/{0}/acls'.format(uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_delete_secret_acls_no_acl_defined_should_fail(self):
        """Delete acls should fail when no acls are defined for a secret."""
        secret_id, _ = create_secret(self.app)

        resp = self.app.delete(
            '/secrets/{0}/acls'.format(secret_id),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_invoke_secret_acls_put_should_fail(self):
        """Should fail as put request to secret acls URI is not supported."""
        secret_id, _ = create_secret(self.app)
        resp = self.app.put(
            '/secrets/{0}/acls'.format(secret_id),
            expect_errors=True)
        self.assertEqual(resp.status_int, 405)


class WhenTestingSecretACLResource(utils.BarbicanAPIBaseTestCase):

    def test_get_secret_acl_with_valid_acl_id(self):
        """Read a specific acl by id and compare with request values."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        acl_map = _get_acl_map(secret_id, is_secret=True)
        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id,
                                           acl_map['read']['id']),
            expect_errors=False)
        acl = resp.json
        self.assertEqual(resp.status_int, 200)
        self.assertEqual('read', acl['operation'])
        self.assertFalse(acl['creator-only'])
        self.assertIsNone(acl.get('users'))

        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id,
                                           acl_map['list']['id']),
            expect_errors=False)
        acl = resp.json
        self.assertEqual(resp.status_int, 200)
        self.assertEqual('list', acl['operation'])
        self.assertFalse(acl['creator-only'])
        self.assertEqual(set(['u1', 'u3', 'u4']), set(acl['users']))

    def test_get_secret_acl_invalid_acl_should_fail(self):
        """Get acl request should fail with invalid acl id."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)
        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id,
                                           uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_get_secret_acl_no_acl_defined_should_fail(self):
        """Get acl request should fail with no acls defined for secret."""
        secret_id, _ = create_secret(self.app)
        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id,
                                           uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_update_secret_acl_modify_all(self):
        """Modify existing ACL users by using specific acl id."""
        secret_id, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(secret_id, is_secret=True)
        acl_id = acl_map['read']['id']

        resp = update_acl(
            self.app, 'secrets', secret_id, acl_id,
            read_user_ids=['u1', 'u2', 'u5'], read_creator_only=True)

        self.assertEqual(resp.status_int, 200)
        acl_ref = resp.json
        self.assertIn('/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
                      acl_ref['acl_ref'])

        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertIn('/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
                      acl['acl_ref'])
        # Check creator_only is False when not provided
        self.assertTrue(acl['creator-only'])
        self.assertEqual('read', acl['operation'])
        self.assertEqual(set(['u1', 'u2', 'u5']), set(acl['users']))

    def test_update_secret_acl_with_duplicate_user_ids(self):
        """Modify existing ACL users by using specific acl id."""
        secret_id, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(secret_id, is_secret=True)
        acl_id = acl_map['read']['id']

        resp = update_acl(
            self.app, 'secrets', secret_id, acl_id,
            read_user_ids=['u1', 'u2', 'u1', 'u5'], read_creator_only=True)

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertIn('/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
                      acl['acl_ref'])
        # Check creator_only is False when not provided
        self.assertTrue(acl['creator-only'])
        self.assertEqual('read', acl['operation'])
        self.assertEqual(set(['u1', 'u2', 'u5']), set(acl['users']))

    def test_update_secret_acl_modify_only_related_operation(self):
        """Only modify the acl for matching operation and ignore others."""
        secret_id, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(secret_id, is_secret=True)
        acl_id = acl_map['read']['id']

        # updating read, list operation and adding write operation acl
        # Update should be for 'read' operation ACL only. Others are ignored.
        resp = update_acl(
            self.app, 'secrets', secret_id, acl_id,
            read_user_ids=['u1', 'u2', 'u5'], read_creator_only=True,
            list_user_ids=['u1', 'u3'], list_creator_only=True,
            write_creator_only=True)

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertIn('/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
                      acl['acl_ref'])
        self.assertTrue(acl['creator-only'])  # read operation value is changed
        self.assertEqual('read', acl['operation'])
        self.assertEqual(set(['u1', 'u2', 'u5']), set(acl['users']))

        acl_map = _get_acl_map(secret_id, is_secret=True)

        # list, write operation should not be changed
        self.assertIsNone(acl_map.get('write'))
        self.assertFalse(acl_map['list']['creator_only'])
        list_users = acl_map['list'].to_dict_fields()['users']
        self.assertEqual(set(['u1', 'u3', 'u4']), set(list_users))

    def test_update_secret_acl_modify_different_operation_should_fail(self):
        """Should fail as modifying existing acl's operation is not allowed."""
        secret_id, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(secret_id, is_secret=True)
        acl_id = acl_map['read']['id']

        # updating with list ACL  should fail as originally read operation
        # ACL is associated with acl_id and cannot be modified.
        resp = update_acl(
            self.app, 'secrets', secret_id, acl_id,
            list_user_ids=['u1', 'u3'], list_creator_only=True,
            expect_errors=True)
        self.assertEqual(resp.status_int, 400)

    def test_update_secret_acl_modify_only_users(self):
        """Modifying existing acl's user list and creator-only flag."""
        secret_id, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u2'],
            read_creator_only=True,
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(secret_id, is_secret=True)
        acl_id = acl_map['read']['id']

        # updating read, list operation and adding write operation acl
        # Update should be for 'read' operation ACL only. Others are ignored.
        resp = update_acl(
            self.app, 'secrets', secret_id, acl_id,
            read_user_ids=['u1', 'u2', 'u5'])

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertEqual(set(['u1', 'u2', 'u5']), set(acl['users']))
        self.assertTrue(acl['creator-only'])

        # Now remove existing all users from ACL list
        resp = update_acl(
            self.app, 'secrets', secret_id, acl_id,
            read_user_ids=[])
        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
            expect_errors=False)

        acl = resp.json
        self.assertIsNone(acl.get('users'))
        self.assertTrue(acl['creator-only'])

    def test_update_secret_acl_modify_creator_only(self):
        """Modifying only creator_only flag for existing acl by its id."""
        secret_id, _ = create_secret(self.app)

        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_user_ids=['u1', 'u2'],
            read_creator_only=True,
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(secret_id, is_secret=True)
        acl_id = acl_map['read']['id']

        # updating read, list operation and adding write operation acl
        # Update should be for 'read' operation ACL only. Others are ignored.
        resp = update_acl(
            self.app, 'secrets', secret_id, acl_id,
            read_creator_only=False)

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/secrets/{0}/acls/{1}'.format(secret_id, acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertEqual(set(['u1', 'u2']), set(acl['users']))
        self.assertFalse(acl['creator-only'])

    def test_update_secret_acl_invalid_acl_should_fail(self):
        """Update should fail when invalid acl id is provided."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = update_acl(
            self.app, 'secrets', secret_id, uuid.uuid4().hex,
            read_creator_only=False, expect_errors=True)

        self.assertEqual(resp.status_int, 404)

    def test_update_secret_acl_when_no_acls_defined_should_fail(self):
        """Update should fail when no secret acls are defined."""
        secret_id, _ = create_secret(self.app)
        resp = update_acl(
            self.app, 'secrets', secret_id, uuid.uuid4().hex,
            read_creator_only=False, expect_errors=True)

        self.assertEqual(resp.status_int, 404)

    def test_delete_secret_acl_with_valid_acl_id(self):
        """Delete existing acls for a given secret."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        acl_map = _get_acl_map(secret_id, is_secret=True)

        list_acl_id = acl_map['list'].id

        resp = self.app.delete(
            '/secrets/{0}/acls/{1}'.format(secret_id, list_acl_id),
            expect_errors=False)
        content = resp.json
        self.assertIsNone(content)  # make sure there is no response
        self.assertEqual(resp.status_int, 200)
        acl_map = _get_acl_map(secret_id, is_secret=True)
        self.assertIsNone(acl_map.get('list'))  # list acl should be deleted

    def test_delete_secret_acls_invalid_secret_should_fail(self):
        """Delete acls should fail when invalid secret id is provided."""
        secret_id, _ = create_secret(self.app)
        _, _ = create_acls(
            self.app, 'secrets', secret_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.delete(
            '/secrets/{0}/acls/{1}'.format(secret_id, uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_invoke_secret_acl_put_should_fail(self):
        """PUT for specific acl id is not supported."""
        secret_id, _ = create_secret(self.app)
        resp = self.app.put(
            '/secrets/{0}/acls/{1}'.format(secret_id, uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 405)


class WhenTestingContainerAclsResource(utils.BarbicanAPIBaseTestCase):

    def test_can_create_new_container_acls(self):
        """Create container acls and compare db values with request data."""
        container_id, _ = create_container(self.app)

        resp, acls = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])
        self.assertEqual(resp.status_int, 201)
        self.assertIsNotNone(acls)
        self.assertTrue(2, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/containers/{0}/acls'.format(container_id),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertFalse(acl_map['list']['creator_only'])

    def test_create_new_container_acls_with_creator_only_values(self):
        """Should allow creating acls for a new container with creator-only."""
        container_id, _ = create_container(self.app)

        resp, acls = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)
        self.assertEqual(resp.status_int, 201)
        self.assertIsNotNone(acls)
        self.assertTrue(3, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/containers/{0}/acls'.format(container_id),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertFalse(acl_map['list']['creator_only'])
        self.assertTrue(acl_map['write']['creator_only'])

    def test_new_container_acls_with_invalid_creator_should_fail(self):
        """Should fail if creator-only flag is provided as string value."""
        container_id, _ = create_container(self.app)

        resp, acls = create_acls(
            self.app, 'containers', container_id,
            read_creator_only="False",
            read_user_ids=['u1', 'u3', 'u4'],
            expect_errors=True)
        self.assertEqual(resp.status_int, 400)
        self.assertIsNone(acls)

        resp, acls = create_acls(
            self.app, 'containers', container_id,
            read_creator_only="None",
            expect_errors=True)
        self.assertEqual(resp.status_int, 400)
        self.assertIsNone(acls)

    def test_new_container_acls_with_missing_container_id_should_fail(self):
        """Create acls request should fail for invalid container id."""
        resp, acls = create_acls(
            self.app, 'containers', uuid.uuid4().hex,
            read_creator_only="False",
            read_user_ids=['u1', 'u3', 'u4'],
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)
        self.assertIsNone(acls)

    def test_existing_acl_post_request_should_fail(self):
        """Should fail when adding acls for container with existing acls."""
        container_id, _ = create_container(self.app)
        resp, acls = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            read_user_ids=['u1', 'u3', 'u4'])
        self.assertEqual(resp.status_int, 201)
        self.assertIsNotNone(acls)

        resp, acls = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            read_user_ids=['u1', 'u3', 'u4'],
            expect_errors=True)
        self.assertEqual(resp.status_int, 400)
        self.assertIsNone(acls)
        self.assertIn("Existing ACL cannot be updated",
                      resp.json['description'])

    def test_get_container_acls_with_valid_container_id(self):
        """Read existing acls for a given valid container id."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.get(
            '/containers/{0}/acls'.format(container_id),
            expect_errors=False)
        acls = resp.json
        self.assertEqual(resp.status_int, 200)
        self.assertTrue(3, len(acls))
        for acl_ref in acls:
            self.assertIn('/containers/{0}/acls'.format(container_id),
                          acl_ref['acl_ref'])

    def test_get_container_acls_invalid_container_should_fail(self):
        """Get container acls should fail for invalid secret id."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.get(
            '/containers/{0}/acls'.format(uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_get_container_acls_no_acls_defined_should_fail(self):
        """Get container acls should fail when no acls defined for a secret."""
        container_id, _ = create_container(self.app)

        resp = self.app.get(
            '/containers/{0}/acls'.format(container_id),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_update_container_acls_modify_all_acls(self):
        """Acls update where only user ids list is modified."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        resp, acls = update_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2', 'u5'],
            list_user_ids=['u1', 'u3', 'u4'])

        self.assertEqual(resp.status_int, 200)
        self.assertIsNotNone(acls)
        self.assertTrue(2, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/containers/{0}/acls'.format(container_id),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertFalse(acl_map['list']['creator_only'])
        self.assertIn('u5', acl_map['read'].to_dict_fields()['users'])

    def test_update_container_acls_modify_creator_only_values(self):
        """Acls update where user ids and creator-only flag is modified."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        resp, acls = update_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3'],
            list_creator_only=None,
            write_creator_only=True)
        self.assertEqual(resp.status_int, 200)
        self.assertIsNotNone(acls)
        self.assertTrue(3, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/containers/{0}/acls'.format(container_id),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertFalse(acl_map['list']['creator_only'])
        self.assertTrue(acl_map['write']['creator_only'])
        self.assertIn('u3', acl_map['list'].to_dict_fields()['users'])
        self.assertNotIn('u4', acl_map['list'].to_dict_fields()['users'])

    def test_update_container_acls_partial_modify_read_users_only(self):
        """Acls update where specific operation acl is modified."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        resp, acls = update_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u3', 'u5'])

        self.assertEqual(resp.status_int, 200)
        self.assertIsNotNone(acls)
        self.assertTrue(2, len(acls))
        for acl_ref in resp.json:
            self.assertIn('/containers/{0}/acls'.format(container_id),
                          acl_ref['acl_ref'])
        acl_map = _get_acl_map(container_id, is_secret=False)
        # Check creator_only is False when not provided
        self.assertFalse(acl_map['read']['creator_only'])
        self.assertIn('u3', acl_map['read'].to_dict_fields()['users'])
        self.assertIn('u5', acl_map['read'].to_dict_fields()['users'])
        self.assertNotIn('u2', acl_map['read'].to_dict_fields()['users'])

    def test_update_container_acls_invalid_secret_should_fail(self):
        """Acls update should fail when invalid container is provided."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        resp, acls = update_acls(
            self.app, 'containers', uuid.uuid4().hex,
            read_user_ids=['u1', 'u3', 'u5'], expect_errors=True)

        self.assertEqual(resp.status_int, 404)
        self.assertIsNone(acls)

    def test_update_container_acls_when_no_acls_defined_should_fail(self):
        """Acls update should fail when acls are defined for a container."""
        container_id, _ = create_container(self.app)

        resp, acls = update_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u3', 'u5'], expect_errors=True)

        self.assertEqual(resp.status_int, 404)
        self.assertIsNone(acls)

    def test_delete_container_acls_with_valid_container_id(self):
        """Delete existing acls for a given container."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.delete(
            '/containers/{0}/acls'.format(container_id),
            expect_errors=False)
        content = resp.json
        self.assertIsNone(content)  # make sure there is no response
        self.assertEqual(resp.status_int, 200)
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertFalse(acl_map)

    def test_delete_container_acls_invalid_container_should_fail(self):
        """Delete acls should fail when invalid container id is provided."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.delete(
            '/containers/{0}/acls'.format(uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_delete_container_acls_no_acl_defined_should_fail(self):
        """Delete acls should fail when no acls are defined for a container."""
        container_id, _ = create_container(self.app)
        resp = self.app.delete(
            '/containers/{0}/acls'.format(container_id),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_invoke_container_acls_put_should_fail(self):
        """PUT request to container acls URI is not supported."""
        container_id, _ = create_container(self.app)
        resp = self.app.put(
            '/containers/{0}/acls'.format(container_id),
            expect_errors=True)
        self.assertEqual(resp.status_int, 405)


class WhenTestingContainerAclResource(utils.BarbicanAPIBaseTestCase):

    def test_get_container_acl_with_valid_acl_id(self):
        """Read a specific acl by id and compare with request values."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        acl_map = _get_acl_map(container_id, is_secret=False)
        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              acl_map['read']['id']),
            expect_errors=False)
        acl = resp.json
        self.assertEqual(resp.status_int, 200)
        self.assertEqual('read', acl['operation'])
        self.assertFalse(acl['creator-only'])
        self.assertIsNone(acl.get('users'))

        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              acl_map['list']['id']),
            expect_errors=False)
        acl = resp.json
        self.assertEqual(resp.status_int, 200)
        self.assertEqual('list', acl['operation'])
        self.assertFalse(acl['creator-only'])
        self.assertEqual(set(['u1', 'u3', 'u4']), set(acl['users']))

    def test_get_container_acl_invalid_acl_should_fail(self):
        """Get acl request should fail with invalid acl id."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)
        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_get_container_acl_no_acl_defined_should_fail(self):
        """Get acl request should fail with no acls defined for container."""
        container_id, _ = create_container(self.app)
        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_update_container_acl_modify_all(self):
        """Modify existing ACL users by using specific acl id."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(container_id, is_secret=False)
        acl_id = acl_map['read']['id']

        resp = update_acl(
            self.app, 'containers', container_id, acl_id,
            read_user_ids=['u1', 'u2', 'u5'], read_creator_only=True)

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertIn('/containers/{0}/acls/{1}'.format(container_id, acl_id),
                      acl['acl_ref'])
        # Check creator_only is False when not provided
        self.assertTrue(acl['creator-only'])
        self.assertEqual('read', acl['operation'])
        self.assertEqual(set(['u1', 'u2', 'u5']), set(acl['users']))

    def test_update_container_acl_with_duplicate_user_ids(self):
        """Modify existing ACL users by using specific acl id."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(container_id, is_secret=False)
        acl_id = acl_map['read']['id']

        resp = update_acl(
            self.app, 'containers', container_id, acl_id,
            read_user_ids=['u1', 'u2', 'u1', 'u5'], read_creator_only=True)

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertIn('/containers/{0}/acls/{1}'.format(container_id, acl_id),
                      acl['acl_ref'])
        # Check creator_only is False when not provided
        self.assertTrue(acl['creator-only'])
        self.assertEqual('read', acl['operation'])
        self.assertEqual(set(['u1', 'u2', 'u5']), set(acl['users']))

    def test_update_container_acl_modify_only_related_operation(self):
        """Only modify the acl for matching operation and ignore others."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(container_id, is_secret=False)
        acl_id = acl_map['read']['id']

        # updating read, list operation and adding write operation acl
        # Update should be for 'read' operation ACL only. Others are ignored.
        resp = update_acl(
            self.app, 'containers', container_id, acl_id,
            read_user_ids=['u1', 'u2', 'u5'], read_creator_only=True,
            list_user_ids=['u1', 'u3'], list_creator_only=True,
            write_creator_only=True)

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertIn('/containers/{0}/acls/{1}'.format(container_id, acl_id),
                      acl['acl_ref'])
        self.assertTrue(acl['creator-only'])  # read operation value is changed
        self.assertEqual('read', acl['operation'])
        self.assertEqual(set(['u1', 'u2', 'u5']), set(acl['users']))

        acl_map = _get_acl_map(container_id, is_secret=False)

        # list, write operation should not be changed
        self.assertIsNone(acl_map.get('write'))
        self.assertFalse(acl_map['list']['creator_only'])
        list_users = acl_map['list'].to_dict_fields()['users']
        self.assertEqual(set(['u1', 'u3', 'u4']), set(list_users))

    def test_update_container_acl_modify_different_operation_should_fail(self):
        """Should fail as modifying existing acl's operation is not allowed."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(container_id, is_secret=False)
        acl_id = acl_map['read']['id']

        # updating with list ACL  should fail as originally read operation
        # ACL is associated with acl_id and cannot be modified.
        resp = update_acl(
            self.app, 'containers', container_id, acl_id,
            list_user_ids=['u1', 'u3'], list_creator_only=True,
            expect_errors=True)
        self.assertEqual(resp.status_int, 400)

    def test_update_container_acl_modify_only_users(self):
        """Modifying existing acl's user list and creator-only flag."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            read_creator_only=True,
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(container_id, is_secret=False)
        acl_id = acl_map['read']['id']

        # updating read, list operation and adding write operation acl
        # Update should be for 'read' operation ACL only. Others are ignored.
        resp = update_acl(
            self.app, 'containers', container_id, acl_id,
            read_user_ids=['u1', 'u2', 'u5'])

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertEqual(set(['u1', 'u2', 'u5']), set(acl['users']))
        self.assertTrue(acl['creator-only'])

        # Now remove existing all users from ACL list
        resp = update_acl(
            self.app, 'containers', container_id, acl_id,
            read_user_ids=[])
        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNone(acl.get('users'))
        self.assertTrue(acl['creator-only'])

    def test_update_container_acl_modify_creator_only(self):
        """Modifying only creator_only flag for existing acl by its id."""
        container_id, _ = create_container(self.app)

        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_user_ids=['u1', 'u2'],
            read_creator_only=True,
            list_user_ids=['u1', 'u3', 'u4'])

        acl_map = _get_acl_map(container_id, is_secret=False)
        acl_id = acl_map['read']['id']

        # updating read, list operation and adding write operation acl
        # Update should be for 'read' operation ACL only. Others are ignored.
        resp = update_acl(
            self.app, 'containers', container_id, acl_id,
            read_creator_only=False)

        self.assertEqual(resp.status_int, 200)

        resp = self.app.get(
            '/containers/{0}/acls/{1}'.format(container_id,
                                              acl_id),
            expect_errors=False)
        acl = resp.json
        self.assertIsNotNone(acl)
        self.assertEqual(set(['u1', 'u2']), set(acl['users']))
        self.assertFalse(acl['creator-only'])

    def test_update_container_acl_invalid_acl_should_fail(self):
        """Update should fail when invalid acl id is provided."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = update_acl(
            self.app, 'containers', container_id, uuid.uuid4().hex,
            read_creator_only=False, expect_errors=True)

        self.assertEqual(resp.status_int, 404)

    def test_update_container_acl_when_no_acls_defined_should_fail(self):
        """Update should fail when no container acls are defined."""
        container_id, _ = create_container(self.app)
        resp = update_acl(
            self.app, 'containers', container_id, uuid.uuid4().hex,
            read_creator_only=False, expect_errors=True)

        self.assertEqual(resp.status_int, 404)

    def test_delete_secret_acl_with_valid_acl_id(self):
        """Delete existing acls for a given container."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        acl_map = _get_acl_map(container_id, is_secret=False)

        list_acl_id = acl_map['list'].id

        resp = self.app.delete(
            '/containers/{0}/acls/{1}'.format(container_id, list_acl_id),
            expect_errors=False)
        content = resp.json
        self.assertIsNone(content)  # make sure there is no response
        self.assertEqual(resp.status_int, 200)
        acl_map = _get_acl_map(container_id, is_secret=False)
        self.assertIsNone(acl_map.get('list'))  # list acl should be deleted

    def test_delete_secret_acls_invalid_secret_should_fail(self):
        """Delete acls should fail when invalid secret id is provided."""
        container_id, _ = create_container(self.app)
        _, _ = create_acls(
            self.app, 'containers', container_id,
            read_creator_only=False,
            list_user_ids=['u1', 'u3', 'u4'],
            list_creator_only=None,
            write_creator_only=True)

        resp = self.app.delete(
            '/containers/{0}/acls/{1}'.format(container_id, uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 404)

    def test_invoke_container_acl_put_should_fail(self):
        """PUT for specific acl id is not supported."""
        container_id, _ = create_container(self.app)
        resp = self.app.put(
            '/containers/{0}/acls/{1}'.format(container_id, uuid.uuid4().hex),
            expect_errors=True)
        self.assertEqual(resp.status_int, 405)


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
                write_user_ids=None, list_user_ids=None,
                read_creator_only=None, write_creator_only=None,
                list_creator_only=None,
                expect_errors=False):
    return manage_acls(app, entity_type, entity_id,
                       read_user_ids=read_user_ids,
                       write_user_ids=write_user_ids,
                       list_user_ids=list_user_ids,
                       read_creator_only=read_creator_only,
                       write_creator_only=write_creator_only,
                       list_creator_only=list_creator_only, is_update=False,
                       expect_errors=expect_errors)


def update_acls(app, entity_type, entity_id, read_user_ids=None,
                write_user_ids=None, list_user_ids=None,
                read_creator_only=None, write_creator_only=None,
                list_creator_only=None,
                expect_errors=False):
    return manage_acls(app, entity_type, entity_id,
                       read_user_ids=read_user_ids,
                       write_user_ids=write_user_ids,
                       list_user_ids=list_user_ids,
                       read_creator_only=read_creator_only,
                       write_creator_only=write_creator_only,
                       list_creator_only=list_creator_only, is_update=True,
                       expect_errors=expect_errors)


def manage_acls(app, entity_type, entity_id, read_user_ids=None,
                write_user_ids=None, list_user_ids=None,
                read_creator_only=None, write_creator_only=None,
                list_creator_only=None, is_update=False,
                expect_errors=False):
    request = {}

    _append_acl_to_request(request, 'read', read_user_ids,
                           read_creator_only)
    _append_acl_to_request(request, 'write', write_user_ids,
                           write_creator_only)
    _append_acl_to_request(request, 'list', list_user_ids,
                           list_creator_only)

    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    if is_update:
        resp = app.patch_json(
            '/{0}/{1}/acls'.format(entity_type, entity_id),
            cleaned_request,
            expect_errors=expect_errors)
    else:
        resp = app.post_json(
            '/{0}/{1}/acls'.format(entity_type, entity_id),
            cleaned_request,
            expect_errors=expect_errors)

    acl_ids = None
    if resp.status_int in (201, 200):
        acl_ids = []
        for acl in resp.json:
            acl_ids.append(_get_entity_id(acl))

    return (resp, acl_ids)


def update_acl(app, entity_type, entity_id, acl_id, read_user_ids=None,
               write_user_ids=None, list_user_ids=None,
               read_creator_only=None, write_creator_only=None,
               list_creator_only=None, expect_errors=False):
    request = {}

    _append_acl_to_request(request, 'read', read_user_ids,
                           read_creator_only)
    _append_acl_to_request(request, 'write', write_user_ids,
                           write_creator_only)
    _append_acl_to_request(request, 'list', list_user_ids,
                           list_creator_only)

    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    resp = app.patch_json(
        '/{0}/{1}/acls/{2}'.format(entity_type, entity_id, acl_id),
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


def _get_entity_id(acl):
    return os.path.split(acl.get('acl_ref', ''))[-1]


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
