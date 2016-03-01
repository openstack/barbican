# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


class TestACLMixin(object):

    def _assert_acl_users(self, user_ids, acls, acl_id, check_size=True):
        """Checks that all input users are present in matching acl users data.

        It also checks if number of acl users are same as input users when
        check_size flag is True.
        """
        acls_map = self._map_id_to_acl(acls)
        acl_users = acls_map[acl_id].to_dict_fields()['users']
        if check_size:
            self.assertEqual(len(user_ids), len(acl_users))
        self.assertTrue(all(user_id in user_ids for user_id in acl_users))

    def _map_id_to_acl(self, acls):
        """Provides dictionary of id and acl from acls list."""
        m = {}
        for acl in acls:
            m[acl.id] = acl
        return m


class WhenTestingSecretACLRepository(database_utils.RepositoryTestCase,
                                     TestACLMixin):

    def setUp(self):
        super(WhenTestingSecretACLRepository, self).setUp()
        self.acl_repo = repositories.get_secret_acl_repository()

    def _create_base_secret(self, project_id=None):
        # Setup the secret and needed base relationship
        secret_repo = repositories.get_secret_repository()
        session = secret_repo.get_session()

        if project_id is None:  # don't re-create project if it created earlier
            project = models.Project()
            project.external_id = "keystone_project_id"
            project.save(session=session)
            project_id = project.id

        secret_model = models.Secret()
        secret_model.project_id = project_id
        secret = secret_repo.create_from(secret_model, session=session)

        secret.save(session=session)

        session.commit()
        return secret

    def test_get_by_secret_id(self):
        session = self.acl_repo.get_session()
        secret = self._create_base_secret()

        acls = self.acl_repo.get_by_secret_id(secret.id, session)
        self.assertEqual(0, len(acls))

        acl1 = self.acl_repo.create_from(models.SecretACL(secret.id, 'read',
                                                          True, ['u1', 'u2']),
                                         session)
        acls = self.acl_repo.get_by_secret_id(secret.id, session)

        self.assertEqual(1, len(acls))
        self.assertEqual(acl1.id, acls[0].id)
        self.assertEqual('read', acls[0].operation)
        self._assert_acl_users(['u2', 'u1'], acls, acl1.id)

    def test_get_by_entity_id(self):
        session = self.acl_repo.get_session()
        secret = self._create_base_secret()

        acl1 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'read', True, ['u1', 'u2']), session)
        acl = self.acl_repo.get(acl1.id, session)
        self.assertIsNotNone(acl)
        self.assertEqual(acl1.id, acl.id)
        self.assertEqual('read', acl.operation)
        self._assert_acl_users(['u1', 'u2'], [acl], acl1.id)

        self.acl_repo.delete_entity_by_id(acl1.id, session)
        acl = self.acl_repo.get(acl1.id, session, suppress_exception=True)
        self.assertIsNone(acl)

    def test_should_raise_notfound_exception_get_by_entity_id(self):
        self.assertRaises(exception.NotFound, self.acl_repo.get,
                          "invalid_id", suppress_exception=False)

    def test_create_or_replace_from_for_new_acls(self):
        """Check create_or_replace_from and get count call.

        It creates new acls with users and make sure that same users
        are returned when acls are queries by secret id.
        It uses get count to assert expected number of acls for that secret.
        """
        session = self.acl_repo.get_session()
        secret = self._create_base_secret()
        acl1 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'read'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl1, user_ids=['u1', 'u2'], session=session)

        acl2 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'write', False), session)
        self.acl_repo.create_or_replace_from(
            secret, acl2, user_ids=['u1', 'u2', 'u3'], session=session)

        acl3 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'delete'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl3, user_ids=[], session=session)

        acls = self.acl_repo.get_by_secret_id(secret.id, session)

        self.assertEqual(3, len(acls))

        id_map = self._map_id_to_acl(acls)
        self.assertTrue(id_map[acl1.id].project_access)
        self.assertFalse(id_map[acl2.id].project_access)
        self.assertEqual('read', id_map[acl1.id].operation)
        self.assertEqual('write', id_map[acl2.id].operation)
        self.assertEqual('delete', id_map[acl3.id].operation)
        # order of input users should not matter
        self._assert_acl_users(['u1', 'u2'], acls, acl1.id)
        self._assert_acl_users(['u2', 'u1'], acls, acl1.id)
        self._assert_acl_users(['u2', 'u1', 'u3'], acls, acl2.id)

        count = self.acl_repo.get_count(secret.id, session)
        self.assertEqual(3, count)
        self.assertEqual(count, len(acls))

    def test_create_or_replace_from_with_none_or_blank_users(self):
        session = self.acl_repo.get_session()
        secret = self._create_base_secret()
        acl1 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'read'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl1, user_ids=None, session=session)

        acl2 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'list'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl1, user_ids=[], session=session)

        acls = self.acl_repo.get_by_secret_id(secret.id, session)
        id_map = self._map_id_to_acl(acls)
        self.assertIsNone(id_map[acl1.id].to_dict_fields().get('users'))
        self.assertIsNone(id_map[acl2.id].to_dict_fields().get('users'))

    def test_create_or_replace_from_for_existing_acls(self):
        """Check create_or_replace_from and get count call.

        It modifies existing acls with users and make sure that updated users
        and project_access flag changes are returned when acls are queries by
        secret id. It uses get count to assert expected number of acls for that
        secret.
        """
        session = self.acl_repo.get_session()
        secret = self._create_base_secret()
        acl1 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'read'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl1, user_ids=['u1', 'u2'], session=session)

        acl2 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'write'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl2, user_ids=['u1', 'u2', 'u3'], session=session)

        acl3 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'list'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl3, user_ids=[], session=session)

        acls = self.acl_repo.get_by_secret_id(secret.id, session)

        self.assertEqual(3, len(acls))

        id_map = self._map_id_to_acl(acls)
        # replace users in existing acls
        id_map[acl1.id].project_access = False
        self.acl_repo.create_or_replace_from(
            secret, id_map[acl1.id], user_ids=['u5'], session=session)

        self.acl_repo.create_or_replace_from(
            secret, id_map[acl2.id], user_ids=['u1', 'u2', 'u3', 'u4'],
            session=session)

        self.acl_repo.create_or_replace_from(
            secret, id_map[acl3.id], user_ids=['u1', 'u2', 'u4'],
            session=session)

        session.commit()  # commit the changes made so far
        acls = self.acl_repo.get_by_secret_id(secret.id, session)
        id_map = self._map_id_to_acl(acls)

        self.assertEqual(3, len(acls))
        self.assertFalse(id_map[acl1.id].project_access)
        self.assertTrue(id_map[acl2.id].project_access)
        self.assertTrue(id_map[acl3.id].project_access)
        self._assert_acl_users(['u5'], acls, acl1.id)
        self._assert_acl_users(['u1', 'u2', 'u3', 'u4'], acls, acl2.id)
        self._assert_acl_users(['u1', 'u2', 'u4'], acls, acl3.id)

    def test_get_count(self):
        session = self.acl_repo.get_session()
        secret1 = self._create_base_secret()
        acl1 = self.acl_repo.create_from(models.SecretACL(secret1.id, 'read',
                                                          None, ['u1', 'u2']),
                                         session)
        self.acl_repo.create_or_replace_from(secret1, acl1)

        secret2 = self._create_base_secret(secret1.project.id)
        acl21 = self.acl_repo.create_from(models.SecretACL(secret2.id, 'read',
                                                           None, ['u3', 'u4']),
                                          session)
        self.acl_repo.create_or_replace_from(secret2, acl21)
        acl22 = self.acl_repo.create_from(models.SecretACL(secret2.id, 'write',
                                                           None, ['u5', 'u6']),
                                          session)
        self.acl_repo.create_or_replace_from(secret2, acl22)

        self.assertEqual(1, self.acl_repo.get_count(secret1.id))
        self.assertEqual(2, self.acl_repo.get_count(secret2.id))

    def test_delete_single_acl_and_count(self):

        session = self.acl_repo.get_session()
        secret = self._create_base_secret()
        acl1 = self.acl_repo.create_from(models.SecretACL(secret.id, 'read',
                                                          None, ['u1', 'u2']),
                                         session)
        self.acl_repo.create_or_replace_from(secret, acl1)
        acl2 = self.acl_repo.create_from(
            models.SecretACL(secret.id, 'write'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl2, user_ids=['u1', 'u2', 'u3'])
        acl3 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'list'), session)
        self.acl_repo.create_or_replace_from(secret, acl3,
                                             user_ids=['u1', 'u3'])

        count = self.acl_repo.get_count(secret.id)
        self.assertEqual(3, count)

        self.acl_repo.delete_entity_by_id(acl2.id, None)
        session.commit()
        self.assertEqual(2, len(secret.secret_acls))

        deleted_acl = self.acl_repo.get(acl2.id, suppress_exception=True)
        self.assertIsNone(deleted_acl)

        acls = self.acl_repo.get_by_secret_id(secret.id)
        self.assertEqual(2, len(acls))

        count = self.acl_repo.get_count(secret.id)
        self.assertEqual(2, count)

    def test_delete_acls_for_secret(self):
        session = self.acl_repo.get_session()
        secret = self._create_base_secret()
        acl1 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'read'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl1, user_ids=['u1', 'u2'], session=session)
        acl2 = self.acl_repo.create_from(models.SecretACL(
            secret.id, 'write'), session)
        self.acl_repo.create_or_replace_from(
            secret, acl2, user_ids=['u1', 'u2', 'u3'], session=session)

        self.acl_repo.delete_acls_for_secret(secret)
        acls = self.acl_repo.get_by_secret_id(secret.id)
        self.assertEqual(0, len(acls))


class WhenTestingContainerACLRepository(database_utils.RepositoryTestCase,
                                        TestACLMixin):

    def setUp(self):
        super(WhenTestingContainerACLRepository, self).setUp()
        self.acl_repo = repositories.get_container_acl_repository()

    def _create_base_container(self, project_id=None):
        # Setup the container and needed base relationship
        container_repo = repositories.get_container_repository()
        session = container_repo.get_session()

        if project_id is None:
            project = models.Project()
            project.external_id = "keystone_project_id"
            project.save(session=session)
            project_id = project.id

        container = models.Container()

        container.project_id = project_id
        container.save(session=session)

        session.commit()
        return container

    def test_get_by_container_id(self):
        session = self.acl_repo.get_session()
        container = self._create_base_container()

        acls = self.acl_repo.get_by_container_id(container.id, session)
        self.assertEqual(0, len(acls))

        acl1 = self.acl_repo.create_from(models.ContainerACL(container.id,
                                                             'read', True,
                                                             ['u1', 'u2']),
                                         session)
        acls = self.acl_repo.get_by_container_id(container.id, session)
        self.assertEqual(1, len(acls))
        self.assertEqual(acl1.id, acls[0].id)
        self.assertEqual('read', acls[0].operation)
        self._assert_acl_users(['u1', 'u2'], acls, acl1.id)

    def test_get_by_entity_id(self):
        session = self.acl_repo.get_session()
        container = self._create_base_container()

        acl1 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'read', True, ['u1', 'u2']), session)

        acl = self.acl_repo.get(acl1.id, session)
        self.assertIsNotNone(acl)
        self.assertEqual(acl1.id, acl.id)
        self.assertEqual('read', acl.operation)
        self._assert_acl_users(['u1', 'u2'], [acl], acl1.id)

        self.acl_repo.delete_entity_by_id(acl1.id, session)
        acl = self.acl_repo.get(acl1.id, session, suppress_exception=True)
        self.assertIsNone(acl)

    def test_should_raise_notfound_exception_get_by_entity_id(self):
        self.assertRaises(exception.NotFound, self.acl_repo.get,
                          "invalid_id", suppress_exception=False)

    def test_create_or_replace_from_for_new_acls(self):
        """Check create_or_replace_from and get count call.

        It creates new acls with users and make sure that same users
        are returned when acls are queries by secret id.
        It uses get count to assert expected number of acls for that secret.
        """
        session = self.acl_repo.get_session()
        container = self._create_base_container()
        acl1 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'read'), session)
        self.acl_repo.create_or_replace_from(
            container, acl1, user_ids=['u1', 'u2'], session=session)

        acl2 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'write', False), session)
        self.acl_repo.create_or_replace_from(
            container, acl2, user_ids=['u1', 'u2', 'u3'], session=session)

        acl3 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'list'), session)
        self.acl_repo.create_or_replace_from(
            container, acl3, user_ids=[], session=session)

        acls = self.acl_repo.get_by_container_id(container.id, session)

        self.assertEqual(3, len(acls))

        id_map = self._map_id_to_acl(acls)
        self.assertTrue(id_map[acl1.id].project_access)
        self.assertFalse(id_map[acl2.id].project_access)
        self.assertEqual('read', id_map[acl1.id].operation)
        self.assertEqual('write', id_map[acl2.id].operation)
        self.assertEqual('list', id_map[acl3.id].operation)
        # order of input users should not matter
        self._assert_acl_users(['u1', 'u2'], acls, acl1.id)
        self._assert_acl_users(['u2', 'u1'], acls, acl1.id)
        self._assert_acl_users(['u2', 'u1', 'u3'], acls, acl2.id)

        count = self.acl_repo.get_count(container.id, session)
        self.assertEqual(3, count)
        self.assertEqual(count, len(acls))

    def test_create_or_replace_from_with_none_or_blank_users(self):
        session = self.acl_repo.get_session()
        container = self._create_base_container()
        acl1 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'read'), session)
        self.acl_repo.create_or_replace_from(
            container, acl1, user_ids=None, session=session)

        acl2 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'write'), session)
        self.acl_repo.create_or_replace_from(
            container, acl1, user_ids=[], session=session)

        acls = self.acl_repo.get_by_container_id(container.id, session)
        id_map = self._map_id_to_acl(acls)
        self.assertIsNone(id_map[acl1.id].to_dict_fields().get('users'))
        self.assertIsNone(id_map[acl2.id].to_dict_fields().get('users'))

    def test_create_or_replace_from_for_existing_acls(self):
        """Check create_or_replace_from and get count call.

        It modifies existing acls with users and make sure that updated users
        and project_access flag changes are returned when acls are queries by
        secret id. It uses get count to assert expected number of acls for that
        secret.
        """
        session = self.acl_repo.get_session()
        container = self._create_base_container()
        acl1 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'read'), session)
        self.acl_repo.create_or_replace_from(
            container, acl1, user_ids=['u1', 'u2'], session=session)

        acl2 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'write'), session)
        self.acl_repo.create_or_replace_from(
            container, acl2, user_ids=['u1', 'u2', 'u3'], session=session)

        acl3 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'list'), session)
        self.acl_repo.create_or_replace_from(
            container, acl3, user_ids=[], session=session)

        acls = self.acl_repo.get_by_container_id(container.id, session)

        self.assertEqual(3, len(acls))

        id_map = self._map_id_to_acl(acls)
        # replace users in existing acls
        id_map[acl1.id].project_access = False
        self.acl_repo.create_or_replace_from(
            container, id_map[acl1.id], user_ids=['u5'], session=session)

        self.acl_repo.create_or_replace_from(
            container, id_map[acl2.id], user_ids=['u1', 'u2', 'u3', 'u4'],
            session=session)

        self.acl_repo.create_or_replace_from(
            container, id_map[acl3.id], user_ids=['u1', 'u2', 'u4'],
            session=session)

        session.commit()
        acls = self.acl_repo.get_by_container_id(container.id, session)
        id_map = self._map_id_to_acl(acls)

        self.assertEqual(3, len(acls))
        self.assertFalse(id_map[acl1.id].project_access)
        self.assertTrue(id_map[acl2.id].project_access)
        self.assertTrue(id_map[acl3.id].project_access)
        self._assert_acl_users(['u5'], acls, acl1.id)
        self._assert_acl_users(['u1', 'u2', 'u3', 'u4'], acls, acl2.id)
        self._assert_acl_users(['u1', 'u2', 'u4'], acls, acl3.id)

    def test_get_count(self):
        session = self.acl_repo.get_session()
        container1 = self._create_base_container()
        acl1 = self.acl_repo.create_from(models.ContainerACL(
            container1.id, 'read', None, ['u1', 'u2']), session)
        self.acl_repo.create_or_replace_from(container1, acl1)

        container2 = self._create_base_container(container1.project_id)
        acl21 = self.acl_repo.create_from(models.ContainerACL(
            container2.id, 'read', None, ['u3', 'u4']), session)
        self.acl_repo.create_or_replace_from(container2, acl21)
        acl22 = self.acl_repo.create_from(models.ContainerACL(
            container2.id, 'write', None, ['u5', 'u6']), session)
        self.acl_repo.create_or_replace_from(container2, acl22)

        self.assertEqual(1, self.acl_repo.get_count(container1.id))
        self.assertEqual(2, self.acl_repo.get_count(container2.id))

    def test_delete_single_acl_and_count(self):

        session = self.acl_repo.get_session()
        container = self._create_base_container()
        acl1 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'read'), session)
        self.acl_repo.create_or_replace_from(container, acl1,
                                             user_ids=['u1', 'u2'])
        acl2 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'write'), session)
        self.acl_repo.create_or_replace_from(container, acl2,
                                             user_ids=['u1', 'u2', 'u3'])
        acl3 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'list'), session)
        self.acl_repo.create_or_replace_from(container, acl3,
                                             user_ids=['u1', 'u3'])

        count = self.acl_repo.get_count(container.id)
        self.assertEqual(3, count)

        self.acl_repo.delete_entity_by_id(acl2.id, None)
        session.commit()  # commit the changes made so far
        self.assertEqual(2, len(container.container_acls))

        deleted_acl = self.acl_repo.get(acl2.id, suppress_exception=True)
        self.assertIsNone(deleted_acl)

        acls = self.acl_repo.get_by_container_id(container.id)
        self.assertEqual(2, len(acls))

        count = self.acl_repo.get_count(container.id)
        self.assertEqual(2, count)

    def test_delete_acls_for_secret(self):
        session = self.acl_repo.get_session()
        container = self._create_base_container()
        acl1 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'read'), session)
        self.acl_repo.create_or_replace_from(
            container, acl1, user_ids=['u1', 'u2'], session=session)
        acl2 = self.acl_repo.create_from(models.ContainerACL(
            container.id, 'write'), session)
        self.acl_repo.create_or_replace_from(
            container, acl2, user_ids=['u1', 'u2', 'u3'], session=session)

        self.acl_repo.delete_acls_for_container(container)
        acls = self.acl_repo.get_by_container_id(container.id)
        self.assertEqual(0, len(acls))
