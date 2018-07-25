#    Copyright 2018 Fujitsu.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from oslo_utils import timeutils
from oslo_versionedobjects import base as object_base

from barbican.common import exception
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
from barbican.objects import base
from barbican.objects import container_acl_user
from barbican.objects import fields


@object_base.VersionedObjectRegistry.register
class ContainerACL(base.BarbicanObject, base.BarbicanPersistentObject,
                   object_base.VersionedObjectDictCompat):
    fields = {
        'container_id': fields.StringField(),
        'operation': fields.StringField(),
        'project_access': fields.BooleanField(default=True),
        'acl_users': fields.ListOfObjectsField('ContainerACLUser',
                                               default=list()),
        'status': fields.StringField(nullable=True, default=base.States.ACTIVE)
    }

    db_model = models.ContainerACL
    db_repo = repo.get_container_acl_repository()
    synthetic_fields = ['acl_users']

    def _validate_fields(self, change_fields):

        msg = u._("Must supply non-None {0} argument for ContainerACL entry.")

        if change_fields.get('container_id') is None:
            raise exception.MissingArgumentError(msg.format("container_id"))

        if change_fields.get('operation') is None:
            raise exception.MissingArgumentError(msg.format("operation"))

    def _get_db_entity(self, user_ids=None):
        return self.db_model(user_ids=user_ids, check_exc=False)

    def create(self, session=None, user_ids=None):
        change_fields = self._get_changed_persistent_fields()
        self._validate_fields(change_fields)
        db_entity = self._get_db_entity(user_ids=user_ids)
        db_entity.update(change_fields)
        db_entity = self.db_repo.create_from(db_entity, session=session)
        self._from_db_object(db_entity)

    def delete(self, session):
        entity_id = self.id
        self.db_repo.delete_entity_by_id(
            entity_id=entity_id, external_project_id=None, session=session)

    @classmethod
    def get_by_container_id(cls, container_id, session=None):
        entities_db = cls.db_repo.get_by_container_id(container_id, session)
        entities = [cls()._from_db_object(entity_db)
                    for entity_db in entities_db]
        return entities

    @classmethod
    def create_or_replace_from(cls, container, container_acl,
                               user_ids=None, session=None):
        """Create or replace Secret and SecretACL

        :param container: an instance of Container object
        :param container_acl: an instance of ContainerACL object
        :param user_ids:
        :param session: a session to connect with database
        """
        session = cls.get_session(session)
        container.updated_at = timeutils.utcnow()
        container.save(session=session)
        container_acl.updated_at = timeutils.utcnow()
        if container_acl.id is None:
            container_acl.create(session=session, user_ids=user_ids)
        else:
            container_acl.save(session=session)
        cls._create_or_replace_acl_users(container_acl=container_acl,
                                         user_ids=user_ids, session=session)

    @classmethod
    def create_or_replace_from_model(cls, container, container_acl,
                                     user_ids=None, session=None):
        """Create or replace Secret and SecretACL

        :param container: an instance of Container model
        :param container_acl: an instance of ContainerACL object
        :param user_ids:
        :param session: a session to connect with database

        It is used during converting from model to OVO. It will be removed
        after Container resource is implemented OVO.
        """
        session = cls.get_session(session)
        container.updated_at = timeutils.utcnow()
        container.save(session=session)
        now = timeutils.utcnow()
        container_acl.updated_at = now
        if container_acl.id is None:
            container_acl.create(session=session, user_ids=user_ids)
        else:
            container_acl.save(session=session)
        cls._create_or_replace_acl_users(container_acl=container_acl,
                                         user_ids=user_ids, session=session)

    @classmethod
    def _create_or_replace_acl_users(cls, container_acl, user_ids,
                                     session=None):
        if user_ids is None:
            return

        user_ids = set(user_ids)

        now = timeutils.utcnow()
        session = session or cls.get_session(session)
        container_acl.updated_at = now

        for acl_user in container_acl.acl_users:
            if acl_user.user_id in user_ids:  # input user_id already exists
                acl_user.updated_at = now
                acl_user.save(session=session)
                user_ids.remove(acl_user.user_id)
            else:
                acl_user.delete(session=session)

        for user_id in user_ids:
            acl_user = container_acl_user.ContainerACLUser(
                acl_id=container_acl.id, user_id=user_id)
            acl_user.create(session=session)

        if container_acl.id:
            container_acl.save(session=session)
        else:
            container_acl.create(session=session)

    @classmethod
    def get_count(cls, container_id, session=None):
        query = cls.db_repo.get_count(container_id, session)
        return query

    @classmethod
    def delete_acls_for_container(cls, container, session=None):

        # TODO(namnh)
        # After Container resource is implemented, This function
        # will be updated source code being used.
        session = cls.get_session(session=session)
        for entity in container.container_acls:
            entity.delete(session=session)

    @classmethod
    def delete_acls_for_container_model(cls, container, session=None):
        """Delete ACLs in Container

        Used during converting Model to OVO, it will be removed in near future.
        :param container: instance of Container model
        :param session: connection to database
        """
        cls.db_repo.delete_acls_for_container(container, session)
