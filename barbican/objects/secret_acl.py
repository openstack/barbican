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
from barbican.model import repositories as repos
from barbican.objects import base
from barbican.objects import fields
from barbican.objects import secret_acl_user


@object_base.VersionedObjectRegistry.register
class SecretACL(base.BarbicanObject, base.BarbicanPersistentObject,
                object_base.VersionedObjectDictCompat):
    fields = {
        'secret_id': fields.StringField(),
        'operation': fields.StringField(),
        'project_access': fields.BooleanField(default=True),
        'acl_users': fields.ListOfObjectsField('SecretACLUser',
                                               default=list()),
        'status': fields.StringField(nullable=True, default=base.States.ACTIVE)
    }

    db_model = models.SecretACL
    db_repo = repos.get_secret_acl_repository()
    synthetic_fields = ['acl_users']

    def _validate_fields(self, change_fields):
        msg = u._("Must supply non-None {0} argument for SecretACL entry.")

        if change_fields.get('secret_id') is None:
            raise exception.MissingArgumentError(msg.format("secret_id"))

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
    def get_by_secret_id(cls, secret_id, session=None):
        secret_acls_db = cls.db_repo.get_by_secret_id(
            secret_id, session=session)
        secret_acls_obj = [cls()._from_db_object(secret_acl_db)
                           for secret_acl_db in secret_acls_db]
        return secret_acls_obj

    @classmethod
    def create_or_replace_from_model(cls, secret, secret_acl,
                                     user_ids=None, session=None):
        """Create or replace Secret and SecretACL

        :param secret: an instance of Secret model
        :param secret_acl: an instance of SecretACL object
        :param user_ids:
        :param session: a session to connect with database

        It is used during converting from model to OVO. It will be removed
        after Secret resource is implemented OVO.
        """
        secret.updated_at = timeutils.utcnow()
        secret_acl.updated_at = timeutils.utcnow()
        secret.save(session=session)
        if secret_acl.id:
            secret_acl.save(session=session)
        else:
            secret_acl.create(session=session)

        cls._create_or_replace_acl_users(secret_acl=secret_acl,
                                         user_ids=user_ids,
                                         session=session)

    @classmethod
    def _create_or_replace_acl_users(cls, secret_acl, user_ids, session=None):
        """Create or replace acl_user

        :param secret_acl: an instance of OVO
        :param user_ids: id of users
        :param session: a session to connect with database
        """

        if user_ids is None:
            return

        user_ids = set(user_ids)

        now = timeutils.utcnow()
        secret_acl.updated_at = now

        for acl_user in secret_acl.acl_users:
            if acl_user.user_id in user_ids:  # input user_id already exists
                acl_user.updated_at = now
                acl_user.save(session=session)
                user_ids.remove(acl_user.user_id)
            else:
                acl_user.delete(session=session)

        for user_id in user_ids:
            acl_user = secret_acl_user.SecretACLUser(acl_id=secret_acl.id,
                                                     user_id=user_id)
            acl_user.create(session=session)

        if secret_acl.id:
            secret_acl.save(session=session)
        else:
            secret_acl.create(session=session)

    @classmethod
    def create_or_replace_from(cls, secret, secret_acl, user_ids=None):
        # TODO(namnh):
        # I will update this function after Secret resource is implemented.
        pass

    @classmethod
    def delete_acls_for_secret_model(cls, secret, session=None):
        """Delete acl in Secret

        :param secret: an instance of Secret model
        :param session: a session to connect with database

        Used during converting Model to OVO. It will be removed in the near
        future.
        """
        cls.db_repo.delete_acls_for_secret(secret, session)

    @classmethod
    def delete_acls_for_secret(cls, secret, session=None):
        """Delete acl in a secret.

        :param secret: an instance of Secret OVO
        :param session: a session to connect with database

        This function will be using after Secret resource is implemented OVO.
        """
        session = cls.get_session(session=session)

        for entity in secret.secret_acls:
            entity.delete(session=session)

    @classmethod
    def get_count(cls, secret_id, session=None):
        return cls.db_repo.get_count(secret_id, session=session)
