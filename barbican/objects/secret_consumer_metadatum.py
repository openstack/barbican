#    Copyright (c) 2019 Red Hat, inc.
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
from oslo_db import exception as db_exc
from oslo_utils import timeutils
from oslo_versionedobjects import base as object_base

from barbican.common import utils
from barbican.model import models
from barbican.model import repositories as repos
from barbican.objects import base
from barbican.objects import fields

LOG = utils.getLogger(__name__)


@object_base.VersionedObjectRegistry.register
class SecretConsumerMetadatum(base.BarbicanObject,
                              base.BarbicanPersistentObject,
                              object_base.VersionedObjectDictCompat):
    fields = {
        'secret_id': fields.StringField(nullable=False),
        'project_id': fields.StringField(nullable=False, default=None),
        'service': fields.StringField(nullable=True, default=None),
        'resource_type': fields.StringField(nullable=True, default=None),
        'resource_id': fields.StringField(nullable=True, default=None),
    }

    db_model = models.SecretConsumerMetadatum
    db_repo = repos.get_secret_consumer_repository()

    @classmethod
    def get_by_secret_id(cls, secret_id, offset_arg=None, limit_arg=None,
                         suppress_exception=False, session=None):
        entities_db, offset, limit, total = \
            cls.db_repo.get_by_secret_id(
                secret_id, offset_arg, limit_arg,
                suppress_exception, session)
        entities = [cls()._from_db_object(entity_db) for entity_db in
                    entities_db]
        return entities, offset, limit, total

    @classmethod
    def get_by_resource_id(cls, resource_id, offset_arg=None, limit_arg=None,
                           suppress_exception=False, session=None):
        entities_db, offset, limit, total = \
            cls.db_repo.get_by_resource_id(
                resource_id, offset_arg, limit_arg,
                suppress_exception, session)
        entities = [cls()._from_db_object(entity_db) for entity_db in
                    entities_db]
        return entities, offset, limit, total

    @classmethod
    def get_by_values(cls, secret_id, resource_id, suppress_exception=False,
                      show_deleted=False, session=None):
        consumer_db = cls.db_repo.get_by_values(secret_id,
                                                resource_id,
                                                suppress_exception,
                                                show_deleted,
                                                session)
        return cls()._from_db_object(consumer_db)

    @classmethod
    def create_or_update_from_model(cls, new_consumer,
                                    secret, session=None):
        """Create or update secret

        :param new_consumer: a instance of SecretConsumerMetadatum model
        :param secret: a instance of Secret OVO
        :param session: a session to connect with database
        :return: None

        It is used during converting from model to OVO. It will be removed
        after Secret resource is implemented OVO.
        """
        session = cls.get_session(session=session)
        try:
            secret.updated_at = timeutils.utcnow()
            secret.save(session=session)
            new_consumer.save(session=session)
        except db_exc.DBDuplicateEntry:
            session.rollback()  # We know consumer already exists.

            # This operation is idempotent, so log this and move on
            LOG.debug(
                "Consumer with resource_id %s already exists for secret %s...",
                new_consumer.resource_id, new_consumer.secret_id
            )
            # Get the existing entry and reuse it by clearing the deleted flags
            existing_consumer = cls.get_by_values(
                new_consumer.secret_id,
                new_consumer.resource_id,
                show_deleted=True
            )
            existing_consumer.deleted = False
            existing_consumer.deleted_at = None
            # We are not concerned about timing here -- set only, no reads
            existing_consumer.save(session=session)

    @classmethod
    def create_or_update_from(cls, new_consumer, secret, session=None):
        """Create or update secret

        :param new_consumer: a instance of SecretConsumerMetadatum OVO
        :param secret: a instance of Secret OVO
        :param session: a session to connect with database
        :return: None
        """
        session = cls.get_session(session=session)
        try:
            secret.updated_at = timeutils.utcnow()
            secret.consumers.append(new_consumer)
            secret.save(session=session)
        except db_exc.DBDuplicateEntry:
            session.rollback()  # We know consumer already exists.

            # This operation is idempotent, so log this and move on
            LOG.debug(
                "Consumer with resource_id %s already exists for secret %s...",
                new_consumer.resource_id, new_consumer.secret_id
            )
            # Get the existing entry and reuse it by clearing the deleted flags
            existing_consumer = cls.get_by_values(
                new_consumer.secret_id,
                new_consumer.resource_id,
                show_deleted=True
            )
            existing_consumer.deleted = False
            existing_consumer.deleted_at = None
            # We are not concerned about timing here -- set only, no reads
            existing_consumer.save(session=session)
