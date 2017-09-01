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
class ContainerConsumerMetadatum(base.BarbicanObject,
                                 base.BarbicanPersistentObject,
                                 object_base.VersionedObjectDictCompat):
    fields = {
        'container_id': fields.StringField(nullable=False),
        'project_id': fields.StringField(nullable=True, default=None),
        'name': fields.StringField(nullable=True, default=None),
        'URL': fields.StringField(nullable=True, default=None),
        'data_hash': fields.StringField(nullable=True, default=None)
    }

    db_model = models.ContainerConsumerMetadatum
    db_repo = repos.get_container_consumer_repository()

    @classmethod
    def get_by_container_id(cls, container_id, offset_arg=None, limit_arg=None,
                            suppress_exception=False, session=None):
        entities_db, offset, limit, total = \
            cls.db_repo.get_by_container_id(
                container_id, offset_arg, limit_arg,
                suppress_exception, session)
        entities = [cls()._from_db_object(entity_db) for entity_db in
                    entities_db]
        return entities, offset, limit, total

    @classmethod
    def get_by_values(cls, container_id, name, URL, suppress_exception=False,
                      show_deleted=False, session=None):
        consumer_db = cls.db_repo.get_by_values(container_id, name,
                                                URL,
                                                suppress_exception,
                                                show_deleted,
                                                session)
        return cls()._from_db_object(consumer_db)

    @classmethod
    def create_or_update_from_model(cls, new_consumer,
                                    container, session=None):
        """Create or update container

        :param new_consumer: a instance of ContainerConsumerMetadatum model
        :param container: a instance of Container OVO
        :param session: a session to connect with database
        :return: None

        It is used during converting from model to OVO. It will be removed
        after Container resource is implemented OVO.
        """
        session = cls.get_session(session=session)
        try:
            container.updated_at = timeutils.utcnow()
            container.save(session=session)
            new_consumer.save(session=session)
        except db_exc.DBDuplicateEntry:
            session.rollback()  # We know consumer already exists.

            # This operation is idempotent, so log this and move on
            LOG.debug("Consumer %s with URL %s already exists for "
                      "container %s, continuing...", new_consumer.name,
                      new_consumer.URL, new_consumer.container_id)
            # Get the existing entry and reuse it by clearing the deleted flags
            existing_consumer = cls.get_by_values(
                new_consumer.container_id, new_consumer.name, new_consumer.URL,
                show_deleted=True)
            existing_consumer.deleted = False
            existing_consumer.deleted_at = None
            # We are not concerned about timing here -- set only, no reads
            existing_consumer.save(session=session)

    @classmethod
    def create_or_update_from(cls, new_consumer, container, session=None):
        """Create or update container

        :param new_consumer: a instance of ContainerConsumerMetadatum OVO
        :param container: a instance of Container OVO
        :param session: a session to connect with database
        :return: None
        """
        session = cls.get_session(session=session)
        try:
            container.updated_at = timeutils.utcnow()
            container.consumers.append(new_consumer)
            container.save(session=session)
        except db_exc.DBDuplicateEntry:
            session.rollback()  # We know consumer already exists.

            # This operation is idempotent, so log this and move on
            LOG.debug("Consumer %s with URL %s already exists for "
                      "container %s, continuing...", new_consumer.name,
                      new_consumer.URL, new_consumer.container_id)
            # Get the existing entry and reuse it by clearing the deleted flags
            existing_consumer = cls.get_by_values(
                new_consumer.container_id, new_consumer.name, new_consumer.URL,
                show_deleted=True)
            existing_consumer.deleted = False
            existing_consumer.deleted_at = None
            # We are not concerned about timing here -- set only, no reads
            existing_consumer.save(session=session)
