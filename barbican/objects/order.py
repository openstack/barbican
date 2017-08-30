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
from oslo_versionedobjects import base as object_base

from barbican.model import models
from barbican.model import repositories as repos
from barbican.objects import base
from barbican.objects import fields


class OrderType(object):
    KEY = 'key'
    ASYMMETRIC = 'asymmetric'
    CERTIFICATE = 'certificate'

    @classmethod
    def is_valid(cls, order_type):
        """Tests if a order type is a valid one."""
        return order_type in cls.__dict__


class OrderStatus(object):
    def __init__(self, id, message):
        self.id = id
        self.message = message


@object_base.VersionedObjectRegistry.register
class Order(base.BarbicanObject, base.BarbicanPersistentObject,
            object_base.VersionedObjectDictCompat):
    """This class represents Order object"""

    fields = {
        'type': fields.StringField(default='key'),
        'project_id': fields.StringField(),
        'error_status_code': fields.StringField(nullable=True, default=None),
        'error_reason': fields.StringField(nullable=True, default=None),
        'meta': fields.JsonField(nullable=True, default=None),
        'secret_id': fields.StringField(nullable=True, default=None),
        'container_id': fields.StringField(nullable=True, default=None),
        'sub_status': fields.StringField(nullable=True, default=None),
        'sub_status_message': fields.StringField(nullable=True, default=None),
        'creator_id': fields.StringField(nullable=True, default=None),
        'order_plugin_metadata': fields.DictOfObjectsField(
            'OrderPluginMetadatum', nullable=True, default=dict()),
        'order_barbican_metadata': fields.DictOfObjectsField(
            'OrderBarbicanMetadatum', nullable=True, default=dict())

    }

    db_model = models.Order
    db_repo = repos.get_order_repository()
    synthetic_fields = ['order_plugin_metadata', 'order_barbican_metadata']

    @classmethod
    def get_by_create_date(cls, external_project_id, offset_arg=None,
                           limit_arg=None, meta_arg=None,
                           suppress_exception=False, session=None):
        """Returns a list of orders

        The list is ordered by the date they were created at and paged
        based on the offset and limit fields.
        :param external_project_id: The keystone id for the project.
        :param offset_arg: The entity number where the query result should
                           start.
        :param limit_arg: The maximum amount of entities in the result set.
        :param meta_arg: Optional meta field used to filter results.
        :param suppress_exception: Whether NoResultFound exceptions should be
                                   suppressed.
        :param session: SQLAlchemy session object.
        :returns: Tuple consisting of
                  (list_of_entities, offset, limit, total).
        """
        entities_db, offset, limit, total = cls.db_repo.get_by_create_date(
            external_project_id,
            offset_arg=offset_arg,
            limit_arg=limit_arg,
            meta_arg=meta_arg,
            suppress_exception=suppress_exception,
            session=session
        )
        entities = [cls()._from_db_object(entity_db)
                    for entity_db in entities_db]
        return entities, offset, limit, total
