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

from barbican.common import utils
from barbican.model import models
from barbican.model import repositories as repos
from barbican.objects import base
from barbican.objects import fields


class OrderRetryTask(base.BarbicanObject, base.BarbicanPersistentObject,
                     object_base.VersionedObjectDictCompat):
    fields = {
        'id': fields.StringField(default=utils.generate_uuid()),
        'order_id': fields.StringField(),
        'retry_task': fields.StringField(),
        'retry_at': fields.DateTimeField(nullable=True, default=None),
        'retry_args': fields.JsonField(),
        'retry_kwargs': fields.JsonField(),
        'retry_count': fields.IntegerField(default=0)
    }

    db_model = models.OrderRetryTask
    db_repo = repos.get_order_retry_tasks_repository()

    @classmethod
    def get_by_create_date(cls, only_at_or_before_this_date=None,
                           offset_arg=None, limit_arg=None,
                           suppress_exception=False,
                           session=None):
        entities_db, offset, limit, total = cls.db_repo.get_by_create_date(
            only_at_or_before_this_date, offset_arg, limit_arg,
            suppress_exception, session)
        entities = [cls()._from_db_object(entity_db)
                    for entity_db in entities_db]
        return entities, offset, limit, total
