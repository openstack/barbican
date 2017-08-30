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


@object_base.VersionedObjectRegistry.register
class OrderBarbicanMetadatum(base.BarbicanObject,
                             base.BarbicanPersistentObject,
                             object_base.VersionedObjectDictCompat):
    """This class represents OrderBarbicanMetadatum object"""

    fields = {
        'order_id': fields.StringField(),
        'key': fields.StringField(),
        'value': fields.StringField()
    }

    db_model = models.OrderBarbicanMetadatum
    db_repo = repos.get_order_barbican_meta_repository()
