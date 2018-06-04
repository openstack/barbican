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
from barbican.model import repositories as repo
from barbican.objects import base
from barbican.objects import fields


@object_base.VersionedObjectRegistry.register
class KEKDatum(base.BarbicanObject, base.BarbicanPersistentObject,
               object_base.VersionedObjectDictCompat):

    fields = {
        'plugin_name': fields.StringField(nullable=True, default=None),
        'kek_label': fields.StringField(nullable=True, default=None),
        'project_id': fields.StringField(nullable=True, default=None),
        'active': fields.BooleanField(default=True),
        'bind_completed': fields.BooleanField(default=False),
        'algorithm': fields.StringField(nullable=True, default=None),
        'bit_length': fields.IntegerField(nullable=True, default=None),
        'mode': fields.StringField(nullable=True, default=None),
        'plugin_meta': fields.StringField(nullable=True, default=None)
    }

    db_model = models.KEKDatum
    db_repo = repo.get_kek_datum_repository()

    @classmethod
    def find_or_create_kek_datum(cls, project, plugin_name,
                                 suppress_exception=False, session=None):
        kek_datum_db = cls.db_repo.find_or_create_kek_datum(
            project, plugin_name, suppress_exception, session)
        return cls()._from_db_object(kek_datum_db)
