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

from barbican.common import exception
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
from barbican.objects import base
from barbican.objects import fields


@object_base.VersionedObjectRegistry.register
class TransportKey(base.BarbicanObject, base.BarbicanPersistentObject,
                   object_base.VersionedObjectDictCompat):
    fields = {
        'plugin_name': fields.StringField(),
        'transport_key': fields.StringField(),
        'status': fields.StringField(nullable=True, default=base.States.ACTIVE)
    }

    db_model = models.TransportKey
    db_repo = repo.get_transport_key_repository()

    def _validate_fields(self, change_fields):
        msg = u._("Must supply non-None {0} argument for TransportKey entry.")

        if change_fields.get('plugin_name') is None:
            raise exception.MissingArgumentError(msg.format("plugin_name"))

        if change_fields.get('transport_key') is None:
            raise exception.MissingArgumentError(msg.format("transport_key"))

    @classmethod
    def get_by_create_date(cls, plugin_name=None,
                           offset_arg=None, limit_arg=None,
                           suppress_exception=False, session=None):
        transport_keys_db, offset, limit, total = \
            cls.db_repo.get_by_create_date(plugin_name, offset_arg, limit_arg,
                                           suppress_exception, session)
        transport_keys_obj = [cls()._from_db_object(transport_key)
                              for transport_key in transport_keys_db]
        return transport_keys_obj, offset, limit, total

    @classmethod
    def get_latest_transport_key(cls, plugin_name, suppress_exception=False,
                                 session=None):
        transport_key_db = cls.db_repo.get_latest_transport_key(
            plugin_name, suppress_exception, session)
        return cls()._from_db_object(transport_key_db)
