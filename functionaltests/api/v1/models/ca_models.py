"""
Copyright 2015 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from functionaltests.api.v1.models.base_models import BaseModel


class CAModel(BaseModel):

    def __init__(self, expiration=None, ca_id=None, ca_ref=None,
                 status=None, updated=None, created=None, plugin_name=None,
                 plugin_ca_id=None, meta=None, parent_ca_ref=None,
                 subject_dn=None, name=None, description=None):
        super(CAModel, self).__init__()

        self.expiration = expiration
        self.ca_id = ca_id
        self.ca_ref = ca_ref
        self.status = status
        self.updated = updated
        self.created = created
        self.plugin_name = plugin_name
        self.plugin_ca_id = plugin_ca_id
        self.meta = meta
        self.parent_ca_ref = parent_ca_ref
        self.subject_dn = subject_dn
        self.name = name
        self.description = description
