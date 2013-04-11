# Copyright 2010-2011 OpenStack LLC.
# All Rights Reserved.
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

"""
API application handler for Cloudkeep's Barbican
"""

import falcon

from barbican.api.resources import VersionResource
from barbican.api.resources import TenantsResource, TenantResource
from barbican.api.resources import SecretsResource, SecretResource

# Resources
VERSIONS = VersionResource()
TENANTS = TenantsResource()
TENANT = TenantResource()
SECRETS = SecretsResource()
SECRET = SecretResource()

# Routing
application = falcon.API()
api = application
api.add_route('/', VERSIONS)
api.add_route('/tenant', TENANTS)
api.add_route('/{tenant_id}', TENANT)
api.add_route('/{tenant_id}/secrets', SECRETS)
api.add_route('/{tenant_id}/secrets/{secret_id}', SECRET)
