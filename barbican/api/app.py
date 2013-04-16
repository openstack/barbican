# Copyright (c) 2013 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
API application handler for Cloudkeep's Barbican
"""

import falcon

from barbican.api.resources import VersionResource
from barbican.api.resources import TenantsResource, TenantResource
from barbican.api.resources import CSRsResource, CSRResource
from barbican.api.resources import CertificatesResource, CertificateResource
from barbican.api.resources import SecretsResource, SecretResource
from barbican.openstack.common import log
from barbican.common import config


def create_main_app(global_config, **local_conf):
    """uWSGI factory method for the Barbican-API application"""

    config.parse_args()
    log.setup('barbican')

    # Resources
    VERSIONS = VersionResource()
    TENANTS = TenantsResource()
    TENANT = TenantResource()
    SECRETS = SecretsResource()
    SECRET = SecretResource()
    CSRS = CSRsResource()
    CSR = CSRResource()
    CERTS = CertificatesResource()
    CERT = CertificateResource()

    wsgi_app = api = falcon.API()
    api.add_route('/', VERSIONS)
    api.add_route('/tenants', TENANTS)
    api.add_route('/tenants/{tenant_id}', TENANT)
    api.add_route('/{tenant_id}/secrets', SECRETS)
    api.add_route('/{tenant_id}/secrets/{secret_id}', SECRET)
    api.add_route('/{tenant_id}/csrs', CSRS)
    api.add_route('/{tenant_id}/csrs/{csr_id}', CSR)
    api.add_route('/{tenant_id}/certificates', CERTS)
    api.add_route('/{tenant_id}/certificates/{cert_id}', CERT)
    
    return wsgi_app