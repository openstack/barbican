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
API-facing resource controllers.
"""


import falcon

from barbican.version import __version__
from barbican.api import ApiResource, load_body, abort
from barbican.model.models import Tenant, Secret, States, CSR, Certificate
from barbican.model.repositories import TenantRepo, SecretRepo
from barbican.model.repositories import CSRRepo, CertificateRepo
from barbican.crypto.fields import encrypt, decrypt
from barbican.openstack.common.gettextutils import _
from barbican.openstack.common import jsonutils as json
from barbican.queue import get_queue_api
from barbican.common import utils

LOG = utils.getLogger(__name__)


def _tenant_not_found():
    abort(falcon.HTTP_404, 'Unable to locate tenant.')


def _tenant_already_exists():
    abort(falcon.HTTP_400, 'Tenant already exists.')


def _secret_not_found():
    abort(falcon.HTTP_400, 'Unable to locate secret profile.')


def json_handler(obj):
    """Convert objects into json-friendly equivalents."""
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


class VersionResource(ApiResource):
    """Returns service and build version information"""

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = json.dumps({'v1': 'current',
                                'build': __version__})


class TenantsResource(ApiResource):
    """Handles Tenant creation requests"""

    def __init__(self, tenant_repo=None):
        LOG.debug('Creating TenantsResource')
        self.repo = tenant_repo or TenantRepo()

    def on_post(self, req, resp):
        body = load_body(req)
        LOG.debug('Start on_post...%s' % body)
        username = body['username']
        # LOG.debug('Username is {0}'.format(username))
        LOG.debug('Tenant username is %s' % username)

        tenant = self.repo.find_by_name(name=username, suppress_exception=True)

        if tenant:
            abort(falcon.HTTP_400, 'Tenant with username {0} '
                                   'already exists'.format(username))

        new_tenant = Tenant()
        new_tenant.username = username
        new_tenant.status = States.ACTIVE
        self.repo.create_from(new_tenant)

        LOG.debug('...post create from')

        resp.status = falcon.HTTP_201
        resp.set_header('Location', '/{0}'.format(new_tenant.id))
        # TBD: Generate URL...
        url = 'http://localhost:8080/tenants/%s' % new_tenant.id
        resp.body = json.dumps({'ref': url})


class TenantResource(ApiResource):
    """Handles Tenant retrieval and deletion requests"""

    def __init__(self, tenant_repo=None):
        self.repo = tenant_repo or TenantRepo()

    def on_get(self, req, resp, tenant_id):
        tenant = self.repo.get(entity_id=tenant_id)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(tenant.to_dict_fields(), default=json_handler)

    def on_delete(self, req, resp, tenant_id):
        tenant = self.repo.get(entity_id=tenant_id)

        self.repo.delete_entity(tenant)

        resp.status = falcon.HTTP_200


class SecretsResource(ApiResource):
    """Handles Secret creation requests"""

    def __init__(self, tenant_repo=None, secret_repo=None):
        LOG.debug('Creating SecretsResource')
        self.tenant_repo = tenant_repo or TenantRepo()
        self.secret_repo = secret_repo or SecretRepo()

    def on_post(self, req, resp, tenant_id):
        tenant = self.tenant_repo.get(tenant_id)

        body = load_body(req)

        LOG.debug('Start on_post...%s' % body)

        name = body['name']
        LOG.debug('Secret name is %s' % name)

        secret = self.secret_repo.find_by_name(name=name,
                                               suppress_exception=True)
        if secret:
            abort(falcon.HTTP_400, 'Secret with name {0} '
                                   'already exists'.format(name))

        # Encrypt fields
        encrypt(body)
        secret_value = body['secret']
        LOG.debug('Encrypted secret is %s' % secret_value)

        new_secret = Secret()
        new_secret.name = name
        new_secret.secret = secret_value
        new_secret.tenant_id = tenant.id
        new_secret.status = States.ACTIVE
        self.secret_repo.create_from(new_secret)

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/secrets/{1}'.format(tenant_id,
                                                              new_secret.id))
        # TBD: Generate URL...
        url = 'http://localhost:8080/%s/secrets/%s' % (tenant_id,
                                                       new_secret.id)
        resp.body = json.dumps({'ref': url})


class SecretResource(ApiResource):
    """Handles Secret retrieval and deletion requests"""

    def __init__(self, secret_repo=None):
        self.repo = secret_repo or SecretRepo()

    def on_get(self, req, resp, tenant_id, secret_id):
        secret = self.repo.get(entity_id=secret_id)
        fields = secret.to_dict_fields()
        LOG.debug('Read encrypted secret as %s' % fields['secret'])

        # Decrypt fields
        decrypt(fields)
        secret_value = fields['secret']

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(fields, default=json_handler)

    def on_delete(self, req, resp, tenant_id, secret_id):
        secret = self.repo.get(entity_id=secret_id)

        self.repo.delete_entity(secret)

        resp.status = falcon.HTTP_200


class CSRsResource(ApiResource):
    """Handles CSR (SSL certificate request) creation and lists requests"""

    def __init__(self, tenant_repo=None, csr_repo=None, queue_resource=None):
        LOG.debug('Creating CSRsResource')
        self.tenant_repo = tenant_repo or TenantRepo()
        self.csr_repo = csr_repo or CSRRepo()
        self.queue = queue_resource or get_queue_api()

    def on_post(self, req, resp, tenant_id):
        tenant = self.tenant_repo.get(tenant_id)

        body = load_body(req)
        LOG.debug('Start on_post...%s' % body)
        requestor = body['requestor']
        LOG.debug('CSR requestor is %s' % requestor)

        # TBD: What criteria to restrict multiple concurrent SSL
        #      requests per tenant?
        # csr = self.csr_repo.find_by_name(name=requestor,
        #                                  suppress_exception=True)
        # if csr:
        #    abort(falcon.HTTP_400, 'Tenant with username {0} '
        #                           'already exists'.format(username))

        # TBD: Encrypt fields

        new_csr = CSR()
        new_csr.requestor = requestor
        new_csr.tenant_id = tenant.id
        self.csr_repo.create_from(new_csr)

        # Send to workers to process.
        self.queue.begin_csr(csr_id=new_csr.id)

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/csrs/{1}'.format(tenant_id,
                                                           new_csr.id))
        # TBD: Generate URL...
        url = 'http://localhost:8080/%s/csrs/%s' % (tenant_id, new_csr.id)
        resp.body = json.dumps({'ref': url})


class CSRResource(ApiResource):
    """Handles CSR retrieval and deletion requests"""

    def __init__(self, csr_repo=None):
        self.repo = csr_repo or CSRRepo()

    def on_get(self, req, resp, tenant_id, csr_id):
        csr = self.repo.get(entity_id=csr_id)

        resp.status = falcon.HTTP_200

        resp.body = json.dumps(csr.to_dict_fields(), default=json_handler)

    def on_delete(self, req, resp, tenant_id, csr_id):
        csr = self.repo.get(entity_id=csr_id)

        self.repo.delete_entity(csr)

        resp.status = falcon.HTTP_200


class CertificatesResource(ApiResource):
    """Handles Certs (SSL certificates) lists per Tenant requests"""

    def __init__(self, cert_repo=None):
        LOG.debug('Creating CertificatesResource')
        self.repo = cert_repo or CertificateRepo()

    def on_post(self, req, resp, tenant_id):
        resp.status = falcon.HTTP_405
        msg = _("To create SSL certificates, you must first issue a CSR.")
        abort(falcon.HTTP_405, msg)


class CertificateResource(ApiResource):
    """Handles Cert (SSL certificates) retrieval and deletion requests"""

    def __init__(self, cert_repo=None):
        self.repo = cert_repo or CertificateRepo()

    def on_get(self, req, resp, tenant_id, cert_id):
        cert = self.repo.get(entity_id=cert_id)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(cert.to_dict_fields(), default=json_handler)

    def on_delete(self, req, resp, tenant_id, cert_id):
        cert = self.repo.get(entity_id=cert_id)

        self.repo.delete_entity(cert)

        resp.status = falcon.HTTP_200
