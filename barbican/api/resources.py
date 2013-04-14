import json
import falcon
import logging

from barbican.version import __version__
from barbican.api import ApiResource, load_body, abort
from barbican.model.models import Tenant, States, CSR, Certificate
from barbican.model.repositories import TenantRepo, CSRRepo, CertificateRepo
from barbican.queue.resources import QueueResource, StartCSRMessage
from barbican.common import config

LOG = logging.getLogger(__name__)

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
        print 'Start on_post...%s' % body
        username = body['username']
        # LOG.debug('Username is {0}'.format(username))
        print 'Username is %s' % username

        tenant = self.repo.find_by_name(name=username, suppress_exception=True)

        if tenant:
            abort(falcon.HTTP_400, 'Tenant with username {0} '
                                   'already exists'.format(username))
        # TBD: Encrypte fields

        new_tenant = Tenant()
        new_tenant.username = username
        new_tenant.status = States.ACTIVE
        self.repo.create_from(new_tenant)

        print '...post create from'

        resp.status = falcon.HTTP_201
        resp.set_header('Location', '/{0}'.format(new_tenant.id))
        # TBD: Generate URL...
        url = 'http://localhost:8080:/tenants/%s' % new_tenant.id
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
        

class CSRsResource(ApiResource):
    """Handles CSR (SSL certificate request) creation and lists requests"""

    def __init__(self, csr_repo=None, queue_resource=None):
        LOG.debug('Creating CSRsResource')
        self.repo = csr_repo or CSRRepo()
        self.queue = queue_resource or QueueResource()

    def on_post(self, req, resp, tenent_id):
        body = load_body(req)
        # TBD: Remove:
        print 'Start on_post...%s' % body
        requestor = body['requestor']
        # LOG.debug('Username is {0}'.format(username))
        print 'requestor is %s' % requestor

        # TBD: What criteria to restrict multiple concurrent SSL requests per tenant?
        # csr = self.repo.find_by_name(name=requestor, suppress_exception=True)
        #
        #if csr:
        #    abort(falcon.HTTP_400, 'Tenant with username {0} '
        #                           'already exists'.format(username))

        # TBD: Encrypt fields

        new_csr = CSR()
        new_csr.requestor = requestor
        self.repo.create_from(new_csr)

        # TBD: Remove:
        print '...post create from'

        # Send to workers to process.
        self.queue.send(StartCSRMessage(new_csr.id))

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/csrs/{1}'.format(tenent_id, new_csr.id))
        # TBD: Generate URL...
        url = 'http://localhost:8080:/%s/csrs/%s' % (tenent_id, new_csr.id)
        resp.body = json.dumps({'ref': url})


class CSRResource(ApiResource):
    """Handles CSR retrieval and deletion requests"""

    def __init__(self, csr_repo=None):
        self.repo = csr_repo or CSRRepo() 

    def on_get(self, req, resp, tenent_id, csr_id):
        csr = self.repo.get(entity_id=csr_id)

        resp.status = falcon.HTTP_200
        
        resp.body = json.dumps(csr.to_dict_fields(), default=json_handler)

    def on_delete(self, req, resp, tenent_id, csr_id):
        csr = self.repo.get(entity_id=csr_id)

        self.repo.delete_entity(csr)

        resp.status = falcon.HTTP_200
 

class CertificatesResource(ApiResource):
    """Handles Certs (SSL certificates) lists per Tenant requests"""

    def __init__(self, cert_repo=None):
        LOG.debug('Creating CertificatesResource')
        self.repo = cert_repo or CertificateRepo()

    def on_post(self, req, resp, tenent_id):
        resp.status = falcon.HTTP_405
        # TBD: I18n this!
        resp.body = u"To create SSL certificates, you must first issue a CSR"


class CertificateResource(ApiResource):
    """Handles Cert (SSL certificates) retrieval and deletion requests"""

    def __init__(self, cert_repo=None):
        self.repo = cert_repo or CertificateRepo() 

    def on_get(self, req, resp, tenent_id, cert_id):
        cert = self.repo.get(entity_id=cert_id)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(cert.to_dict_fields(), default=json_handler)