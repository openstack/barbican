import json
import falcon
import logging

from barbican.version import __version__
from barbican.api import ApiResource, load_body, abort
from barbican.model.models import Tenant
from barbican.model.repositories import TenantRepo
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

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = json.dumps({'v1': 'current',
                                'build': __version__})


class TenantsResource(ApiResource):

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

        new_tenant = Tenant()
        new_tenant.username = username
        self.repo.create_from(new_tenant)

        print '...post create from'

        resp.status = falcon.HTTP_201
        resp.set_header('Location', '/{0}'.format(new_tenant.id))
        # TBD: Generate URL...
        url = 'http://localhost:8080:/tenants/%s' % new_tenant.id
        resp.body = json.dumps({'ref': url})


class TenantResource(ApiResource):

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