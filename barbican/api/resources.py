import json
import falcon
import logging

from barbican.version import __version__
from barbican.api import ApiResource, load_body, abort
from barbican.model.tenant import Tenant, Secret
import barbican.model.repositories

def _tenant_not_found():
    abort(falcon.HTTP_404, 'Unable to locate tenant.')


def _tenant_already_exists():
    abort(falcon.HTTP_400, 'Tenant already exists.')


def _secret_not_found():
    abort(falcon.HTTP_400, 'Unable to locate secret profile.')


def format_tenant(tenant):
    if not isinstance(tenant, dict):
        tenant = tenant.__dict__

    return {'id': tenant['id'],
            'tenant_id': tenant['tenant_id']}


class VersionResource(ApiResource):

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = json.dumps({'v1': 'current',
                                'build': __version__})


class TenantsResource(ApiResource):

    def __init__(self, db_session):
        self.repo = TenantRepo() 

    def on_post(self, req, resp):
        body = load_body(req)
        username = body['username']
        logging.debug('Username is {0}'.format(username))

        tenant = self.repo.find_by_name(username, False)

        if tenant:
            abort(falcon.HTTP_400, 'Tenant with username {0} '
                                   'already exists'.format(username))

        new_tenant = Tenant(username)
        self.db.add(new_tenant)
        self.db.commit()

        resp.status = falcon.HTTP_201
        resp.set_header('Location', '/v1/{0}'.format(new_tenant.id))


class TenantResource(ApiResource):

    def __init__(self, db_session):
        self.db = db_session

    def on_get(self, req, resp, tenant_id):
        tenant = find_tenant(self.db, id=tenant_id,
                             when_not_found=_tenant_not_found)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(tenant.format())

    def on_delete(self, req, resp, tenant_id):
        tenant = find_tenant(self.db, id=tenant_id,
                             when_not_found=_tenant_not_found)

        self.db.delete(tenant)
        self.db.commit()

        resp.status = falcon.HTTP_200


class SecretsResource(ApiResource):

    def __init__(self, db_session):
        self.db = db_session

    def on_get(self, req, resp, tenant_id):
        tenant = find_tenant(self.db, id=tenant_id,
                             when_not_found=_tenant_not_found)

        resp.status = falcon.HTTP_200

        #jsonify a list of formatted secrets
        resp.body = json.dumps([s.format() for s in tenant.secrets])

    def on_post(self, req, resp, tenant_id):
        tenant = find_tenant(self.db, id=tenant_id,
                             when_not_found=_tenant_not_found)

        body = load_body(req)
        secret_name = body['name']

        # Check if the tenant already has a secret with this name
        for secret in tenant.secrets:
            if secret.name == secret_name:
                abort(falcon.HTTP_400,
                      'Secret with name {0} already exists.'.format(
                      secret.name, secret.id))

        # Create the new secret
        new_secret = Secret(tenant.id, secret_name)
        tenant.secrets.append(new_secret)

        self.db.add(new_secret)
        self.db.commit()

        resp.status = falcon.HTTP_201
        resp.set_header('Location',
                        '/v1/{0}/secrets/{1}'
                        .format(tenant_id, new_secret.id))


class SecretResource(ApiResource):

    def __init__(self, db_session):
        self.db = db_session

    def on_get(self, req, resp, tenant_id, secret_id):
        #verify the tenant exists
        tenant = find_tenant(self.db, tenant_id=tenant_id,
                             when_not_found=_tenant_not_found)

        #verify the secret exists
        secret = find_secret(self.db, id=secret_id,
                             when_not_found=_secret_not_found)

        #verify the secret belongs to the tenant
        if not secret in tenant.secrets:
            _secret_not_found()

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(secret.format())

    def on_put(self, req, resp, tenant_id, secret_id):
        #verify the tenant exists
        tenant = find_tenant(self.db, tenant_id=tenant_id,
                             when_not_found=_tenant_not_found)

        #verify the secret exists
        secret = find_secret(self.db, id=secret_id,
                             when_not_found=_secret_not_found)

        #verify the secret belongs to the tenant
        if not secret in tenant.secrets:
            _secret_not_found()

        #load the message
        body = load_body(req)

        #if attributes are present in message, update the secret
        if 'name' in body.keys():
            secret.name = body['name']

        self.db.commit()
        resp.status = falcon.HTTP_200

    def on_delete(self, req, resp, tenant_id, secret_id):
        #verify the tenant exists
        tenant = find_tenant(self.db, tenant_id=tenant_id,
                             when_not_found=_tenant_not_found)

        #verify the secret exists
        secret = find_secret(self.db, id=secret_id,
                             when_not_found=_secret_not_found)

        #verify the secret belongs to the tenant
        if not secret in tenant.secrets:
            _secret_not_found()

        self.db.delete(secret)
        self.db.commit()

        resp.status = falcon.HTTP_200
