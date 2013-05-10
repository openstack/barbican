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
from barbican.api import policy
from barbican.model.models import (Tenant, Secret, TenantSecret,
                                   EncryptedDatum, Order, States)
from barbican.model.repositories import (TenantRepo, SecretRepo,
                                         OrderRepo, TenantSecretRepo,
                                         EncryptedDatumRepo)
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

    def __init__(self, policy_enforcer=None):
        LOG.debug('=== Creating VersionResource ===')
        self.policy = policy_enforcer or policy.Enforcer()

    def on_get(self, req, resp):
        LOG.debug('=== Authenticated and policy satisfied VersionResource ===')
        resp.status = falcon.HTTP_200
        resp.body = json.dumps({'v1': 'current',
                                'build': __version__})


class SecretsResource(ApiResource):
    """Handles Secret creation requests"""

    def __init__(self, tenant_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None,
                 policy_enforcer=None):
        LOG.debug('Creating SecretsResource')
        self.tenant_repo = tenant_repo or TenantRepo()
        self.secret_repo = secret_repo or SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or TenantSecretRepo()
        self.datum_repo = datum_repo or EncryptedDatumRepo()
        self.policy = policy_enforcer or policy.Enforcer()
        

    def on_post(self, req, resp, tenant_id):

        LOG.debug('Start on_post for tenant-ID {0}:'.format(tenant_id))
   
        body = load_body(req)
   
        # Retrieve Tenant, or else create new Tenant
        #   if this is a request from a new tenant.
        tenant = self.tenant_repo.get(tenant_id, suppress_exception=True)
        if not tenant:
            LOG.debug('Creating tenant for {0}'.format(tenant_id))
            tenant = Tenant()
            tenant.keystone_id = tenant_id
            tenant.status = States.ACTIVE
            self.tenant_repo.create_from(tenant)

        # Verify secret doesn't already exist.
        name = body['name']
        LOG.debug('Secret name is {0}'.format(name))
        secret = self.secret_repo.find_by_name(name=name,
                                               suppress_exception=True)
        if secret:
            abort(falcon.HTTP_400, 'Secret with name {0} '
                                   'already exists'.format(name))

        # Encrypt fields.
        encrypt(body)
        LOG.debug('Post-encrypted fields...{0}'.format(body))
        secret_value = body['cypher_text']
        LOG.debug('Encrypted secret is {0}'.format(secret_value))

        # Create Secret entity.
        new_secret = Secret()
        new_secret.name = name
#TODO:  new_secret.expiration = ...
        new_secret.status = States.ACTIVE
        self.secret_repo.create_from(new_secret)

        # Create Tenant/Secret entity.
        new_assoc = TenantSecret()
        new_assoc.tenant_id = tenant.id
        new_assoc.secret_id = new_secret.id
        new_assoc.role = "admin"
        new_assoc.status = States.ACTIVE
        self.tenant_secret_repo.create_from(new_assoc)

        # Create EncryptedDatum entity.
        new_datum = EncryptedDatum()
        new_datum.secret_id = new_secret.id
        new_datum.mime_type = body['mime_type']
        new_datum.cypher_text = secret_value
        new_datum.kek_metadata = body['kek_metadata']
        new_datum.status = States.ACTIVE
        self.datum_repo.create_from(new_datum)

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/secrets/{1}'.format(tenant_id,
                                                              new_secret.id))
        #TODO: Generate URL...Use .format() approach here too
        url = 'http://localhost:8080/{0}/secrets/{1}'.format(tenant_id,
                                                             new_secret.id)
        LOG.debug('URI to secret is {0}'.format(url))
        resp.body = json.dumps({'ref': url})


class SecretResource(ApiResource):
    """Handles Secret retrieval and deletion requests"""

    def __init__(self, secret_repo=None, policy_enforcer=None):
        self.repo = secret_repo or SecretRepo()
        self.policy = policy_enforcer or policy.Enforcer()

    def on_get(self, req, resp, tenant_id, secret_id):
        #TODO: Use a falcon exception here
        secret = self.repo.get(entity_id=secret_id)
        resp.status = falcon.HTTP_200
        resp.body = json.dumps(secret.to_dict_fields(), default=json_handler)

    def on_delete(self, req, resp, tenant_id, secret_id):
        secret = self.repo.get(entity_id=secret_id)

        self.repo.delete_entity(secret)

        resp.status = falcon.HTTP_200


class OrdersResource(ApiResource):
    """Handles Order requests for Secret creation"""

    def __init__(self, tenant_repo=None, order_repo=None, 
                  queue_resource=None, policy_enforcer=None):
        LOG.debug('Creating OrdersResource')
        self.tenant_repo = tenant_repo or TenantRepo()
        self.order_repo = order_repo or OrderRepo()
        self.queue = queue_resource or get_queue_api()
        self.policy = policy_enforcer or policy.Enforcer()
    def on_post(self, req, resp, tenant_id):

        # Retrieve Tenant, or else create new Tenant
        #   if this is a request from a new tenant.
        tenant = self.tenant_repo.get(tenant_id, suppress_exception=True)
        if not tenant:
            tenant = Tenant()
            tenant.keystone_id = tenant_id
            tenant.status = States.ACTIVE
            self.tenant_repo.create_from(tenant)

        body = load_body(req)
        LOG.debug('Start on_post...{0}'.format(body))
        name = body['secret_name']
        LOG.debug('Secret to create is {0}'.format(name))


        #TODO: What criteria to restrict multiple concurrent Order
        #      requests per tenant?
        # order = self.order_repo.find_by_name(name=secret_name,
        #                                  suppress_exception=True)
        # if order:
        #    abort(falcon.HTTP_400, 'Order with username {0} '
        #                           'already exists'.format(username))

        #TODO: Encrypt fields as needed

        new_order = Order()
        new_order.secret_name = body['secret_name']
        new_order.secret_mime_type = body['secret_mime_type']
#TODO:        new_order.secret_expiration = body['secret_expiration']
        new_order.tenant_id = tenant.id
        self.order_repo.create_from(new_order)

        # Send to workers to process.
        self.queue.process_order(order_id=new_order.id)

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/orders/{1}'.format(tenant_id,
                                                             new_order.id))
        #TODO: Generate URL...
        url = 'http://localhost:8080/{0}/orders/{1}'.format(tenant_id,
                                                            new_order.id)
        resp.body = json.dumps({'ref': url})


class OrderResource(ApiResource):
    """Handles Order retrieval and deletion requests"""

    def __init__(self, order_repo=None, policy_enforcer=None):
        self.repo = order_repo or OrderRepo()
        self.policy = policy_enforcer or policy.Enforcer()

    def on_get(self, req, resp, tenant_id, order_id):
        #TODO: Use a falcon exception here
        order = self.repo.get(entity_id=order_id)
        resp.status = falcon.HTTP_200
        resp.body = json.dumps(order.to_dict_fields(), default=json_handler)

    def on_delete(self, req, resp, tenant_id, order_id):
        order = self.repo.get(entity_id=order_id)

        self.repo.delete_entity(order)

        resp.status = falcon.HTTP_200
