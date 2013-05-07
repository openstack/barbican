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
from barbican.model.models import (Tenant, Secret, TenantSecret,
                                   EncryptedDatum, Order, States)
from barbican.model.repositories import (TenantRepo, SecretRepo,
                                         OrderRepo, TenantSecretRepo,
                                         EncryptedDatumRepo)
from barbican.common.resources import (create_secret,
                                       create_encrypted_datum)
from barbican.crypto.fields import (encrypt, decrypt,
                                    dumps, augment_fields_with_content_types)
from barbican.openstack.common.gettextutils import _
from barbican.openstack.common import jsonutils as json
from barbican.queue import get_queue_api
from barbican.common import utils

LOG = utils.getLogger(__name__)


def _secret_not_found():
    """Throw exception indicating secret not found."""
    abort(falcon.HTTP_400, 'Unable to locate secret profile.')


def _put_accept_incorrect(ct):
    """Throw exception indicating request content-type is not supported."""
    abort(falcon.HTTP_415, "Content-Type of '{0}' "
          "is not supported.".format(ct))


def _client_content_mismatch_to_secret():
    """
    Throw exception indicating client content-type doesn't match
    secret's mime-type.
    """
    abort(falcon.HTTP_400, "Request content-type doesn't match secret's.")
 

def json_handler(obj):
    """Convert objects into json-friendly equivalents."""
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


class VersionResource(ApiResource):
    """Returns service and build version information"""

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = json.dumps({'v1': 'current',
                                'build': __version__})


class SecretsResource(ApiResource):
    """Handles Secret creation requests"""

    def __init__(self, tenant_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None):
        LOG.debug('Creating SecretsResource')
        self.tenant_repo = tenant_repo or TenantRepo()
        self.secret_repo = secret_repo or SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or TenantSecretRepo()
        self.datum_repo = datum_repo or EncryptedDatumRepo()

    def on_post(self, req, resp, tenant_id):

        LOG.debug('Start on_post for tenant-ID {0}:'.format(tenant_id))
   
        body = load_body(req)

        # Create Secret
        new_secret = create_secret(body, tenant_id,
                                   self.tenant_repo,
                                   self.secret_repo,
                                   self.tenant_secret_repo,
                                   self.datum_repo)

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/secrets/{1}'.format(tenant_id,
                                                              new_secret.id))
        #TODO: Generate URL
        url = 'http://localhost:8080/{0}/secrets/{1}'.format(tenant_id,
                                                             new_secret.id)
        LOG.debug('URI to secret is {0}'.format(url))
        resp.body = json.dumps({'ref': url})


class SecretResource(ApiResource):
    """Handles Secret retrieval and deletion requests"""

    def __init__(self, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None):
        self.repo = secret_repo or SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or TenantSecretRepo()
        self.datum_repo = datum_repo or EncryptedDatumRepo()

    def on_get(self, req, resp, tenant_id, secret_id):

        print "req: ",dir(req)
        print "req accept: ",req.accept
        print "req content: ",req.content_type
        print "resp: ",dir(resp)

        secret = self.repo.get(entity_id=secret_id, suppress_exception=True)
        if not secret:
            _secret_not_found()

        print "secret data: ",secret.encrypted_data

        resp.status = falcon.HTTP_200

        if not req.accept or req.accept == 'application/json':
            # Metadata-only response, no decryption necessary.
            resp.body = json.dumps(augment_fields_with_content_types(secret),
                                   default=json_handler)
        else:
            resp.body = dumps(req.accept, secret)

    def on_put(self, req, resp, tenant_id, secret_id):

        print "req: ",dir(req)
        print "req accept: ",req.accept
        print "req content: ",req.content_type
        print "resp: ",dir(resp)

        if not req.content_type or req.content_type == 'application/json':
            _put_accept_incorrect(req.content_type)

        secret = self.repo.get(entity_id=secret_id, suppress_exception=True)
        if not secret:
            _secret_not_found()
        if secret.mime_type != req.content_type:
            _client_content_mismatch_to_secret()

        try:
            plain_text = req.stream.read()
        except IOError:
            abort(falcon.HTTP_500, 'Read Error')

        print "uploaded secret data: ",plain_text

        resp.status = falcon.HTTP_200
        
        resp.body = create_encrypted_datum(secret, plain_text, 
                                           tenant_id, tenant_secret_repo,
                                           datum_repo)

    def on_delete(self, req, resp, tenant_id, secret_id):
        secret = self.repo.get(entity_id=secret_id)

        self.repo.delete_entity(secret)

        resp.status = falcon.HTTP_200


class OrdersResource(ApiResource):
    """Handles Order requests for Secret creation"""

    def __init__(self, tenant_repo=None, order_repo=None,
                 queue_resource=None):
        LOG.debug('Creating OrdersResource')
        self.tenant_repo = tenant_repo or TenantRepo()
        self.order_repo = order_repo or OrderRepo()
        self.queue = queue_resource or get_queue_api()

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

    def __init__(self, order_repo=None):
        self.repo = order_repo or OrderRepo()

    def on_get(self, req, resp, tenant_id, order_id):
        #TODO: Use a falcon exception here
        order = self.repo.get(entity_id=order_id)
        resp.status = falcon.HTTP_200
        resp.body = json.dumps(order.to_dict_fields(), default=json_handler)

    def on_delete(self, req, resp, tenant_id, order_id):
        order = self.repo.get(entity_id=order_id)

        self.repo.delete_entity(order)

        resp.status = falcon.HTTP_200
