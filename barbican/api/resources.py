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

from barbican.api import ApiResource, load_body, abort
from barbican.common.resources import (create_secret,
                                       create_encrypted_datum,
                                       get_or_create_tenant)
from barbican.common import utils
from barbican.crypto.extension_manager import (
    CryptoMimeTypeNotSupportedException
)
from barbican.crypto.mime_types import augment_fields_with_content_types
from barbican.model.models import (Tenant, Secret, TenantSecret,
                                   EncryptedDatum, Order, States)
from barbican.model.repositories import (TenantRepo, SecretRepo,
                                         OrderRepo, TenantSecretRepo,
                                         EncryptedDatumRepo)
from barbican.openstack.common.gettextutils import _
from barbican.openstack.common import jsonutils as json
from barbican.queue import get_queue_api
from barbican.version import __version__


LOG = utils.getLogger(__name__)


def _secret_not_found():
    """Throw exception indicating secret not found."""
    abort(falcon.HTTP_400, _('Unable to locate secret profile.'))


def _put_accept_incorrect(ct):
    """Throw exception indicating request content-type is not supported."""
    abort(falcon.HTTP_415, _("Content-Type of '{0}' "
          "is not supported.").format(ct))


def _client_content_mismatch_to_secret():
    """
    Throw exception indicating client content-type doesn't match
    secret's mime-type.
    """
    abort(falcon.HTTP_400, _("Request content-type doesn't match secret's."))


def _failed_to_create_encrypted_datum():
    """
    Throw exception we could not create an EncryptedDatum
    record for the secret.
    """
    abort(falcon.HTTP_400, _("Could not add secret data to Barbican."))


def _secret_already_has_data():
    """
    Throw exception that the secret already has data.
    """
    abort(falcon.HTTP_409, _("Secret already has data, cannot modify it."))


def _secret_not_in_order():
    """
    Throw exception that secret information is not available in the order.
    """
    abort(falcon.HTTP_400, _("Secret metadata expected but not received."))


def json_handler(obj):
    """Convert objects into json-friendly equivalents."""
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def convert_secret_to_href(tenant_id, secret_id):
    """Convert the tenant/secret IDs to a HATEOS-style href"""
    if secret_id:
        resource = 'secrets/' + secret_id
    else:
        resource = 'secrets/????'
    return utils.hostname_for_refs(tenant_id=tenant_id, resource=resource)


def convert_order_to_href(tenant_id, order_id):
    """Convert the tenant/order IDs to a HATEOS-style href"""
    if order_id:
        resource = 'orders/' + order_id
    else:
        resource = 'orders/????'
    return utils.hostname_for_refs(tenant_id=tenant_id, resource=resource)


def convert_to_hrefs(tenant_id, fields):
    """Convert id's within a fields dict to HATEOS-style hrefs"""
    if 'secret_id' in fields:
        fields['secret_ref'] = convert_secret_to_href(tenant_id,
                                                      fields['secret_id'])
        del fields['secret_id']
    return fields


class VersionResource(ApiResource):
    """Returns service and build version information"""

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = json.dumps({'v1': 'current',
                                'build': __version__})


class SecretsResource(ApiResource):
    """Handles Secret creation requests."""

    def __init__(self, crypto_manager,
                 tenant_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None):
        LOG.debug('Creating SecretsResource')
        self.tenant_repo = tenant_repo or TenantRepo()
        self.secret_repo = secret_repo or SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or TenantSecretRepo()
        self.datum_repo = datum_repo or EncryptedDatumRepo()
        self.crypto_manager = crypto_manager

    def on_post(self, req, resp, tenant_id):
        LOG.debug('Start on_post for tenant-ID {0}:'.format(tenant_id))

        data = load_body(req)
        tenant = get_or_create_tenant(tenant_id, self.tenant_repo)

        new_secret = create_secret(data, tenant, self.crypto_manager,
                                   self.secret_repo, self.tenant_secret_repo,
                                   self.datum_repo)

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/secrets/{1}'.format(tenant_id,
                                                              new_secret.id))
        url = convert_secret_to_href(tenant_id, new_secret.id)
        LOG.debug('URI to secret is {0}'.format(url))
        resp.body = json.dumps({'secret_ref': url})


class SecretResource(ApiResource):
    """Handles Secret retrieval and deletion requests"""

    def __init__(self, crypto_manager, tenant_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None):
        self.crypto_manager = crypto_manager
        self.tenant_repo = tenant_repo or TenantRepo()
        self.repo = secret_repo or SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or TenantSecretRepo()
        self.datum_repo = datum_repo or EncryptedDatumRepo()

    def on_get(self, req, resp, tenant_id, secret_id):

        secret = self.repo.get(entity_id=secret_id, suppress_exception=True)
        if not secret:
            _secret_not_found()

        resp.status = falcon.HTTP_200

        if not req.accept or req.accept == 'application/json':
            # Metadata-only response, no decryption necessary.
            resp.set_header('Content-Type', 'application/json')
            resp.body = json.dumps(augment_fields_with_content_types(secret),
                                   default=json_handler)
        else:
            tenant = get_or_create_tenant(tenant_id, self.tenant_repo)
            resp.set_header('Content-Type', req.accept)
            resp.body = self.crypto_manager.decrypt(req.accept, secret, tenant)

    def on_put(self, req, resp, tenant_id, secret_id):

        if not req.content_type or req.content_type == 'application/json':
            _put_accept_incorrect(req.content_type)

        secret = self.repo.get(entity_id=secret_id, suppress_exception=True)
        if not secret:
            _secret_not_found()
        if secret.mime_type != req.content_type:
            _client_content_mismatch_to_secret()
        if secret.encrypted_data:
            _secret_already_has_data()

        try:
            plain_text = req.stream.read()
        except IOError:
            abort(falcon.HTTP_500, 'Read Error')

        resp.status = falcon.HTTP_200

        try:
            create_encrypted_datum(secret,
                                   plain_text,
                                   tenant_id,
                                   self.crypto_manager,
                                   self.tenant_secret_repo,
                                   self.datum_repo)
        except ValueError:
            LOG.error('Problem creating an encrypted datum for the secret.',
                      exc_info=True)
            _failed_to_create_encrypted_datum()

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

        if 'secret' not in body:
            _secret_not_in_order()
        secret_info = body['secret']
        name = secret_info['name']
        LOG.debug('Secret to create is {0}'.format(name))

        # TODO: What criteria to restrict multiple concurrent Order
        #      requests per tenant?
        # order = self.order_repo.find_by_name(name=secret_name,
        #                                  suppress_exception=True)
        # if order:
        #    abort(falcon.HTTP_400, 'Order with username {0} '
        #                           'already exists'.format(username))

        # TODO: Encrypt fields as needed

        new_order = Order()
        new_order.secret_name = secret_info['name']
        new_order.secret_algorithm = secret_info.get('algorithm', None)
        new_order.secret_bit_length = secret_info.get('bit_length', None)
        new_order.secret_cypher_type = secret_info.get('cypher_type', None)
        new_order.secret_mime_type = secret_info['mime_type']
        new_order.secret_expiration = secret_info.get('expiration', None)

        new_order.tenant_id = tenant.id
        self.order_repo.create_from(new_order)

        # Send to workers to process.
        self.queue.process_order(order_id=new_order.id)

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/orders/{1}'.format(tenant_id,
                                                             new_order.id))
        url = convert_order_to_href(tenant_id, new_order.id)
        resp.body = json.dumps({'order_ref': url})


class OrderResource(ApiResource):
    """Handles Order retrieval and deletion requests"""

    def __init__(self, order_repo=None):
        self.repo = order_repo or OrderRepo()

    def on_get(self, req, resp, tenant_id, order_id):
        #TODO: Use a falcon exception here
        order = self.repo.get(entity_id=order_id)
        resp.status = falcon.HTTP_200
        resp.body = json.dumps(convert_to_hrefs(order.tenant_id,
                                                order.to_dict_fields()),
                               default=json_handler)

    def on_delete(self, req, resp, tenant_id, order_id):
        order = self.repo.get(entity_id=order_id)

        self.repo.delete_entity(order)

        resp.status = falcon.HTTP_200
