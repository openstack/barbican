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

from barbican import api
from barbican.api.policy import Enforcer
from barbican.common import resources as res
from barbican.common import utils
from barbican.crypto.mime_types import augment_fields_with_content_types
from barbican.model import models
from barbican.model import repositories as repo
from barbican.common import exception
from barbican.crypto import extension_manager as em
from barbican.openstack.common.gettextutils import _
from barbican.openstack.common import jsonutils as json
from barbican.queue import get_queue_api
from barbican.version import __version__


LOG = utils.getLogger(__name__)


def _general_failure(message, req, resp):
    """Throw exception a general processing failure."""
    api.abort(falcon.HTTP_500, _(message), req, resp)


def _secret_not_found(req, resp):
    """Throw exception indicating secret not found."""
    api.abort(falcon.HTTP_404, _('Unable to locate secret.'), req, resp)


def _order_not_found(req, resp):
    """Throw exception indicating order not found."""
    api.abort(falcon.HTTP_404, _('Unable to locate order.'), req, resp)


def _put_accept_incorrect(ct, req, resp):
    """Throw exception indicating request content-type is not supported."""
    api.abort(falcon.HTTP_415,
              _("Content-Type of '{0}' is not supported.").format(ct),
              req, resp)


def _get_accept_not_supported(accept, req, resp):
    """Throw exception indicating request's accept is not supported."""
    api.abort(falcon.HTTP_406,
              _("Accept of '{0}' is not supported.").format(accept),
              req, resp)


def _get_secret_info_not_found(mime_type, req, resp):
    """Throw exception indicating request's accept is not supported."""
    api.abort(falcon.HTTP_404,
              _("Secret information of type '{0}' not available for "
                "decryption.").format(mime_type),
              req, resp)


def _secret_mime_type_not_supported(mt, req, resp):
    """Throw exception indicating secret mime-type is not supported."""
    api.abort(falcon.HTTP_400,
              _("Mime-type of '{0}' is not supported.").format(mt), req, resp)


def _client_content_mismatch_to_secret(expected, actual, req, res):
    """
    Throw exception indicating client content-type doesn't match
    secret's mime-type.
    """
    api.abort(falcon.HTTP_400,
              _("Request content-type of '{0}' doesn't match "
                "secret's of '{1}'.").format(actual, expected), req, res)


def _secret_data_too_large(req, resp):
    """Throw exception indicating plain-text was too big."""
    api.abort(falcon.HTTP_413,
              _("Could not add secret data as it was too large"), req, resp)


def _secret_plain_text_empty(req, resp):
    """Throw exception indicating empty plain-text was supplied."""
    api.abort(falcon.HTTP_400,
              _("Could not add secret with empty 'plain_text'"), req, resp)


def _failed_to_create_encrypted_datum(req, resp):
    """
    Throw exception we could not create an EncryptedDatum
    record for the secret.
    """
    api.abort(falcon.HTTP_400,
              _("Could not add secret data to Barbican."), req, resp)


def _failed_to_decrypt_data(req, resp):
    """Throw exception if failed to decrypt secret information."""
    api.abort(falcon.HTTP_500,
              _("Problem decrypting secret information."), req, resp)


def _secret_already_has_data(req, resp):
    """
    Throw exception that the secret already has data.
    """
    api.abort(falcon.HTTP_409,
              _("Secret already has data, cannot modify it."), req, resp)


def _secret_not_in_order(req, resp):
    """
    Throw exception that secret information is not available in the order.
    """
    api.abort(falcon.HTTP_400,
              _("Secret metadata expected but not received."), req, resp)


def _secret_create_failed(req, resp):
    """
    Throw exception that secret creation attempt failed.
    """
    api.abort(falcon.HTTP_500, _("Unabled to create secret."), req, resp)


def json_handler(obj):
    """Convert objects into json-friendly equivalents."""
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def convert_secret_to_href(keystone_id, secret_id):
    """Convert the tenant/secret IDs to a HATEOS-style href"""
    if secret_id:
        resource = 'secrets/' + secret_id
    else:
        resource = 'secrets/????'
    return utils.hostname_for_refs(keystone_id=keystone_id, resource=resource)


def convert_order_to_href(keystone_id, order_id):
    """Convert the tenant/order IDs to a HATEOS-style href"""
    if order_id:
        resource = 'orders/' + order_id
    else:
        resource = 'orders/????'
    return utils.hostname_for_refs(keystone_id=keystone_id, resource=resource)


def convert_to_hrefs(keystone_id, fields):
    """Convert id's within a fields dict to HATEOS-style hrefs"""
    if 'secret_id' in fields:
        fields['secret_ref'] = convert_secret_to_href(keystone_id,
                                                      fields['secret_id'])
        del fields['secret_id']
    if 'order_id' in fields:
        fields['order_ref'] = convert_order_to_href(keystone_id,
                                                    fields['order_id'])
        del fields['order_id']
    return fields


def convert_list_to_href(resources_name, keystone_id, offset, limit):
    """
    Convert the tenant ID and offset/limit info to a HATEOS-style href
    suitable for use in a list navigation paging interface.
    """
    resource = '{0}?limit={1}&offset={2}'.format(resources_name, limit,
                                                 offset)
    return utils.hostname_for_refs(keystone_id=keystone_id, resource=resource)


def previous_href(resources_name, keystone_id, offset, limit):
    """
    Create a HATEOS-style 'previous' href suitable for use in a list
    navigation paging interface, assuming the provided values are the
    currently viewed page.
    """
    offset = max(0, offset - limit)
    return convert_list_to_href(resources_name, keystone_id, offset, limit)


def next_href(resources_name, keystone_id, offset, limit):
    """
    Create a HATEOS-style 'next' href suitable for use in a list
    navigation paging interface, assuming the provided values are the
    currently viewed page.
    """
    offset = offset + limit
    return convert_list_to_href(resources_name, keystone_id, offset, limit)


def add_nav_hrefs(resources_name, keystone_id, offset, limit,
                  num_elements, data):
    if offset > 0:
        data.update({'previous': previous_href(resources_name,
                                               keystone_id,
                                               offset,
                                               limit)})
    if num_elements >= limit:
        data.update({'next': next_href(resources_name,
                                       keystone_id,
                                       offset,
                                       limit)})
    return data


class VersionResource(api.ApiResource):
    """Returns service and build version information"""

    def __init__(self, policy_enforcer=None):
        LOG.debug('=== Creating VersionResource ===')
        self.policy = policy_enforcer or Enforcer()

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = json.dumps({'v1': 'current',
                                'build': __version__})


class SecretsResource(api.ApiResource):
    """Handles Secret creation requests."""

    def __init__(self, crypto_manager,
                 tenant_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None,
                 policy_enforcer=None):
        LOG.debug('Creating SecretsResource')
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.secret_repo = secret_repo or repo.SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or repo.TenantSecretRepo()
        self.datum_repo = datum_repo or repo.EncryptedDatumRepo()
        self.crypto_manager = crypto_manager
        self.policy = policy_enforcer or Enforcer()

    def on_post(self, req, resp, keystone_id):
        LOG.debug('Start on_post for tenant-ID {0}:'.format(keystone_id))

        data = api.load_body(req, resp)
        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)

        try:
            new_secret = res.create_secret(data, tenant, self.crypto_manager,
                                           self.secret_repo,
                                           self.tenant_secret_repo,
                                           self.datum_repo)
        except em.CryptoMimeTypeNotSupportedException as cmtnse:
            LOG.exception('Secret creation failed - mime-type not supported')
            _secret_mime_type_not_supported(cmtnse.mime_type, req, resp)
        except exception.NoDataToProcess:
            LOG.exception('No secret data to process')
            _secret_plain_text_empty(req, resp)
        except exception.LimitExceeded:
            LOG.exception('Secret data too big to process')
            _secret_data_too_large(req, resp)
        except Exception as e:
            LOG.exception('Secret creation failed - unknown')
            _general_failure('Secret creation failed - unknown', req, resp)

        resp.status = falcon.HTTP_201
        resp.set_header('Location', '/{0}/secrets/{1}'.format(keystone_id,
                                                              new_secret.id))
        url = convert_secret_to_href(keystone_id, new_secret.id)
        LOG.debug('URI to secret is {0}'.format(url))
        resp.body = json.dumps({'secret_ref': url})

    def on_get(self, req, resp, keystone_id):
        LOG.debug('Start secrets on_get '
                  'for tenant-ID {0}:'.format(keystone_id))

        params = req._params

        result = self.secret_repo \
                     .get_by_create_date(keystone_id,
                                         offset_arg=params.get('offset',
                                                               None),
                                         limit_arg=params.get('limit',
                                                              None),
                                         suppress_exception=True)
        secrets, offset, limit = result

        if not secrets:
            secrets_resp_overall = {'secrets': []}
        else:
            secret_fields = lambda s: augment_fields_with_content_types(s)
            secrets_resp = [convert_to_hrefs(keystone_id, secret_fields(s)) for
                            s in secrets]
            secrets_resp_overall = add_nav_hrefs('secrets', keystone_id,
                                                 offset, limit, len(secrets),
                                                 {'secrets': secrets_resp})

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(secrets_resp_overall,
                               default=json_handler)


class SecretResource(api.ApiResource):
    """Handles Secret retrieval and deletion requests"""

    def __init__(self, crypto_manager,
                 tenant_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None,
                 policy_enforcer=None):
        self.crypto_manager = crypto_manager
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.repo = secret_repo or repo.SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or repo.TenantSecretRepo()
        self.datum_repo = datum_repo or repo.EncryptedDatumRepo()
        self.policy = policy_enforcer or Enforcer()

    def on_get(self, req, resp, keystone_id, secret_id):

        secret = self.repo.get(entity_id=secret_id, keystone_id=keystone_id,
                               suppress_exception=True)
        if not secret:
            _secret_not_found(req, resp)

        resp.status = falcon.HTTP_200

        if not req.accept or req.accept == 'application/json' \
           or req.accept == '*/*':
            # Metadata-only response, no decryption necessary.
            resp.set_header('Content-Type', 'application/json')
            secret_fields = augment_fields_with_content_types(secret)
            resp.body = json.dumps(convert_to_hrefs(keystone_id,
                                                    secret_fields),
                                   default=json_handler)
        else:
            tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)
            resp.set_header('Content-Type', req.accept)
            try:
                resp.body = self.crypto_manager.decrypt(req.accept, secret,
                                                        tenant)
            except em.CryptoAcceptNotSupportedException as canse:
                LOG.exception('Secret decryption failed - '
                              'accept not supported')
                _get_accept_not_supported(canse.accept, req, resp)
            except em.CryptoNoSecretOrDataException as cnsode:
                LOG.exception('Secret information of type {0} not '
                              'found for decryption.'.format(cnsode.mime_type))
                _get_secret_info_not_found(cnsode.mime_type, req, resp)
            except Exception as e:
                LOG.exception('Secret decryption failed - unknown')
                _failed_to_decrypt_data(req, resp)

    def on_put(self, req, resp, keystone_id, secret_id):

        if not req.content_type or req.content_type == 'application/json':
            _put_accept_incorrect(req.content_type, req, resp)

        secret = self.repo.get(entity_id=secret_id, keystone_id=keystone_id,
                               suppress_exception=True)
        if not secret:
            _secret_not_found(req, resp)
        if secret.mime_type != req.content_type:
            _client_content_mismatch_to_secret(secret.mime_type,
                                               req.content_type, req, resp)
        if secret.encrypted_data:
            _secret_already_has_data(req, resp)

        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)

        try:
            plain_text = req.stream.read(api.MAX_BYTES_REQUEST_INPUT_ACCEPTED)
        except IOError:
            api.abort(falcon.HTTP_500, 'Read Error')

        resp.status = falcon.HTTP_200

        try:
            res.create_encrypted_datum(secret,
                                       plain_text,
                                       tenant,
                                       self.crypto_manager,
                                       self.tenant_secret_repo,
                                       self.datum_repo)
        except em.CryptoMimeTypeNotSupportedException as cmtnse:
            LOG.exception('Secret creation failed - mime-type not supported')
            _secret_mime_type_not_supported(cmtnse.mime_type, req, resp)
        except exception.NoDataToProcess:
            LOG.exception('No secret data to process')
            _secret_plain_text_empty(req, resp)
        except exception.LimitExceeded:
            LOG.exception('Secret data too big to process')
            _secret_data_too_large(req, resp)
        except Exception as e:
            LOG.exception('Secret creation failed - unknown')
            _failed_to_create_encrypted_datum(req, resp)

    def on_delete(self, req, resp, keystone_id, secret_id):

        try:
            self.repo.delete_entity_by_id(entity_id=secret_id,
                                          keystone_id=keystone_id)
        except exception.NotFound:
            LOG.exception('Problem deleting secret')
            _secret_not_found(req, resp)

        resp.status = falcon.HTTP_200


class OrdersResource(api.ApiResource):
    """Handles Order requests for Secret creation"""

    def __init__(self, tenant_repo=None, order_repo=None,
                 queue_resource=None, policy_enforcer=None):

        LOG.debug('Creating OrdersResource')
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.order_repo = order_repo or repo.OrderRepo()
        self.queue = queue_resource or get_queue_api()
        self.policy = policy_enforcer or Enforcer()

    def on_post(self, req, resp, keystone_id):

        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)

        body = api.load_body(req, resp)
        LOG.debug('Start on_post...{0}'.format(body))

        if 'secret' not in body:
            _secret_not_in_order(req, resp)
        secret_info = body['secret']
        name = secret_info['name']
        LOG.debug('Secret to create is {0}'.format(name))

        new_order = models.Order()
        new_order.secret_name = secret_info['name']
        new_order.secret_algorithm = secret_info.get('algorithm', None)
        new_order.secret_bit_length = secret_info.get('bit_length', None)
        new_order.secret_cypher_type = secret_info.get('cypher_type', None)
        new_order.secret_mime_type = secret_info['mime_type']
        new_order.secret_expiration = secret_info.get('expiration', None)
        new_order.tenant_id = tenant.id
        self.order_repo.create_from(new_order)

        # Send to workers to process.
        self.queue.process_order(order_id=new_order.id,
                                 keystone_id=keystone_id)

        resp.status = falcon.HTTP_202
        resp.set_header('Location', '/{0}/orders/{1}'.format(keystone_id,
                                                             new_order.id))
        url = convert_order_to_href(keystone_id, new_order.id)
        resp.body = json.dumps({'order_ref': url})

    def on_get(self, req, resp, keystone_id):
        LOG.debug('Start orders on_get '
                  'for tenant-ID {0}:'.format(keystone_id))

        params = req._params

        result = self.order_repo \
                     .get_by_create_date(keystone_id,
                                         offset_arg=params.get('offset',
                                                               None),
                                         limit_arg=params.get('limit',
                                                              None),
                                         suppress_exception=True)
        orders, offset, limit = result

        if not orders:
            orders_resp_overall = {'orders': []}
        else:
            orders_resp = [convert_to_hrefs(keystone_id, o.to_dict_fields())
                           for o in orders]
            orders_resp_overall = add_nav_hrefs('orders', keystone_id,
                                                offset, limit, len(orders),
                                                {'orders': orders_resp})

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(orders_resp_overall,
                               default=json_handler)


class OrderResource(api.ApiResource):
    """Handles Order retrieval and deletion requests"""

    def __init__(self, order_repo=None, policy_enforcer=None):
        self.repo = order_repo or repo.OrderRepo()
        self.policy = policy_enforcer or Enforcer()

    def on_get(self, req, resp, keystone_id, order_id):
        order = self.repo.get(entity_id=order_id, keystone_id=keystone_id,
                              suppress_exception=True)
        if not order:
            _order_not_found(req, resp)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(convert_to_hrefs(keystone_id,
                                                order.to_dict_fields()),
                               default=json_handler)

    def on_delete(self, req, resp, keystone_id, order_id):

        try:
            self.repo.delete_entity_by_id(entity_id=order_id,
                                          keystone_id=keystone_id)
        except exception.NotFound:
            LOG.exception('Problem deleting order')
            _order_not_found(req, resp)

        resp.status = falcon.HTTP_200
