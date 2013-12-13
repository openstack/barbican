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
import urllib
import falcon

from barbican import api
from barbican.common import exception
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican.crypto import mime_types
from barbican.model import models
from barbican.model import repositories as repo
from barbican.openstack.common import gettextutils as u
from barbican.openstack.common import jsonutils as json
from barbican.queue import client as async_client
from barbican import version


LOG = utils.getLogger(__name__)


def _authorization_failed(message, req, resp):
    """Throw exception that authorization failed."""
    api.abort(falcon.HTTP_401, message, req, resp)


def _secret_not_found(req, resp):
    """Throw exception indicating secret not found."""
    api.abort(falcon.HTTP_404, u._('Not Found. Sorry but your secret is in '
                                   'another castle.'), req, resp)


def _order_not_found(req, resp):
    """Throw exception indicating order not found."""
    api.abort(falcon.HTTP_404, u._('Not Found. Sorry but your order is in '
                                   'another castle.'), req, resp)


def _verification_not_found(req, resp):
    """Throw exception indicating verification not found."""
    api.abort(falcon.HTTP_404, u._('Not Found. Sorry but your verification '
                                   'result is in '
                                   'another castle.'), req, resp)


def _put_accept_incorrect(ct, req, resp):
    """Throw exception indicating request content-type is not supported."""
    api.abort(falcon.HTTP_415,
              u._("Content-Type of '{0}' is not "
                  "supported for PUT.").format(ct),
              req, resp)


def _secret_already_has_data(req, resp):
    """Throw exception that the secret already has data."""
    api.abort(falcon.HTTP_409,
              u._("Secret already has data, cannot modify it."), req, resp)


def _secret_not_in_order(req, resp):
    """Throw exception that secret info is not available in the order."""
    api.abort(falcon.HTTP_400,
              u._("Secret metadata expected but not received."), req, resp)


def json_handler(obj):
    """Convert objects into json-friendly equivalents."""
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def convert_secret_to_href(keystone_id, secret_id):
    """Convert the tenant/secret IDs to a HATEOS-style href."""
    if secret_id:
        resource = 'secrets/' + secret_id
    else:
        resource = 'secrets/????'
    return utils.hostname_for_refs(keystone_id=keystone_id, resource=resource)


def convert_verification_to_href(keystone_id, verification_id):
    """Convert the tenant/verification IDs to a HATEOS-style href."""
    if verification_id:
        resource = 'verifications/' + verification_id
    else:
        resource = 'verifications/????'
    return utils.hostname_for_refs(keystone_id=keystone_id, resource=resource)


def convert_order_to_href(keystone_id, order_id):
    """Convert the tenant/order IDs to a HATEOS-style href."""
    if order_id:
        resource = 'orders/' + order_id
    else:
        resource = 'orders/????'
    return utils.hostname_for_refs(keystone_id=keystone_id, resource=resource)


def convert_to_hrefs(keystone_id, fields):
    """Convert id's within a fields dict to HATEOS-style hrefs."""
    if 'secret_id' in fields:
        fields['secret_ref'] = convert_secret_to_href(keystone_id,
                                                      fields['secret_id'])
        del fields['secret_id']
    if 'order_id' in fields:
        fields['order_ref'] = convert_order_to_href(keystone_id,
                                                    fields['order_id'])
        del fields['order_id']
    if 'verification_id' in fields:
        fields['verification_ref'] = \
            convert_verification_to_href(keystone_id,
                                         fields['verification_id'])
        del fields['verification_id']
    return fields


def convert_list_to_href(resources_name, keystone_id, offset, limit):
    """Supports pretty output of paged-list hrefs.

    Convert the tenant ID and offset/limit info to a HATEOS-style href
    suitable for use in a list navigation paging interface.
    """
    resource = '{0}?limit={1}&offset={2}'.format(resources_name, limit,
                                                 offset)
    return utils.hostname_for_refs(keystone_id=keystone_id, resource=resource)


def previous_href(resources_name, keystone_id, offset, limit):
    """Supports pretty output of previous-page hrefs.

    Create a HATEOS-style 'previous' href suitable for use in a list
    navigation paging interface, assuming the provided values are the
    currently viewed page.
    """
    offset = max(0, offset - limit)
    return convert_list_to_href(resources_name, keystone_id, offset, limit)


def next_href(resources_name, keystone_id, offset, limit):
    """Supports pretty output of next-page hrefs.

    Create a HATEOS-style 'next' href suitable for use in a list
    navigation paging interface, assuming the provided values are the
    currently viewed page.
    """
    offset = offset + limit
    return convert_list_to_href(resources_name, keystone_id, offset, limit)


def add_nav_hrefs(resources_name, keystone_id, offset, limit,
                  total_elements, data):
    """Adds next and/or previous hrefs to paged list responses.

    :param resources_name: Name of api resource
    :param keystone_id: Keystone id of the tenant
    :param offset: Element number (ie. index) where current page starts
    :param limit: Max amount of elements listed on current page
    :param num_elements: Total number of elements
    :returns: augmented dictionary with next and/or previous hrefs
    """
    if offset > 0:
        data.update({'previous': previous_href(resources_name,
                                               keystone_id,
                                               offset,
                                               limit)})
    if total_elements > (offset + limit):
        data.update({'next': next_href(resources_name,
                                       keystone_id,
                                       offset,
                                       limit)})
    return data


def is_json_request_accept(req):
    """Test if http request 'accept' header configured for JSON response.

    :param req: HTTP request
    :return: True if need to return JSON response.
    """
    return not req.accept or req.accept == 'application/json' \
        or req.accept == '*/*'


def enforce_rbac(req, resp, action_name, keystone_id=None):
    """Enforce RBAC based on 'request' information."""
    if action_name and 'barbican.context' in req.env:

        # Prepare credentials information.
        ctx = req.env['barbican.context']  # Placed here by context.py
                                           #   middleware
        credentials = {
            'roles': ctx.roles,
            'user': ctx.user,
            'tenant': ctx.tenant,
        }

        # Verify keystone_id matches the tenant ID.
        if keystone_id and keystone_id != ctx.tenant:
            _authorization_failed(u._("URI tenant does not match "
                                      "authenticated tenant."), req, resp)

        # Enforce special case: secret GET decryption
        if 'secret:get' == action_name and not is_json_request_accept(req):
            action_name = 'secret:decrypt'  # Override to perform special rules

        # Enforce access controls.
        ctx.policy_enforcer.enforce(action_name, {}, credentials,
                                    do_raise=True)


def handle_rbac(action_name='default'):
    """Decorator handling RBAC enforcement on behalf of REST verb methods."""

    def rbac_decorator(fn):
        def enforcer(inst, req, resp, *args, **kwargs):

            # Enforce RBAC rules.
            enforce_rbac(req, resp, action_name,
                         keystone_id=kwargs.get('keystone_id'))

            # Execute guarded method now.
            fn(inst, req, resp, *args, **kwargs)

        return enforcer

    return rbac_decorator


def handle_exceptions(operation_name=u._('System')):
    """Decorator handling generic exceptions from REST methods."""

    def exceptions_decorator(fn):

        def handler(inst, req, resp, *args, **kwargs):
            try:
                fn(inst, req, resp, *args, **kwargs)
            except falcon.HTTPError as f:
                LOG.exception('Falcon error seen')
                raise f  # Already converted to Falcon exception, just reraise
            except Exception as e:
                status, message = api.generate_safe_exception_message(
                    operation_name, e)
                LOG.exception(message)
                api.abort(status, message, req, resp)

        return handler

    return exceptions_decorator


class PerformanceResource(api.ApiResource):
    """Supports a static response to support performance testing."""

    def __init__(self):
        LOG.debug('=== Creating PerformanceResource ===')

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = '42'


class VersionResource(api.ApiResource):
    """Returns service and build version information."""

    def __init__(self):
        LOG.debug('=== Creating VersionResource ===')

    @handle_exceptions(u._('Version retrieval'))
    @handle_rbac('version:get')
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = json.dumps({'v1': 'current',
                                'build': version.__version__})


class SecretsResource(api.ApiResource):
    """Handles Secret creation requests."""

    def __init__(self, crypto_manager,
                 tenant_repo=None, secret_repo=None,
                 tenant_secret_repo=None, datum_repo=None, kek_repo=None):
        LOG.debug('Creating SecretsResource')
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.secret_repo = secret_repo or repo.SecretRepo()
        self.tenant_secret_repo = tenant_secret_repo or repo.TenantSecretRepo()
        self.datum_repo = datum_repo or repo.EncryptedDatumRepo()
        self.kek_repo = kek_repo or repo.KEKDatumRepo()
        self.crypto_manager = crypto_manager
        self.validator = validators.NewSecretValidator()

    @handle_exceptions(u._('Secret creation'))
    @handle_rbac('secrets:post')
    def on_post(self, req, resp, keystone_id):
        LOG.debug('Start on_post for tenant-ID {0}:...'.format(keystone_id))

        data = api.load_body(req, resp, self.validator)
        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)

        new_secret = res.create_secret(data, tenant, self.crypto_manager,
                                       self.secret_repo,
                                       self.tenant_secret_repo,
                                       self.datum_repo,
                                       self.kek_repo)

        resp.status = falcon.HTTP_201
        resp.set_header('Location', '/{0}/secrets/{1}'.format(keystone_id,
                                                              new_secret.id))
        url = convert_secret_to_href(keystone_id, new_secret.id)
        LOG.debug('URI to secret is {0}'.format(url))
        resp.body = json.dumps({'secret_ref': url})

    @handle_exceptions(u._('Secret(s) retrieval'))
    @handle_rbac('secrets:get')
    def on_get(self, req, resp, keystone_id):
        LOG.debug('Start secrets on_get '
                  'for tenant-ID {0}:'.format(keystone_id))

        name = req.get_param('name')
        if name:
            name = urllib.unquote_plus(name)

        result = self.secret_repo.get_by_create_date(
            keystone_id,
            offset_arg=req.get_param('offset'),
            limit_arg=req.get_param('limit'),
            name=name,
            alg=req.get_param('alg'),
            mode=req.get_param('mode'),
            bits=req.get_param('bits'),
            suppress_exception=True
        )

        secrets, offset, limit, total = result

        if not secrets:
            secrets_resp_overall = {'secrets': [],
                                    'total': total}
        else:
            secret_fields = lambda s: mime_types\
                .augment_fields_with_content_types(s)
            secrets_resp = [convert_to_hrefs(keystone_id, secret_fields(s)) for
                            s in secrets]
            secrets_resp_overall = add_nav_hrefs('secrets', keystone_id,
                                                 offset, limit, total,
                                                 {'secrets': secrets_resp})
            secrets_resp_overall.update({'total': total})

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(secrets_resp_overall,
                               default=json_handler)


class SecretResource(api.ApiResource):
    """Handles Secret retrieval and deletion requests."""

    def __init__(self, crypto_manager,
                 tenant_repo=None, secret_repo=None, datum_repo=None,
                 kek_repo=None):
        self.crypto_manager = crypto_manager
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.repo = secret_repo or repo.SecretRepo()
        self.datum_repo = datum_repo or repo.EncryptedDatumRepo()
        self.kek_repo = kek_repo or repo.KEKDatumRepo()

    @handle_exceptions(u._('Secret retrieval'))
    @handle_rbac('secret:get')
    def on_get(self, req, resp, keystone_id, secret_id):

        secret = self.repo.get(entity_id=secret_id, keystone_id=keystone_id,
                               suppress_exception=True)
        if not secret:
            _secret_not_found(req, resp)

        resp.status = falcon.HTTP_200

        if is_json_request_accept(req):
            # Metadata-only response, no decryption necessary.
            resp.set_header('Content-Type', 'application/json')
            secret_fields = mime_types.augment_fields_with_content_types(
                secret)
            resp.body = json.dumps(convert_to_hrefs(keystone_id,
                                                    secret_fields),
                                   default=json_handler)
        else:
            tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)
            resp.set_header('Content-Type', req.accept)

            resp.body = self.crypto_manager \
                            .decrypt(req.accept,
                                     secret,
                                     tenant)

    @handle_exceptions(u._('Secret update'))
    @handle_rbac('secret:put')
    def on_put(self, req, resp, keystone_id, secret_id):

        if not req.content_type or req.content_type == 'application/json':
            _put_accept_incorrect(req.content_type, req, resp)

        secret = self.repo.get(entity_id=secret_id, keystone_id=keystone_id,
                               suppress_exception=True)
        if not secret:
            _secret_not_found(req, resp)

        if secret.encrypted_data:
            _secret_already_has_data(req, resp)

        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)
        payload = None
        content_type = req.content_type
        content_encoding = req.get_header('Content-Encoding')

        try:
            payload = req.stream.read(api.MAX_BYTES_REQUEST_INPUT_ACCEPTED)
        except IOError:
            api.abort(falcon.HTTP_500, 'Read Error')

        res.create_encrypted_datum(secret,
                                   payload,
                                   content_type,
                                   content_encoding,
                                   tenant,
                                   self.crypto_manager,
                                   self.datum_repo,
                                   self.kek_repo)

        resp.status = falcon.HTTP_200

    @handle_exceptions(u._('Secret deletion'))
    @handle_rbac('secret:delete')
    def on_delete(self, req, resp, keystone_id, secret_id):

        try:
            self.repo.delete_entity_by_id(entity_id=secret_id,
                                          keystone_id=keystone_id)
        except exception.NotFound:
            LOG.exception('Problem deleting secret')
            _secret_not_found(req, resp)

        resp.status = falcon.HTTP_200


class OrdersResource(api.ApiResource):
    """Handles Order requests for Secret creation."""

    def __init__(self, tenant_repo=None, order_repo=None,
                 queue_resource=None):

        LOG.debug('Creating OrdersResource')
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.order_repo = order_repo or repo.OrderRepo()
        self.queue = queue_resource or async_client.TaskClient()
        self.validator = validators.NewOrderValidator()

    @handle_exceptions(u._('Order creation'))
    @handle_rbac('orders:post')
    def on_post(self, req, resp, keystone_id):

        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)

        body = api.load_body(req, resp, self.validator)
        LOG.debug('Start on_post...{0}'.format(body))

        if 'secret' not in body:
            _secret_not_in_order(req, resp)
        secret_info = body['secret']
        name = secret_info.get('name')
        LOG.debug('Secret to create is {0}'.format(name))

        new_order = models.Order()
        new_order.secret_name = secret_info.get('name')
        new_order.secret_algorithm = secret_info.get('algorithm')
        new_order.secret_bit_length = secret_info.get('bit_length', 0)
        new_order.secret_mode = secret_info.get('mode')
        new_order.secret_payload_content_type = secret_info.get(
            'payload_content_type')

        new_order.secret_expiration = secret_info.get('expiration')
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

    @handle_exceptions(u._('Order(s) retrieval'))
    @handle_rbac('orders:get')
    def on_get(self, req, resp, keystone_id):
        LOG.debug('Start orders on_get '
                  'for tenant-ID {0}:'.format(keystone_id))

        result = self.order_repo \
            .get_by_create_date(keystone_id,
                                offset_arg=req.get_param('offset'),
                                limit_arg=req.get_param('limit'),
                                suppress_exception=True)
        orders, offset, limit, total = result

        if not orders:
            orders_resp_overall = {'orders': [],
                                   'total': total}
        else:
            orders_resp = [convert_to_hrefs(keystone_id, o.to_dict_fields())
                           for o in orders]
            orders_resp_overall = add_nav_hrefs('orders', keystone_id,
                                                offset, limit, total,
                                                {'orders': orders_resp})
            orders_resp_overall.update({'total': total})

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(orders_resp_overall,
                               default=json_handler)


class OrderResource(api.ApiResource):
    """Handles Order retrieval and deletion requests."""

    def __init__(self, order_repo=None):
        self.repo = order_repo or repo.OrderRepo()

    @handle_exceptions(u._('Order retrieval'))
    @handle_rbac('order:get')
    def on_get(self, req, resp, keystone_id, order_id):
        order = self.repo.get(entity_id=order_id, keystone_id=keystone_id,
                              suppress_exception=True)
        if not order:
            _order_not_found(req, resp)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(convert_to_hrefs(keystone_id,
                                                order.to_dict_fields()),
                               default=json_handler)

    @handle_exceptions(u._('Order deletion'))
    @handle_rbac('order:delete')
    def on_delete(self, req, resp, keystone_id, order_id):

        try:
            self.repo.delete_entity_by_id(entity_id=order_id,
                                          keystone_id=keystone_id)
        except exception.NotFound:
            LOG.exception('Problem deleting order')
            _order_not_found(req, resp)

        resp.status = falcon.HTTP_200


class VerificationsResource(api.ApiResource):
    """Handles Verification creation requests.

    Creating a verification entity initiates verification processing
    on a target resource. The results of this verification processing
    can be monitored via this entity.
    """

    def __init__(self, tenant_repo=None, verification_repo=None,
                 queue_resource=None):
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.verification_repo = verification_repo or repo.VerificationRepo()
        self.validator = validators.VerificationValidator()
        self.queue = queue_resource or async_client.TaskClient()

    @handle_exceptions(u._('Verification creation'))
    @handle_rbac('verifications:post')
    def on_post(self, req, resp, keystone_id):
        LOG.debug('Start on_post for tenant-ID {0}:...'.format(keystone_id))

        data = api.load_body(req, resp, self.validator)
        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)

        new_verification = models.Verification(data)
        new_verification.tenant_id = tenant.id
        self.verification_repo.create_from(new_verification)

        # Send to workers to process.
        self.queue.process_verification(verification_id=new_verification.id,
                                        keystone_id=keystone_id)

        resp.status = falcon.HTTP_202
        resp.set_header('Location',
                        '/{0}/verifications/{1}'.format(keystone_id,
                                                        new_verification.id))
        url = convert_verification_to_href(keystone_id, new_verification.id)
        LOG.debug('URI to verification is {0}'.format(url))
        resp.body = json.dumps({'verification_ref': url})

    @handle_exceptions(u._('Verification(s) retrieval'))
    @handle_rbac('verifications:get')
    def on_get(self, req, resp, keystone_id):
        LOG.debug('Start verifications on_get '
                  'for tenant-ID {0}:'.format(keystone_id))

        result = self.verification_repo.get_by_create_date(
            keystone_id,
            offset_arg=req.get_param('offset'),
            limit_arg=req.get_param('limit'),
            suppress_exception=True
        )

        verifications, offset, limit, total = result

        if not verifications:
            resp_verif_overall = {'verifications': [], 'total': total}
        else:
            resp_verif = [convert_to_hrefs(keystone_id,
                                           v.to_dict_fields()) for
                          v in verifications]
            resp_verif_overall = add_nav_hrefs('verifications', keystone_id,
                                               offset, limit, total,
                                               {'verifications': resp_verif})
            resp_verif_overall.update({'total': total})

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(resp_verif_overall,
                               default=json_handler)


class VerificationResource(api.ApiResource):
    """Handles Verification entity retrieval and deletion requests."""

    def __init__(self, verification_repo=None):
        self.repo = verification_repo or repo.VerificationRepo()

    @handle_exceptions(u._('Verification retrieval'))
    @handle_rbac('verification:get')
    def on_get(self, req, resp, keystone_id, verification_id):
        verif = self.repo.get(entity_id=verification_id,
                              keystone_id=keystone_id,
                              suppress_exception=True)
        if not verif:
            _verification_not_found(req, resp)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(convert_to_hrefs(keystone_id,
                                                verif.to_dict_fields()),
                               default=json_handler)

    @handle_exceptions(u._('Verification deletion'))
    @handle_rbac('verification:delete')
    def on_delete(self, req, resp, keystone_id, verification_id):

        try:
            self.repo.delete_entity_by_id(entity_id=verification_id,
                                          keystone_id=keystone_id)
        except exception.NotFound:
            _verification_not_found(req, resp)

        resp.status = falcon.HTTP_200
