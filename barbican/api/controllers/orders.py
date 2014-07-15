#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import pecan

from barbican import api
from barbican.api import controllers
from barbican.api.controllers import hrefs
from barbican.common import exception
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican.model import models
from barbican.model import repositories as repo
from barbican.openstack.common import gettextutils as u
from barbican.queue import client as async_client

LOG = utils.getLogger(__name__)


def _order_not_found():
    """Throw exception indicating order not found."""
    pecan.abort(404, u._('Not Found. Sorry but your order is in '
                         'another castle.'))


def _secret_not_in_order():
    """Throw exception that secret info is not available in the order."""
    pecan.abort(400, u._("Secret metadata expected but not received."))


def _order_update_not_supported():
    """Throw exception that PUT operation is not supported for orders."""
    pecan.abort(405, u._("Order update is not supported."))


class OrderController(object):

    """Handles Order retrieval and deletion requests."""

    def __init__(self, order_id, order_repo=None):
        self.order_id = order_id
        self.repo = order_repo or repo.OrderRepo()

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Order retrieval'))
    @controllers.enforce_rbac('order:get')
    def index(self, keystone_id):
        order = self.repo.get(entity_id=self.order_id, keystone_id=keystone_id,
                              suppress_exception=True)
        if not order:
            _order_not_found()

        return hrefs.convert_to_hrefs(keystone_id, order.to_dict_fields())

    @index.when(method='PUT')
    @controllers.handle_exceptions(u._('Order update'))
    def on_put(self, keystone_id, **kwargs):
        _order_update_not_supported()

    @index.when(method='DELETE')
    @controllers.handle_exceptions(u._('Order deletion'))
    @controllers.enforce_rbac('order:delete')
    def on_delete(self, keystone_id, **kwargs):

        try:
            self.repo.delete_entity_by_id(entity_id=self.order_id,
                                          keystone_id=keystone_id)
        except exception.NotFound:
            LOG.exception('Problem deleting order')
            _order_not_found()


class OrdersController(object):
    """Handles Order requests for Secret creation."""

    def __init__(self, tenant_repo=None, order_repo=None,
                 queue_resource=None):

        LOG.debug('Creating OrdersController')
        self.tenant_repo = tenant_repo or repo.TenantRepo()
        self.order_repo = order_repo or repo.OrderRepo()
        self.queue = queue_resource or async_client.TaskClient()
        self.validator = validators.NewOrderValidator()

    @pecan.expose()
    def _lookup(self, order_id, *remainder):
        return OrderController(order_id, self.order_repo), remainder

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Order(s) retrieval'))
    @controllers.enforce_rbac('orders:get')
    def index(self, keystone_id, **kw):
        LOG.debug('Start orders on_get '
                  'for tenant-ID {0}:'.format(keystone_id))

        result = self.order_repo \
            .get_by_create_date(keystone_id,
                                offset_arg=kw.get('offset', 0),
                                limit_arg=kw.get('limit', None),
                                suppress_exception=True)
        orders, offset, limit, total = result

        if not orders:
            orders_resp_overall = {'orders': [],
                                   'total': total}
        else:
            orders_resp = [
                hrefs.convert_to_hrefs(keystone_id, o.to_dict_fields())
                for o in orders
            ]
            orders_resp_overall = hrefs.add_nav_hrefs('orders', keystone_id,
                                                      offset, limit, total,
                                                      {'orders': orders_resp})
            orders_resp_overall.update({'total': total})

        return orders_resp_overall

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Order update'))
    @controllers.enforce_rbac('orders:put')
    def on_put(self, keystone_id, **kwargs):
        _order_update_not_supported()

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Order creation'))
    @controllers.enforce_rbac('orders:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, keystone_id, **kwargs):

        tenant = res.get_or_create_tenant(keystone_id, self.tenant_repo)

        body = api.load_body(pecan.request, validator=self.validator)
        LOG.debug('Start on_post...{0}'.format(body))

        if 'secret' not in body:
            _secret_not_in_order()
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

        pecan.response.status = 202
        pecan.response.headers['Location'] = '/{0}/orders/{1}'.format(
            keystone_id, new_order.id
        )
        url = hrefs.convert_order_to_href(keystone_id, new_order.id)
        return {'order_ref': url}
