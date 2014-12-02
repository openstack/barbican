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
from barbican.common import exception
from barbican.common import hrefs
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
from barbican.openstack.common import jsonutils as json
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


def _order_type_not_in_order():
    """Throw exception that order type is not available in the order."""
    pecan.abort(400, u._("Order type is expected but not received."))


def _order_meta_not_in_update():
    """Throw exception that order meta is not available for an order update."""
    pecan.abort(400, u._("Order meta is expected for order updates."))


def _order_update_not_supported_for_type(order_type):
    """Throw exception that update is not supported."""
    pecan.abort(400, u._("Updates are not supported for order type "
                         "{0}.").format(order_type))


def _order_cannot_be_updated_if_not_pending(order_status):
    """Throw exception that order cannot be updated if not PENDING."""
    pecan.abort(400, u._("Only PENDING orders can be updated. Order is in the"
                         "{0} state.").format(order_status))


def order_cannot_modify_order_type():
    """Throw exception that order type cannot be modified."""
    pecan.abort(400, u._("Cannot modify order type."))


class OrderController(object):

    """Handles Order retrieval and deletion requests."""

    def __init__(self, order_id, order_repo=None,
                 queue_resource=None):
        self.order_id = order_id
        self.order_repo = order_repo or repo.OrderRepo()
        self.queue = queue_resource or async_client.TaskClient()
        self.type_order_validator = validators.TypeOrderValidator()

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Order retrieval'))
    @controllers.enforce_rbac('order:get')
    def index(self, keystone_id):
        order = self.order_repo.get(entity_id=self.order_id,
                                    keystone_id=keystone_id,
                                    suppress_exception=True)
        if not order:
            _order_not_found()

        return hrefs.convert_to_hrefs(order.to_dict_fields())

    @index.when(method='PUT')
    @controllers.handle_exceptions(u._('Order update'))
    @controllers.enforce_rbac('order:put')
    @controllers.enforce_content_types(['application/json'])
    def on_put(self, keystone_id, **kwargs):
        raw_body = pecan.request.body
        order_type = None
        if raw_body:
            order_type = json.loads(raw_body).get('type')

        if not order_type:
            _order_type_not_in_order()

        order_model = self.order_repo.get(entity_id=self.order_id,
                                          keystone_id=keystone_id,
                                          suppress_exception=True)

        if not order_model:
            _order_not_found()

        if order_model.type != order_type:
            order_cannot_modify_order_type()

        if models.OrderType.CERTIFICATE != order_model.type:
            _order_update_not_supported_for_type(order_type)

        if models.States.PENDING != order_model.status:
            _order_cannot_be_updated_if_not_pending(order_model.status)

        body = api.load_body(pecan.request,
                             validator=self.type_order_validator)

        updated_meta = body.get('meta')

        if not updated_meta:
            _order_meta_not_in_update()

        # TODO(chellygel): Put updated_meta into a separate order association
        # entity.
        self.queue.update_order(order_id=self.order_id,
                                keystone_id=keystone_id,
                                updated_meta=updated_meta)

    @index.when(method='DELETE')
    @controllers.handle_exceptions(u._('Order deletion'))
    @controllers.enforce_rbac('order:delete')
    def on_delete(self, keystone_id, **kwargs):

        try:
            self.order_repo.delete_entity_by_id(entity_id=self.order_id,
                                                keystone_id=keystone_id)
        except exception.NotFound:
            LOG.exception(u._LE('Problem deleting order'))
            _order_not_found()


class OrdersController(object):
    """Handles Order requests for Secret creation."""

    def __init__(self, project_repo=None, order_repo=None,
                 queue_resource=None):

        LOG.debug('Creating OrdersController')
        self.project_repo = project_repo or repo.ProjectRepo()
        self.order_repo = order_repo or repo.OrderRepo()
        self.queue = queue_resource or async_client.TaskClient()
        self.type_order_validator = validators.TypeOrderValidator()

    @pecan.expose()
    def _lookup(self, order_id, *remainder):
        return OrderController(order_id, self.order_repo), remainder

    @pecan.expose(generic=True, template='json')
    @controllers.handle_exceptions(u._('Order(s) retrieval'))
    @controllers.enforce_rbac('orders:get')
    def index(self, keystone_id, **kw):
        LOG.debug('Start orders on_get '
                  'for project-ID %s:', keystone_id)

        result = self.order_repo.get_by_create_date(
            keystone_id, offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit', None), suppress_exception=True)
        orders, offset, limit, total = result

        if not orders:
            orders_resp_overall = {'orders': [],
                                   'total': total}
        else:
            orders_resp = [
                hrefs.convert_to_hrefs(o.to_dict_fields())
                for o in orders
            ]
            orders_resp_overall = hrefs.add_nav_hrefs('orders',
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

        project = res.get_or_create_project(keystone_id, self.project_repo)

        body = api.load_body(pecan.request,
                             validator=self.type_order_validator)
        order_type = body.get('type')
        LOG.debug('Processing order type %s', order_type)

        new_order = models.Order()
        new_order.meta = body.get('meta')
        new_order.type = order_type
        new_order.tenant_id = project.id

        self.order_repo.create_from(new_order)

        self.queue.process_type_order(order_id=new_order.id,
                                      keystone_id=keystone_id)
        pecan.response.status = 202
        pecan.response.headers['Location'] = '/{0}/orders/{1}'.format(
            keystone_id, new_order.id
        )
        url = hrefs.convert_order_to_href(new_order.id)
        return {'order_ref': url}
