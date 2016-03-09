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
from barbican.common import hrefs
from barbican.common import quota
from barbican.common import resources as res
from barbican.common import utils
from barbican.common import validators
from barbican import i18n as u
from barbican.model import models
from barbican.model import repositories as repo
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


class OrderController(controllers.ACLMixin):

    """Handles Order retrieval and deletion requests."""

    def __init__(self, order, queue_resource=None):
        self.order = order
        self.order_repo = repo.get_order_repository()
        self.queue = queue_resource or async_client.TaskClient()
        self.type_order_validator = validators.TypeOrderValidator()

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Order retrieval'))
    @controllers.enforce_rbac('order:get')
    def on_get(self, external_project_id):
        return hrefs.convert_to_hrefs(self.order.to_dict_fields())

    @index.when(method='PUT')
    @controllers.handle_exceptions(u._('Order update'))
    @controllers.enforce_rbac('order:put')
    @controllers.enforce_content_types(['application/json'])
    def on_put(self, external_project_id, **kwargs):
        body = api.load_body(pecan.request,
                             validator=self.type_order_validator)

        project = res.get_or_create_project(external_project_id)
        order_type = body.get('type')

        request_id = None
        ctxt = controllers._get_barbican_context(pecan.request)
        if ctxt and ctxt.request_id:
            request_id = ctxt.request_id

        if self.order.type != order_type:
            order_cannot_modify_order_type()

        if models.OrderType.CERTIFICATE != self.order.type:
            _order_update_not_supported_for_type(order_type)

        if models.States.PENDING != self.order.status:
            _order_cannot_be_updated_if_not_pending(self.order.status)

        updated_meta = body.get('meta')
        validators.validate_ca_id(project.id, updated_meta)

        # TODO(chellygel): Put 'meta' into a separate order association
        # entity.
        self.queue.update_order(order_id=self.order.id,
                                project_id=external_project_id,
                                updated_meta=updated_meta,
                                request_id=request_id)

    @index.when(method='DELETE')
    @utils.allow_all_content_types
    @controllers.handle_exceptions(u._('Order deletion'))
    @controllers.enforce_rbac('order:delete')
    def on_delete(self, external_project_id, **kwargs):
        self.order_repo.delete_entity_by_id(
            entity_id=self.order.id,
            external_project_id=external_project_id)


class OrdersController(controllers.ACLMixin):
    """Handles Order requests for Secret creation."""

    def __init__(self, queue_resource=None):

        LOG.debug('Creating OrdersController')
        self.order_repo = repo.get_order_repository()
        self.queue = queue_resource or async_client.TaskClient()
        self.type_order_validator = validators.TypeOrderValidator()
        self.quota_enforcer = quota.QuotaEnforcer('orders', self.order_repo)

    @pecan.expose()
    def _lookup(self, order_id, *remainder):
        # NOTE(jaosorior): It's worth noting that even though this section
        # actually does a lookup in the database regardless of the RBAC policy
        # check, the execution only gets here if authentication of the user was
        # previously successful.

        ctx = controllers._get_barbican_context(pecan.request)

        order = self.order_repo.get(entity_id=order_id,
                                    external_project_id=ctx.project,
                                    suppress_exception=True)
        if not order:
            _order_not_found()

        return OrderController(order, self.order_repo), remainder

    @pecan.expose(generic=True)
    def index(self, **kwargs):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Order(s) retrieval'))
    @controllers.enforce_rbac('orders:get')
    def on_get(self, external_project_id, **kw):
        LOG.debug('Start orders on_get '
                  'for project-ID %s:', external_project_id)

        result = self.order_repo.get_by_create_date(
            external_project_id, offset_arg=kw.get('offset', 0),
            limit_arg=kw.get('limit', None), meta_arg=kw.get('meta', None),
            suppress_exception=True)
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

    @index.when(method='PUT', template='json')
    @controllers.handle_exceptions(u._('Order update'))
    @controllers.enforce_rbac('orders:put')
    def on_put(self, external_project_id, **kwargs):
        _order_update_not_supported()

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Order creation'))
    @controllers.enforce_rbac('orders:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id, **kwargs):
        project = res.get_or_create_project(external_project_id)

        body = api.load_body(pecan.request,
                             validator=self.type_order_validator)

        order_type = body.get('type')
        order_meta = body.get('meta')
        request_type = order_meta.get('request_type')

        LOG.debug('Processing order type %s, request type %s',
                  order_type, request_type)

        if order_type == models.OrderType.CERTIFICATE:
            validators.validate_ca_id(project.id, body.get('meta'))
            if request_type == 'stored-key':
                container_ref = order_meta.get('container_ref')
                validators.validate_stored_key_rsa_container(
                    external_project_id,
                    container_ref, pecan.request)

        self.quota_enforcer.enforce(project)

        new_order = models.Order()
        new_order.meta = body.get('meta')
        new_order.type = order_type
        new_order.project_id = project.id

        request_id = None
        ctxt = controllers._get_barbican_context(pecan.request)
        if ctxt:
            new_order.creator_id = ctxt.user
            request_id = ctxt.request_id

        self.order_repo.create_from(new_order)

        # Grab our id before commit due to obj expiration from sqlalchemy
        order_id = new_order.id

        # Force commit to avoid async issues with the workers
        repo.commit()

        self.queue.process_type_order(order_id=order_id,
                                      project_id=external_project_id,
                                      request_id=request_id)

        url = hrefs.convert_order_to_href(order_id)

        pecan.response.status = 202
        pecan.response.headers['Location'] = url

        return {'order_ref': url}
