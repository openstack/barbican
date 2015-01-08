"""
Copyright 2014 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from functionaltests.api.v1.behaviors import base_behaviors
from functionaltests.api.v1.models import order_models


class OrderBehaviors(base_behaviors.BaseBehaviors):

    def create_order(self, model, extra_headers=None):
        """Create an order from the data in the model.

        :param model: The data used to create the order
        :param extra_headers: Optional HTTP headers to add to the request
        :return: The create response and href for the order
        """

        # create the order
        resp = self.client.post('orders', request_model=model,
                                extra_headers=extra_headers)

        returned_data = self.get_json(resp)
        order_ref = returned_data.get('order_ref')

        # remember this order for our housekeeping cleanup
        if order_ref:
            self.created_entities.append(order_ref)

        return resp, order_ref

    def get_order(self, order_ref, extra_headers=None):
        """Get an order from an href.

        :param order_ref: The href for an order
        :param extra_headers: Optional HTTP headers to add to the request
        :return: The response from the get
        """
        return self.client.get(order_ref,
                               response_model_type=order_models.OrderModel,
                               extra_headers=extra_headers)

    def get_orders(self, limit=10, offset=0, extra_headers=None):
        """Get a list of orders.

        :param limit: limits number of returned orders (default 10)
        :param offset: represents how many records to skip before retrieving
                       the list (default 0)
        :param extra_headers: Optional HTTP headers to add to the request
        :return the response, a list of orders and the next/pref hrefs
        """
        resp = self.client.get('orders',
                               params={'limit': limit, 'offset': offset},
                               extra_headers=extra_headers)

        orders_list = self.get_json(resp)

        orders, next_ref, prev_ref = self.client.get_list_of_models(
            orders_list, order_models.OrderModel)

        return resp, orders, next_ref, prev_ref

    def delete_order(self, order_ref, extra_headers=None, expected_fail=False):
        """Delete an order.

        :param order_ref: HATEOS ref of the order to be deleted
        :param extra_headers: Optional HTTP headers to add to the request
        :param expected_fail: Flag telling the delete whether or not this
                              operation is expected to fail (ie coming
                              from a negative test).  We need this to
                              determine whether or not this delete should
                              also remove an entity from our internal
                              list for housekeeping.
        :return A request response object
        """
        resp = self.client.delete(order_ref, extra_headers=extra_headers)
        if not expected_fail:
            self.created_entities.remove(order_ref)
        return resp

    def delete_all_created_orders(self):
        """Delete all of the orders that we have created."""
        orders_to_delete = [order for order in self.created_entities]
        for order_ref in orders_to_delete:
            self.delete_order(order_ref)
