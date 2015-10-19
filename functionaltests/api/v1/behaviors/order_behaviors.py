"""
Copyright 2014-2015 Rackspace

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
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import order_models


class OrderBehaviors(base_behaviors.BaseBehaviors):

    def create_order(self, model, extra_headers=None, use_auth=True,
                     user_name=None, admin=None):
        """Create an order from the data in the model.

        :param model: The data used to create the order
        :param extra_headers: Optional HTTP headers to add to the request
        :param use_auth: Boolean to determine whether auth headers are sent
        :param user_name: the user used to do the create
        :param admin: the admin of the group to which user_name belongs
        :return: The create response and href for the order
        """

        # create the order
        resp = self.client.post('orders', request_model=model,
                                extra_headers=extra_headers,
                                user_name=user_name, use_auth=use_auth)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None

        returned_data = self.get_json(resp)
        order_ref = returned_data.get('order_ref')

        # remember this order and its admin for our housekeeping cleanup
        if order_ref:
            if admin is None:
                admin = user_name
            self.created_entities.append((order_ref, admin))

        return resp, order_ref

    def get_order(self, order_ref, extra_headers=None, user_name=None,
                  use_auth=True):
        """Get an order from an href.

        :param order_ref: The href for an order
        :param extra_headers: Optional HTTP headers to add to the request
        :param user_name: the user used to do the get
        :param use_auth: Boolean to determine whether auth headers are sent
        :return: The response from the get
        """
        return self.client.get(order_ref,
                               response_model_type=order_models.OrderModel,
                               extra_headers=extra_headers,
                               user_name=user_name, use_auth=use_auth)

    def get_orders(self, limit=10, offset=0, filter=None,
                   extra_headers=None, user_name=None, use_auth=True):
        """Get a list of orders.

        :param limit: limits number of returned orders (default 10)
        :param offset: represents how many records to skip before retrieving
                       the list (default 0)
        :param filter: optional filter to limit the returned orders to
                        those whose metadata contains the filter.
        :param extra_headers: Optional HTTP headers to add to the request
        :param user_name: the user used to do the get
        :param use_auth: Boolean to determine whether auth headers are sent
        :return the response, a list of orders and the next/pref hrefs
        """
        params = {'limit': limit, 'offset': offset}

        if filter:
            params['meta'] = filter

        resp = self.client.get('orders', params=params,
                               extra_headers=extra_headers,
                               user_name=user_name, use_auth=use_auth)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None, None, None

        orders_list = self.get_json(resp)

        orders, next_ref, prev_ref = self.client.get_list_of_models(
            orders_list, order_models.OrderModel)

        return resp, orders, next_ref, prev_ref

    def delete_order(self, order_ref, extra_headers=None, expected_fail=False,
                     user_name=None, use_auth=True):
        """Delete an order.

        :param order_ref: HATEOAS ref of the order to be deleted
        :param extra_headers: Optional HTTP headers to add to the request
        :param expected_fail: Flag telling the delete whether or not this
                              operation is expected to fail (ie coming
                              from a negative test).  We need this to
                              determine whether or not this delete should
                              also remove an entity from our internal
                              list for housekeeping.
        :param user_name: the user used to do the delete
        :param use_auth: Boolean to determine whether auth headers are sent
        :return A request response object
        """
        resp = self.client.delete(order_ref, extra_headers=extra_headers,
                                  user_name=user_name, use_auth=use_auth)

        if not expected_fail:
            for item in self.created_entities:
                if item[0] == order_ref:
                    self.created_entities.remove(item)

        return resp

    def delete_all_created_orders(self):
        """Delete all orders and other entities created by orders.

        """
        container_client = container_behaviors.ContainerBehaviors(self.client)
        secret_client = secret_behaviors.SecretBehaviors(self.client)

        orders_to_delete = [order for order in self.created_entities]

        for (order_ref, admin) in orders_to_delete:
            order_resp = self.get_order(order_ref, user_name=admin)

            # If order has secrets
            if order_resp.model.secret_ref:
                secret_client.delete_secret(order_resp.model.secret_ref,
                                            user_name=admin)

            # If containers supported
            container_attr_exists = getattr(order_resp.model,
                                            "container_ref",
                                            None)
            if container_attr_exists and order_resp.model.container_ref:
                container_resp = container_client.get_container(
                    order_resp.model.container_ref, user_name=admin)
                # remove secrets in the containers in the orders
                if container_resp.model.secret_refs:
                    for secret in container_resp.model.secret_refs:
                        secret_client.delete_secret(secret.secret_ref,
                                                    user_name=admin)

                container_client.delete_container(
                    order_resp.model.container_ref, user_name=admin)

            self.delete_order(order_ref, user_name=admin)
