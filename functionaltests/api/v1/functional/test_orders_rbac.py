# Copyright (c) 2015 Rackspace
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

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.models import order_models
from functionaltests.common import config


CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
creator_a = CONF.rbac_users.creator_a
observer_a = CONF.rbac_users.observer_a
auditor_a = CONF.rbac_users.auditor_a


test_data_rbac_create_order = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 202},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 202},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}


test_data_rbac_get_order = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 200},
}


test_data_rbac_get_list_of_orders = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}

test_data_rbac_delete_order = {
    'with_admin_a': {'user': admin_a, 'admin': admin_a,
                     'expected_return': 204},
    'with_creator_a': {'user': creator_a, 'admin': admin_a,
                       'expected_return': 403},
    'with_observer_a': {'user': observer_a, 'admin': admin_a,
                        'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'admin': admin_a,
                       'expected_return': 403},
}


def get_default_order_data():
    return {'type': 'key',
            "meta": {
                "name": "barbican functional test order name",
                "algorithm": "aes",
                "bit_length": 256,
                "mode": "cbc",
            }
            }


@utils.parameterized_test_case
class RBACOrdersTestCase(base.TestCase):
    """Functional tests exercising RBAC Policies"""
    def setUp(self):
        super(RBACOrdersTestCase, self).setUp()
        self.order_behaviors = order_behaviors.OrderBehaviors(self.client)

    def tearDown(self):
        self.order_behaviors.delete_all_created_orders()
        super(RBACOrdersTestCase, self).tearDown()

    @utils.parameterized_dataset(test_data_rbac_create_order)
    def test_rbac_create_order(self, user, admin, expected_return):
        """Test RBAC for order creation

        Issue an order creation and verify that the correct
        http return code comes back for the specified user.

        :param user: the user who will attempt to do the create
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        test_model = order_models.OrderModel(**get_default_order_data())
        resp, order_ref = self.order_behaviors.create_order(test_model,
                                                            user_name=user,
                                                            admin=admin)
        self.assertEqual(expected_return, resp.status_code)
        self.assertEqual(expected_return == 202, order_ref is not None)

    @utils.parameterized_dataset(test_data_rbac_get_order)
    def test_rbac_get_order(self, user, admin, expected_return):
        """Test RBAC for order get metadata

        Issue an order get and verify that the correct
        http return code comes back for the specified user.

        The initial order will be created with the admin user to ensure
        that it gets created successfully.  We don't want the order
        create to fail since we are only testing order get here.

        :param user: the user who will attempt to do the get
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        order_ref = self._create_initial_order(admin=admin)

        resp = self.order_behaviors.get_order(order_ref, user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        self.assertEqual(expected_return == 200, resp.content is not None)

    @utils.parameterized_dataset(test_data_rbac_get_list_of_orders)
    def test_rbac_get_list_of_orders(self, user, admin, expected_return):
        """Test RBAC for get order list

        Issue a get order list and verify that the correct
        http return code comes back for the specified user.

        Some initial orders will be stored with the admin user to ensure
        that they get created successfully.  We don't want the order
        creates to fail since we are only testing get order list.

        :param user: the user who will attempt to get the list of orders
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        for i in range(3):
            order_ref = self._create_initial_order(admin=admin)
            self.assertIsNotNone(order_ref)

        resp, orders, next, prev = self.order_behaviors.get_orders(
            limit=10, offset=0, user_name=user)
        self.assertEqual(expected_return, resp.status_code)
        self.assertIsNotNone(orders)

    @utils.parameterized_dataset(test_data_rbac_delete_order)
    def test_rbac_delete_order(self, user, admin, expected_return):
        """Test RBAC for order delete

        Issue an order delete and verify that the correct
        http return code comes back for the specified user.

        The initial order will be stored with the admin user to ensure
        that it gets created successfully.  We don't want the order
        create to fail since we are only testing order delete here.

        :param user: the user who will attempt to do the delete
        :param admin: the admin of the group containing the user
        :param expected_return: the expected http return code
        """
        order_ref = self._create_initial_order(admin=admin)

        resp = self.order_behaviors.delete_order(order_ref, user_name=user)
        self.assertEqual(expected_return, resp.status_code)

    def _create_initial_order(self, admin=admin_a,
                              order_data=get_default_order_data()):
        """Utility function to create an order

        Some tests require a order to exist before they test certain things,
        so this function can be used to do that setup.

        :param admin: the admin user who will create the order
        :param order_data: the data for the order
        :return: href to the newly created order
        """
        test_model = order_models.OrderModel(**order_data)
        resp, order_ref = self.order_behaviors.create_order(test_model,
                                                            user_name=admin)
        self.assertEqual(202, resp.status_code)
        return order_ref
