# Copyright (c) 2015 Cisco Systems
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

import testtools

from barbican.plugin.interface import certificate_manager as cert_interface

from functionaltests.api import base
from functionaltests.api.v1.behaviors import ca_behaviors
from functionaltests.api.v1.behaviors import consumer_behaviors
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.behaviors import quota_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import ca_models
from functionaltests.api.v1.models import consumer_model
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import order_models
from functionaltests.api.v1.models import quota_models
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config


CONF = config.get_config()
admin_b = CONF.rbac_users.admin_b
service_admin = CONF.identity.service_admin


def is_ca_backend_snakeoil():
    return 'snakeoil_ca' in\
           cert_interface.CONF.certificate.enabled_certificate_plugins


@testtools.testcase.attr('no_parallel')
class QuotaEnforcementTestCase(base.TestCase):

    def setUp(self):
        super(QuotaEnforcementTestCase, self).setUp()
        self.quota_behaviors = quota_behaviors.QuotaBehaviors(self.client)
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client)
        self.order_behaviors = order_behaviors.OrderBehaviors(self.client)
        self.consumer_behaviors = consumer_behaviors.ConsumerBehaviors(
            self.client)
        self.ca_behaviors = ca_behaviors.CABehaviors(self.client)

        self.secret_data = self.get_default_secret_data()
        self.quota_data = self.get_default_quota_data()
        self.project_id = self.quota_behaviors.get_project_id_from_name(
            admin_b)
        self.order_secrets = []
        self.root_ca_ref = None
        self.test_order_sent = False

    def tearDown(self):
        self.quota_behaviors.delete_all_created_quotas()
        self.consumer_behaviors.delete_all_created_consumers()
        self.container_behaviors.delete_all_created_containers()
        self.secret_behaviors.delete_all_created_secrets()
        self.ca_behaviors.delete_all_created_cas()
        for secret_ref in self.order_secrets:
            resp = self.secret_behaviors.delete_secret(
                secret_ref, user_name=admin_b)
            self.assertEqual(204, resp.status_code)
        self.order_behaviors.delete_all_created_orders()
        super(QuotaEnforcementTestCase, self).tearDown()

    def test_secrets_unlimited(self):
        self.set_quotas('secrets', -1)
        self.create_secrets(count=5)

    def test_secrets_disabled(self):
        self.set_quotas('secrets', 0)
        self.create_secrets(expected_return=403)

    def test_secrets_limited_one(self):
        self.set_quotas('secrets', 1)
        self.create_secrets(count=1)
        self.create_secrets(expected_return=403)

    def test_secrets_limited_five(self):
        self.set_quotas('secrets', 5)
        self.create_secrets(count=5)
        self.create_secrets(expected_return=403)

    def test_containers_unlimited(self):
        self.set_quotas('containers', -1)
        self.create_containers(count=5)

    def test_containers_disabled(self):
        self.set_quotas('containers', 0)
        self.create_containers(expected_return=403)

    def test_containers_limited_one(self):
        self.set_quotas('containers', 1)
        self.create_containers(count=1)
        self.create_containers(expected_return=403)

    def test_containers_limited_five(self):
        self.set_quotas('containers', 5)
        self.create_containers(count=5)
        self.create_containers(expected_return=403)

    def test_orders_unlimited(self):
        self.set_quotas('orders', -1)
        self.create_orders(count=5)

    def test_orders_disabled(self):
        self.set_quotas('orders', 0)
        self.create_orders(expected_return=403)

    def test_orders_limited_one(self):
        self.set_quotas('orders', 1)
        self.create_orders(count=1)
        self.create_orders(expected_return=403)

    def test_orders_limited_five(self):
        self.set_quotas('orders', 5)
        self.create_orders(count=5)
        self.create_orders(expected_return=403)

    def test_consumers_unlimited(self):
        self.set_quotas('consumers', -1)
        self.create_consumers(count=5)

    def test_consumers_disabled(self):
        self.set_quotas('consumers', 0)
        self.create_consumers(expected_return=403)

    def test_consumers_limited_one(self):
        self.set_quotas('consumers', 1)
        self.create_consumers(count=1)
        self.create_consumers(expected_return=403)

    def test_consumers_limited_five(self):
        self.set_quotas('consumers', 5)
        self.create_consumers(count=5)
        self.create_consumers(expected_return=403)

    @testtools.skipIf(not is_ca_backend_snakeoil(),
                      "This test is only usable with snakeoil")
    def test_snakeoil_cas_unlimited(self):
        self.set_quotas('cas', -1)
        self.create_snakeoil_cas(count=5)

    @testtools.skipIf(not is_ca_backend_snakeoil(),
                      "This test is only usable with snakeoil")
    def test_snakeoil_cas_disabled(self):
        self.set_quotas('cas', 0)
        self.create_snakeoil_cas(expected_return=403)

    @testtools.skipIf(not is_ca_backend_snakeoil(),
                      "This test is only usable with snakeoil")
    def test_snakeoil_cas_limited_one(self):
        self.set_quotas('cas', 1)
        self.create_snakeoil_cas(count=1)
        self.create_snakeoil_cas(expected_return=403)

    @testtools.skipIf(not is_ca_backend_snakeoil(),
                      "This test is only usable with snakeoil")
    def test_snakeoil_cas_limited_five(self):
        self.set_quotas('cas', 5)
        self.create_snakeoil_cas(count=5)
        self.create_snakeoil_cas(expected_return=403)

# ----------------------- Helper Functions ---------------------------

    def get_default_quota_data(self):
        return {"project_quotas":
                {"secrets": -1,
                 "orders": -1,
                 "containers": -1,
                 "consumers": -1}}

    def set_quotas(self, resource, quota):
        """Utility function to set resource quotas"""
        self.quota_data["project_quotas"][resource] = quota
        request_model = quota_models.ProjectQuotaRequestModel(
            **self.quota_data)
        resp = self.quota_behaviors.set_project_quotas(self.project_id,
                                                       request_model,
                                                       user_name=service_admin)
        self.assertEqual(204, resp.status_code)

    def get_default_secret_data(self):
        return {
            "name": "AES key",
            "expiration": "2050-02-28T19:14:44.180394",
            "algorithm": "aes",
            "bit_length": 256,
            "mode": "cbc",
            "payload": "Z0Y2K2xMb0Yzb2hBOWFQUnB0KzZiUT09",
            "payload_content_type": "application/octet-stream",
            "payload_content_encoding": "base64",
        }

    def create_secrets(self, count=1, expected_return=201):
        """Utility function to create secrets"""
        secret_ref = None
        for _ in range(count):
            test_model = secret_models.SecretModel(**self.secret_data)
            resp, secret_ref = self.secret_behaviors.create_secret(
                test_model, user_name=admin_b)
            self.assertEqual(expected_return, resp.status_code)
        return secret_ref

    def get_container_req(self, secret_ref):
        return {"name": "test_container",
                "type": "generic",
                "secret_refs": [{'name': 'secret1', 'secret_ref': secret_ref}]}

    def create_containers(self, count=1, expected_return=201):
        """Utility function to create containers"""
        container_ref = None
        for _ in range(count):
            secret_ref = self.create_secrets()
            test_model = container_models.ContainerModel(
                **self.get_container_req(secret_ref))
            resp, container_ref = self.container_behaviors.create_container(
                test_model, user_name=admin_b)
            self.assertEqual(expected_return, resp.status_code)
        return container_ref

    def get_default_order_data(self):
        return {'type': 'key',
                "meta": {
                    "name": "barbican functional test order name",
                    "algorithm": "aes",
                    "bit_length": 256,
                    "mode": "cbc"}}

    def create_orders(self, count=1, expected_return=202):
        """Utility function to create orders"""
        for _ in range(count):
            order_data = self.get_default_order_data()
            test_model = order_models.OrderModel(**order_data)
            resp, order_ref = self.order_behaviors.create_order(
                test_model, user_name=admin_b)
            self.assertEqual(expected_return, resp.status_code)
            if resp.status_code == 202:
                order_resp = self.order_behaviors.get_order(
                    order_ref, user_name=admin_b)
                self.assertEqual(order_resp.status_code, 200)
                self.order_secrets.append(order_resp.model.secret_ref)

    def get_default_consumer_data(self):
        return {"name": "consumer_name",
                "URL": "consumer_url"}

    def create_consumers(self, count=1, expected_return=200):
        """Utility function to create consumers"""
        for _ in range(count):
            container_ref = self.create_containers()
            model = consumer_model.ConsumerModel(
                **self.get_default_consumer_data())
            resp, consumer_dat = self.consumer_behaviors.create_consumer(
                model, container_ref, user_name=admin_b)
            self.assertEqual(expected_return, resp.status_code)

    def get_order_simple_cmc_request_data(self):
        return {
            'type': 'certificate',
            'meta': {
                'request_type': 'simple-cmc',
                'requestor_name': 'Barbican User',
                'requestor_email': 'user@example.com',
                'requestor_phone': '555-1212'
            }
        }

    def get_root_ca_ref(self):
        if self.root_ca_ref is not None:
            return self.root_ca_ref

        (resp, cas, total, next_ref, prev_ref) = self.ca_behaviors.get_cas()
        snake_name = 'barbican.plugin.snakeoil_ca.SnakeoilCACertificatePlugin'
        snake_plugin_ca_id = "Snakeoil CA"

        for item in cas:
            ca = self.ca_behaviors.get_ca(item)
            if ca.model.plugin_name == snake_name:
                if ca.model.plugin_ca_id == snake_plugin_ca_id:
                    return item
        return None

    def get_snakeoil_subca_model(self):
        parent_ca_ref = self.get_root_ca_ref()
        return ca_models.CAModel(
            parent_ca_ref=parent_ca_ref,
            description="Test Snake Oil Subordinate CA",
            name="Subordinate CA",
            subject_dn="CN=Subordinate CA, O=example.com"
        )

    def create_snakeoil_cas(self, count=1, expected_return=201):
        """Utility function to create snakeoil cas"""
        for _ in range(count):
            ca_model = self.get_snakeoil_subca_model()
            resp, ca_ref = self.ca_behaviors.create_ca(ca_model,
                                                       user_name=admin_b)
            self.assertEqual(expected_return, resp.status_code)
