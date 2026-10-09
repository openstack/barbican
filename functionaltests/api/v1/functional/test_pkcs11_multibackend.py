# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_serialization import base64 as oslo_base64
import testtools

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.behaviors import secretstores_behaviors
from functionaltests.api.v1.functional.test_secrets import get_default_data
from functionaltests.api.v1.functional.test_secrets import get_default_payload
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config

CONF = config.get_config()
admin_b = CONF.rbac_users.admin_b


def _pkcs11_multibackend_enabled():
    return (base.conf_multiple_backends_enabled and
            utils.is_pkcs11_enabled())


def _get_store_refs(ss_behaviors, user_name=admin_b):
    """Return pkcs11 and software secret_store_ref values."""
    resp, stores = ss_behaviors.get_all_secret_stores(user_name=user_name)
    if resp.status_code != 200:
        return None, None

    pkcs11_ref = None
    software_ref = None
    for store in stores['secret_stores']:
        if store['global_default'] or 'PKCS11' in store['name']:
            pkcs11_ref = store['secret_store_ref']
        elif 'Software' in store['name']:
            software_ref = store['secret_store_ref']
    return pkcs11_ref, software_ref


@utils.parameterized_test_case
class PKCS11MultiBackendTestCase(base.TestCase):
    """Exercise PKCS#11 + simple_crypto dual-store DevStack configuration."""

    def setUp(self):
        super(PKCS11MultiBackendTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.ss_behaviors = secretstores_behaviors.SecretStoresBehaviors(
            self.client)

    def tearDown(self):
        self.ss_behaviors.cleanup_preferred_secret_store_entities()
        self.secret_behaviors.delete_all_created_secrets()
        super(PKCS11MultiBackendTestCase, self).tearDown()

    @testtools.skipUnless(_pkcs11_multibackend_enabled(),
                          'requires PKCS#11 dual-store DevStack config')
    def test_global_default_is_pkcs11(self):
        resp, store = self.ss_behaviors.get_global_default(
            user_name=admin_b)
        self.assertEqual(200, resp.status_code)
        self.assertEqual('store_crypto', store['secret_store_plugin'])
        self.assertTrue(store['global_default'])
        self.assertIn('PKCS11', store['name'])

        pkcs11_ref, _ = _get_store_refs(self.ss_behaviors)
        self.assertEqual(pkcs11_ref, store['secret_store_ref'])

    @testtools.skipUnless(_pkcs11_multibackend_enabled(),
                          'requires PKCS#11 dual-store DevStack config')
    def test_secret_roundtrip_on_pkcs11_global_default(self):
        """Secrets without a project preferred store use PKCS#11."""
        test_model = secret_models.SecretModel(**get_default_data())
        resp, secret_ref = self.secret_behaviors.create_secret(
            test_model, user_name=admin_b)
        self.assertEqual(201, resp.status_code)

        expected = oslo_base64.decode_as_bytes(get_default_payload())
        get_resp = self.secret_behaviors.get_secret(
            secret_ref,
            test_model.payload_content_type,
            user_name=admin_b)
        self.assertEqual(expected, get_resp.content)

    @testtools.skipUnless(_pkcs11_multibackend_enabled(),
                          'requires PKCS#11 dual-store DevStack config')
    def test_preferred_software_store_roundtrip(self):
        """Project preferred store overrides the PKCS#11 global default."""
        _, software_store_ref = _get_store_refs(self.ss_behaviors)
        self.assertIsNotNone(software_store_ref)
        resp = self.ss_behaviors.set_preferred_secret_store(
            software_store_ref, user_name=admin_b)
        self.assertEqual(204, resp.status_code)

        test_model = secret_models.SecretModel(**get_default_data())
        resp, secret_ref = self.secret_behaviors.create_secret(
            test_model, user_name=admin_b)
        self.assertEqual(201, resp.status_code)

        expected = oslo_base64.decode_as_bytes(get_default_payload())
        get_resp = self.secret_behaviors.get_secret(
            secret_ref,
            test_model.payload_content_type,
            user_name=admin_b)
        self.assertEqual(expected, get_resp.content)

    @testtools.skipUnless(_pkcs11_multibackend_enabled(),
                          'requires PKCS#11 dual-store DevStack config')
    def test_list_secret_stores_includes_both_backends(self):
        resp, stores = self.ss_behaviors.get_all_secret_stores(
            user_name=admin_b)
        self.assertEqual(200, resp.status_code)
        plugins = {store['secret_store_plugin']
                   for store in stores['secret_stores']}
        self.assertIn('store_crypto', plugins)
        self.assertEqual(2, len(stores['secret_stores']))
