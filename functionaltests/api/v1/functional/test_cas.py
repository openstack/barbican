# Copyright (c) 2015 Red Hat, Inc.
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

import base64
import copy
import re
import testtools

from OpenSSL import crypto

from barbican.common import hrefs
from barbican.plugin.interface import certificate_manager as cert_interface
from barbican.tests import certificate_utils as certutil
from functionaltests.api import base
from functionaltests.api.v1.behaviors import ca_behaviors
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.models import ca_models
from functionaltests.api.v1.models import order_models
from functionaltests.common import config

CONF = config.get_config()

admin_a = CONF.rbac_users.admin_a
creator_a = CONF.rbac_users.creator_a
service_admin = CONF.identity.service_admin

order_simple_cmc_request_data = {
    'type': 'certificate',
    'meta': {
        'request_type': 'simple-cmc',
        'requestor_name': 'Barbican User',
        'requestor_email': 'user@example.com',
        'requestor_phone': '555-1212'
    }
}


BARBICAN_SRV_CONF = cert_interface.CONF


def is_plugin_enabled(plugin):
    return plugin in BARBICAN_SRV_CONF.certificate.enabled_certificate_plugins


def depends_on_ca_plugins(*plugins):
    def depends_on_ca_plugins_decorator(function):
        def wrapper(instance, *args, **kwargs):
            plugins_enabled = (is_plugin_enabled(p) for p in plugins)
            if not all(plugins_enabled):
                instance.skipTest("The following plugin(s) need to be "
                                  "enabled: ".format(plugins))
            function(instance, *args, **kwargs)
        return wrapper
    return depends_on_ca_plugins_decorator


def convert_to_X509Name(dn):
    target = crypto.X509().get_subject()
    fields = dn.split(',')
    for field in fields:
        m = re.search(r"(\w+)\s*=\s*(.+)", field.strip())
        name = m.group(1)
        value = m.group(2)
        if name.lower() == 'ou':
            target.OU = value
        elif name.lower() == 'st':
            target.ST = value
        elif name.lower() == 'cn':
            target.CN = value
        elif name.lower() == 'l':
            target.L = value
        elif name.lower() == 'o':
            target.O = value
    return target


class CATestCommon(base.TestCase):

    def setUp(self):
        super(CATestCommon, self).setUp()
        self.order_behaviors = order_behaviors.OrderBehaviors(self.client)
        self.ca_behaviors = ca_behaviors.CABehaviors(self.client)

        self.simple_cmc_data = copy.deepcopy(order_simple_cmc_request_data)

    def tearDown(self):
        self.order_behaviors.delete_all_created_orders()
        self.ca_behaviors.delete_all_created_cas()
        super(CATestCommon, self).tearDown()

    def send_test_order(self, ca_ref=None):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())
        if ca_ref is not None:
            ca_id = hrefs.get_ca_id_from_ref(ca_ref)
            test_model.meta['ca_id'] = ca_id

        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

    def get_root_ca_ref(self, ca_plugin_name, ca_plugin_id):
        (resp, cas, total, next_ref, prev_ref) = self.ca_behaviors.get_cas()

        for item in cas:
            ca = self.ca_behaviors.get_ca(item)
            if ca.model.plugin_name == ca_plugin_name:
                if ca.model.plugin_ca_id == ca_plugin_id:
                    return item
        return None

    def get_snakeoil_root_ca_ref(self):
        return self.get_root_ca_ref(
            ca_plugin_name=('barbican.plugin.snakeoil_ca.'
                            'SnakeoilCACertificatePlugin'),
            ca_plugin_id="Snakeoil CA")


class CertificateAuthoritiesTestCase(CATestCommon):

    def setUp(self):
        super(CertificateAuthoritiesTestCase, self).setUp()

        self.subca_subject = "CN=Subordinate CA, O=example.com"
        self.subca_name = "Subordinate CA"
        self.subca_description = "Test Snake Oil Subordinate CA"

        self.subca_subca_subject = "CN=sub-sub CA, O=example.com"
        self.subca_subca_name = "Sub-Sub CA"
        self.subca_subca_description = "Test Snake Oil Sub-Sub CA"

    def get_signing_cert(self, ca_ref):
        resp = self.ca_behaviors.get_cacert(ca_ref)
        return crypto.load_certificate(crypto.FILETYPE_PEM, resp.text)

    def verify_signing_cert(self, ca_ref, subject_dn, issuer_dn):
        cacert = self.get_signing_cert(ca_ref)
        return ((cacert.get_subject() == subject_dn) and
                (cacert.get_issuer() == issuer_dn))

    def get_snakeoil_subca_model(self):
        return ca_models.CAModel(
            parent_ca_ref=self.get_snakeoil_root_ca_ref(),
            description=self.subca_description,
            name=self.subca_name,
            subject_dn=self.subca_subject
        )

    def get_snakeoil_sub_subca_model(self, parent_ca_ref):
        return ca_models.CAModel(
            parent_ca_ref=parent_ca_ref,
            description=self.subca_subca_description,
            name=self.subca_subca_name,
            subject_dn=self.subca_subca_subject
        )

    @depends_on_ca_plugins('snakeoil_ca')
    def test_create_snakeoil_subca(self):
        ca_model = self.get_snakeoil_subca_model()
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(201, resp.status_code)

        root_ca_ref = self.get_snakeoil_root_ca_ref()
        root_subject = self.get_signing_cert(root_ca_ref).get_subject()

        self.verify_signing_cert(
            ca_ref=ca_ref,
            subject_dn=convert_to_X509Name(self.subca_subject),
            issuer_dn=root_subject)

    @depends_on_ca_plugins('snakeoil_ca')
    def test_create_subca_of_snakeoil_subca(self):
        parent_model = self.get_snakeoil_subca_model()
        resp, parent_ref = self.ca_behaviors.create_ca(parent_model)
        self.assertEqual(201, resp.status_code)

        child_model = self.get_snakeoil_sub_subca_model(parent_ref)
        resp, child_ref = self.ca_behaviors.create_ca(child_model)
        self.assertEqual(201, resp.status_code)

        parent_subject = self.get_signing_cert(parent_ref).get_subject()
        self.verify_signing_cert(
            ca_ref=child_ref,
            subject_dn=convert_to_X509Name(self.subca_subca_subject),
            issuer_dn=parent_subject)

    def test_create_subca_with_invalid_parent_ca_id(self):
        ca_model = self.get_snakeoil_subca_model()
        ca_model.parent_ca_ref = 'http://localhost:9311/cas/invalid_ref'
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(400, resp.status_code)

    def test_create_subca_with_missing_parent_ca_id(self):
        ca_model = self.get_snakeoil_subca_model()
        del ca_model.parent_ca_ref
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(400, resp.status_code)

    def test_create_subca_with_missing_subjectdn(self):
        ca_model = self.get_snakeoil_subca_model()
        del ca_model.subject_dn
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(400, resp.status_code)

    @depends_on_ca_plugins('snakeoil_ca')
    def test_create_snakeoil_subca_and_send_cert_order(self):
        ca_model = self.get_snakeoil_subca_model()
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(201, resp.status_code)
        self.send_test_order(ca_ref)

    # @depends_on_ca_plugins('snakeoil_ca')
    @testtools.skip("Skip test until ca behaviors tracks project cas")
    def test_add_snakeoil_ca__to_project_and_get_preferred(self):
        ca_ref = self.get_snakeoil_root_ca_ref()
        resp = self.ca_behaviors.add_ca_to_project(ca_ref, user_name=admin_a)
        self.assertEqual(204, resp.status_code)

        ca = self.ca_behaviors.get_preferred(user_name=admin_a)
        self.assertEqual(hrefs.get_ca_id_from_ref(ca_ref), ca.model.ca_id)

    @depends_on_ca_plugins('snakeoil_ca')
    def test_create_and_delete_snakeoil_subca(self):
        ca_model = self.get_snakeoil_subca_model()
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(201, resp.status_code)

        self.ca_behaviors.delete_ca(ca_ref)
        resp = self.ca_behaviors.get_ca(ca_ref)
        self.assertEqual(404, resp.status_code)

    @depends_on_ca_plugins('snakeoil_ca')
    def test_fail_to_delete_top_level_snakeoil_ca(self):
        resp = self.ca_behaviors.delete_ca(
            self.get_snakeoil_root_ca_ref(),
            expected_fail=True)
        self.assertEqual(403, resp.status_code)

    @depends_on_ca_plugins('snakeoil_ca')
    def test_create_snakeoil_subca_and_get_cacert(self):
        ca_model = self.get_snakeoil_subca_model()
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(201, resp.status_code)
        resp = self.ca_behaviors.get_cacert(ca_ref)
        self.assertEqual(200, resp.status_code)
        crypto.load_certificate(crypto.FILETYPE_PEM, resp.text)


class ListingCAsTestCase(CATestCommon):
    """Tests for listing CAs.

    Must be in a separate class so that we can deselect them
    in the parallel CA tests, until we can deselect specific tests
    using a decorator.
    """

    def test_list_and_get_cas(self):
        (resp, cas, total, next_ref, prev_ref) = self.ca_behaviors.get_cas()
        self.assertGreater(total, 0)
        for item in cas:
            ca = self.ca_behaviors.get_ca(item)
            self.assertIsNotNone(ca.model.plugin_name)
            self.assertIsNotNone(ca.model.ca_id)
            self.assertIsNotNone(ca.model.plugin_ca_id)

    @depends_on_ca_plugins('snakeoil_ca', 'simple_certificate')
    def test_list_snakeoil_and_simple_cert_cas(self):
        """Test if backend loads these specific CAs

        Since the standard gate works with the snakeoil CA and the
        simple_certificate CA. This test is just to make sure that these two
        are specifically loaded.
        """
        (resp, cas, total, next_ref, prev_ref) = self.ca_behaviors.get_cas()
        self.assertEqual(total, 2)


class ProjectCATestCase(CATestCommon):

    def setUp(self):
        super(ProjectCATestCase, self).setUp()

    @depends_on_ca_plugins('snakeoil_ca', 'simple_certificate')
    def test_addition_of_project_ca_affects_getting_ca_list(self):
        # Getting list of CAs should get the total configured CAs
        (resp, cas, initial_total, _, __) = self.ca_behaviors.get_cas()
        self.assertEqual(initial_total, 2)

        # Set project CA
        ca_ref = self.get_snakeoil_root_ca_ref()
        resp = self.ca_behaviors.add_ca_to_project(ca_ref, user_name=admin_a)
        self.assertEqual(204, resp.status_code)

        # Getting list of CAs should get only the project CA for admin
        (resp, cas, project_ca_total, _, __) = self.ca_behaviors.get_cas(
            user_name=admin_a)
        self.assertEqual(1, project_ca_total)
        # Getting list of CAs should get only the project CA for non-admin
        (resp, cas, project_ca_total, _, __) = self.ca_behaviors.get_cas(
            user_name=creator_a)
        self.assertEqual(1, project_ca_total)

        # Remove project CA
        resp = self.ca_behaviors.remove_ca_from_project(ca_ref,
                                                        user_name=admin_a)
        self.assertEqual(204, resp.status_code)

        # Getting list of CAs should get the total configured CAs (as seen
        # before)
        (resp, cas, final_total, _, __) = self.ca_behaviors.get_cas()
        self.assertEqual(initial_total, final_total)


class GlobalPreferredCATestCase(CATestCommon):

    def setUp(self):
        super(GlobalPreferredCATestCase, self).setUp()
        (_, self.cas, self.num_cas, _, _) = self.ca_behaviors.get_cas()
        self.ca_ids = [hrefs.get_ca_id_from_ref(ref) for ref in self.cas]

    def tearDown(self):
        self.ca_behaviors.unset_global_preferred(user_name=service_admin)
        super(CATestCommon, self).tearDown()

    def test_global_preferred_no_project_admin_access(self):
        resp = self.ca_behaviors.get_global_preferred()
        self.assertEqual(403, resp.status_code)
        resp = self.ca_behaviors.set_global_preferred(ca_ref=self.cas[1])
        self.assertEqual(403, resp.status_code)
        resp = self.ca_behaviors.unset_global_preferred()
        self.assertEqual(403, resp.status_code)

    def test_global_preferred_update(self):
        if self.num_cas < 2:
            self.skipTest("At least two CAs are required for this test")
        resp = self.ca_behaviors.set_global_preferred(
            ca_ref=self.cas[0], user_name=service_admin)
        self.assertEqual(204, resp.status_code)
        resp = self.ca_behaviors.get_global_preferred(user_name=service_admin)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(self.ca_ids[0], resp.model.ca_id)

        resp = self.ca_behaviors.set_global_preferred(
            ca_ref=self.cas[1], user_name=service_admin)
        self.assertEqual(204, resp.status_code)
        resp = self.ca_behaviors.get_global_preferred(user_name=service_admin)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(self.ca_ids[1], resp.model.ca_id)

    def test_global_preferred_set_and_unset(self):
        resp = self.ca_behaviors.unset_global_preferred(
            user_name=service_admin)
        self.assertEqual(204, resp.status_code)
        resp = self.ca_behaviors.get_global_preferred(user_name=service_admin)
        self.assertEqual(404, resp.status_code)

        resp = self.ca_behaviors.set_global_preferred(
            ca_ref=self.cas[0], user_name=service_admin)
        self.assertEqual(204, resp.status_code)
        resp = self.ca_behaviors.get_global_preferred(user_name=service_admin)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(self.ca_ids[0], resp.model.ca_id)

        resp = self.ca_behaviors.unset_global_preferred(
            user_name=service_admin)
        self.assertEqual(204, resp.status_code)
        resp = self.ca_behaviors.get_global_preferred(user_name=service_admin)
        self.assertEqual(404, resp.status_code)

    @testtools.skip("Skip test until ca behaviors tracks project cas")
    def test_global_preferred_affects_project_preferred(self):
        if self.num_cas < 2:
            self.skipTest("At least two CAs are required for this test")
        resp = self.ca_behaviors.get_preferred(user_name=admin_a)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(self.ca_ids[0], resp.model.ca_id)

        resp = self.ca_behaviors.set_global_preferred(
            ca_ref=self.cas[1], user_name=service_admin)
        self.assertEqual(204, resp.status_code)

        resp = self.ca_behaviors.get_preferred(user_name=admin_a)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(self.ca_ids[1], resp.model.ca_id)
