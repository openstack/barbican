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

from OpenSSL import crypto
import testtools

from barbican.common import hrefs
from barbican.plugin.interface import certificate_manager as cert_interface
from barbican.tests import certificate_utils as certutil
from functionaltests.api import base
from functionaltests.api.v1.behaviors import ca_behaviors
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.models import ca_models
from functionaltests.api.v1.models import order_models

order_simple_cmc_request_data = {
    'type': 'certificate',
    'meta': {
        'request_type': 'simple-cmc',
        'requestor_name': 'Barbican User',
        'requestor_email': 'user@example.com',
        'requestor_phone': '555-1212'
    }
}


CONF = cert_interface.CONF


def is_snakeoil_enabled():
    return 'snakeoil_ca' in CONF.certificate.enabled_certificate_plugins


def convert_to_X509Name(dn):
    target = crypto.X509Name()
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


class CertificateAuthoritiesTestCase(base.TestCase):

    def setUp(self):
        super(CertificateAuthoritiesTestCase, self).setUp()
        self.order_behaviors = order_behaviors.OrderBehaviors(self.client)
        self.ca_behaviors = ca_behaviors.CABehaviors(self.client)
        self.root_ca_ref = None

        self.subca_subject = "CN=Subordinate CA, O=example.com"
        self.subca_name = "Subordinate CA"
        self.subca_description = "Test Snake Oil Subordinate CA"

        self.subca_subca_subject = "CN=sub-sub CA, O=example.com"
        self.subca_subca_name = "Sub-Sub CA"
        self.subca_subca_description = "Test Snake Oil Sub-Sub CA"

        self.simple_cmc_data = copy.deepcopy(order_simple_cmc_request_data)

        # we need to prime the pump ie. populate the CA table by sending
        # in an order (just in case)
        self.send_test_order()

    def tearDown(self):
        self.order_behaviors.delete_all_created_orders()
        self.ca_behaviors.delete_all_created_cas()
        super(CertificateAuthoritiesTestCase, self).tearDown()

    def get_signing_cert(self, ca_ref):
        resp = self.ca_behaviors.get_cacert(ca_ref)
        return crypto.load_certificate(crypto.FILETYPE_PEM, resp)

    def verify_signing_cert(self, ca_ref, subject_dn, issuer_dn):
        cacert = self.get_signing_cert(ca_ref)
        return ((cacert.get_subject() == subject_dn) and
                (cacert.get_issuer() == issuer_dn))

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

    def test_list_and_get_cas(self):
        (resp, cas, total, next_ref, prev_ref) = self.ca_behaviors.get_cas()
        self.assertGreater(total, 0)
        for item in cas:
            ca = self.ca_behaviors.get_ca(item)
            self.assertIsNotNone(ca.model.plugin_name)
            self.assertIsNotNone(ca.model.ca_id)
            self.assertIsNotNone(ca.model.plugin_ca_id)

    @testtools.skipIf(not is_snakeoil_enabled(),
                      "This test is only usable with snakeoil")
    def test_create_snakeoil_subca(self):
        ca_model = self.get_snakeoil_subca_model()
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(201, resp.status_code)

        # TODO(alee) Get this additional test code working
        # root_subject = self.get_signing_cert(
        #    self.get_root_ca_ref()).get_subject()

        # self.verify_signing_cert(
        #    ca_ref=ca_ref,
        #    subject_dn=convert_to_X509Name(self.subca_subject),
        #    issuer_dn=root_subject)

    @testtools.skipIf(not is_snakeoil_enabled(),
                      "This test is only usable with snakeoil")
    def test_create_subca_of_snakeoil_subca(self):
        parent_model = self.get_snakeoil_subca_model()
        resp, parent_ref = self.ca_behaviors.create_ca(parent_model)
        self.assertEqual(201, resp.status_code)

        child_model = self.get_snakeoil_sub_subca_model(parent_ref)
        resp, child_ref = self.ca_behaviors.create_ca(child_model)
        self.assertEqual(201, resp.status_code)

        # TODO(alee) Get this additional test code working
        # parent_subject = self.get_signing_cert(parent_ref).get_subject()
        # self.verify_signing_cert(
        #    ca_ref=child_ref,
        #    subject_dn=convert_to_X509Name(self.subca_subca_subject),
        #    issuer_dn=parent_subject)

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

    @testtools.skipIf(not is_snakeoil_enabled(),
                      "This test is only usable with snakeoil")
    def test_create_snakeoil_subca_and_send_cert_order(self):
        ca_model = self.get_snakeoil_subca_model()
        resp, ca_ref = self.ca_behaviors.create_ca(ca_model)
        self.assertEqual(201, resp.status_code)
        self.send_test_order(ca_ref)
