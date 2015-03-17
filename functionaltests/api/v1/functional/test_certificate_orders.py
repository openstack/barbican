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
import copy
import time

import testtools

from barbican.tests import certificate_utils as certutil
from functionaltests.api import base
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import order_models

try:
    import pki  # flake8: noqa
    dogtag_imports_ok = True
except ImportError:
    # dogtag libraries not available, assume dogtag not installed
    dogtag_imports_ok = False

order_simple_cmc_request_data = {
    'type': 'certificate',
    'meta': {
        'request_type': 'simple-cmc',
        'requestor_name': 'Barbican User',
        'requestor_email': 'user@example.com',
        'requestor_phone': '555-1212'
    }
}

order_full_cmc_request_data = {
    'type': 'certificate',
    'meta': {
        'request_type': 'full-cmc',
        'requestor_name': 'Barbican User',
        'requestor_email': 'user@example.com',
        'requestor_phone': '555-1212'
    }
}

order_stored_key_request_data = {
    'type': 'certificate',
    'meta': {
        'request_type': 'stored-key',
        'subject_dn': 'cn=server.example.com,o=example.com',
        'requestor_name': 'Barbican User',
        'requestor_email': 'user@example.com',
        'requestor_phone': '555-1212'
    }
}

order_dogtag_custom_request_data = {
    'type': 'certificate',
    'meta': {
        'request_type': 'custom'
    }
}


class CertificatesTestCase(base.TestCase):

    def setUp(self):
        super(CertificatesTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(self.client)
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.simple_cmc_data = copy.deepcopy(order_simple_cmc_request_data)
        self.full_cmc_data = copy.deepcopy(order_full_cmc_request_data)
        self.stored_key_data = copy.deepcopy(order_stored_key_request_data)
        self.dogtag_custom_data = copy.deepcopy(
            order_dogtag_custom_request_data)

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(CertificatesTestCase, self).tearDown()

    def wait_for_order(self, order_ref):
        # Make sure we have an order in a terminal state
        time_count = 1
        order_resp = self.behaviors.get_order(order_ref)

        while ((order_resp.model.status != "ACTIVE") and
               (order_resp.model.status != "ERROR") and
               time_count <= 4):
            time.sleep(1)
            time_count += 1
            order_resp = self.behaviors.get_order(order_ref)
        return order_resp

    def create_asymmetric_key_container(self):
        # TODO(alee) Complete this
        return "valid_container_ref"

    def create_generic_container(self):
        # TODO(alee) Complete this.
        return "valid_non_asymmetric_container_ref"

    def create_asymmetric_key_container_without_secrets(self):
        # TODO(alee) Complete this.
        return "asym_container_without_secrets"

    def get_dogtag_ca_id(self):
        # TODO(alee) implement this to get the right ca_id
        return "dummy_ca_id"

    @testtools.testcase.attr('positive')
    @testtools.skip("broken till state machine fixed")
    def test_create_simple_cmc_order(self):
        # TODO(alee) This currently returns 'ACTIVE' because the underlying
        # state machine is not correct.  Unskip when all is correct.

        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual('PENDING', order_resp.model.status)

    @testtools.testcase.attr('positive')
    @testtools.skip("broken till state machine fixed")
    def test_create_simple_cmc_order_without_requestor_info(self):
        # TODO(alee) This currently returns 'ACTIVE' because the underlying
        # state machine is not correct.  Unskip when all is correct.

        self.simple_cmc_data.pop("requestor_name", None)
        self.simple_cmc_data.pop("requestor_email", None)
        self.simple_cmc_data.pop("requestor_phone", None)

        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual('PENDING', order_resp.model.status)

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_simple_cmc_order_with_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()
        test_model.meta['profile'] = 'caServerCert'
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)

        self.assertEqual('ACTIVE', order_resp.model.status)
        self.assertIsNotNone(order_resp.model.meta['certificate'])

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_simple_cmc_with_profile_and_no_ca_id(self):
        # TODO(alee) currently exceptions are broken.  Should be returning
        # 400 not 500

        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()
        test_model.meta['profile'] = 'caServerCert'

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        # TODO(alee) validate exception message

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_simple_cmc_with_profile_and_incorrect_ca_id(self):
        # TODO(alee) Exceptions are broken.  Should be return 400 not 204

        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()
        test_model.meta['profile'] = 'caServerCert'
        test_model.meta['ca_id'] = 'incorrect_ca_id'

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        # TODO(alee) validate exception message

    @testtools.testcase.attr('negative')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_simple_cmc_with_dogtag_and_invalid_subject_dn(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()
        test_model.meta['profile'] = 'caServerCert'
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ERROR', order_resp.model.status)
        # TODO(alee) confirm error substatus/message

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_simple_csc_order_with_invalid_pkcs10(self):
        # TODO(alee) Exceptions are now broken, should return 400 not 500
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_bad_csr()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        # confirm error message

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_simple_csc_order_with_unsigned_pkcs10(self):
        # TODO(alee) Exceptions are now broken. Should return 400 not 500
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = (
            certutil.create_csr_that_has_not_been_signed())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        # confirm error message

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_simple_csc_order_with_pkcs10_signed_by_wrong_key(self):
        # TODO(alee) Exceptions are now broken. Should return 400 not 500
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = (
            certutil.create_csr_signed_with_wrong_key())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message

    @testtools.testcase.attr('negative')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_simple_cmc_order_with_invalid_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()
        test_model.meta['profile'] = 'invalidProfileID'
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ERROR', order_resp.model.status)
        # confirm order substatus = data issue seen

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_simple_cmc_order_with_non_approved_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()
        test_model.meta['profile'] = 'caSigningCert'
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('PENDING', order_resp.model.status)

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_simple_cmc_order_with_missing_request(self):
        # TODO(alee) Exceptions are now broken. Should return 400 not 500
        test_model = order_models.OrderModel(**self.simple_cmc_data)

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)
        self.assertIsNone(order_ref)
        # confirm error message

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till we handle this better")
    def test_create_full_cmc_order(self):
        # TODO(alee) right now, order is created.  we need to handle this
        # better and error out early
        test_model = order_models.OrderModel(**self.full_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message, should have not implemented

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_cert_order_with_invalid_type(self):
        # TODO(alee)  Exceptions are now broken. Should return 400 not 500
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = certutil.create_good_csr()
        test_model.meta['request_type'] = "invalid_type"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message

    @testtools.testcase.attr('positive')
    @testtools.skip("broken till container code written, state machine fixed")
    def test_create_stored_key_order(self):
        # TODO(alee) Fix the create_container function and status code
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual('PENDING', order_resp.model.status)

        # confirm order_status == PENDING

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_stored_key_order_with_dogtag_profile(self):
        # TODO(alee) Fix the create_container function and status code
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        test_model.meta['profile'] = "caServerCert"
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ACTIVE', order_resp.model.status)
        self.assertIsNotNone(order_resp.model.meta['certificate'])

    @testtools.testcase.attr('negative')
    @testtools.skip("broken pending dave's validator code")
    def test_create_stored_key_order_with_invalid_container_ref(self):
        # TODO(alee) Now returns 204, pending Dave's code changes
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = "invalid"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_stored_key_order_with_missing_container_ref(self):
        # TODO(alee) Exceptions are now broken. Should return 400 not 500
        test_model = order_models.OrderModel(**self.stored_key_data)

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_unauthorized_container_ref(self):
        # TODO(alee) - Not sure how to do this
        pass

    @testtools.testcase.attr('negative')
    @testtools.skip("broken pending dave's validator code")
    def test_create_stored_key_order_with_invalid_container_type(self):
        # TODO(alee) Now returns 204, pending Dave's code changes
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (self.create_generic_container())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message

    @testtools.testcase.attr('negative')
    @testtools.skip("broken pending dave's validator code")
    def test_create_stored_key_order_with_container_secrets_missing(self):
        # TODO(alee) Now returns 204, pending Dave's code changes
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container_without_secrets())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_container_secrets_inaccessible(self):
        # TODO(alee) Not sure how to do this
        pass

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_stored_key_order_with_subject_dn_missing(self):
        # TODO(alee) Exceptions are now broken. Should return 400 not 500
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        del test_model.meta['subject_dn']

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message

    @testtools.testcase.attr('negative')
    @testtools.skip("broken till exceptions fixed")
    def test_create_stored_key_order_with_subject_dn_invalid(self):
        # TODO(alee) Exceptions are now broken. Should return 400 not 500
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        test_model.meta['subject_dn'] = "invalid_subject_dn"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        # confirm error message

    @testtools.testcase.attr('positive')
    def test_create_stored_key_order_with_extensions(self):
        # TODO(alee) - Figure out how we want to handle this.
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        test_model.meta['extensions'] = "any-extensions-will-do-right-now"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        self.behaviors.get_order(order_ref)
        # confirm order_status == PENDING ??

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_stored_key_order_with_non_approved_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        test_model.meta['profile'] = "caSigningCert"
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('PENDING', order_resp.model.status)

    @testtools.testcase.attr('negative')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_stored_key_order_with_invalid_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        test_model.meta['profile'] = "invalidProfileID"
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ERROR', order_resp.model.status)
        # confirm order substatus = data issue seen

    @testtools.testcase.attr('positive')
    @testtools.skip("broken till state machine fixed")
    def test_create_cert_order_with_missing_request_type(self):
        # TODO(alee) Need to fix state machine to return PENDING
        # defaults to 'custom' type
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['request_data'] = certutil.create_good_csr()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual('PENDING', order_resp.model.status)

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_custom_order_with_valid_dogtag_data(self):
        # TODO(alee) Set correct custom cert data
        # defaults to 'custom' type
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['request_data'] = certutil.create_good_csr()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ACTIVE', order_resp.model.status)
        self.assertIsNotNone(order_resp.model.meta['certificate'])

    @testtools.testcase.attr('negative')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_custom_order_with_invalid_dogtag_data(self):
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['request_data'] = "invalid_data"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ERROR', order_resp.model.status)
        # confirm substatus - data error seen

    @testtools.testcase.attr('positive')
    @testtools.skip("broken till state machine fixed")
    def test_create_custom_order_for_generic_plugin(self):
        # TODO(alee) - fix state machine
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual('PENDING', order_resp.model.status)
