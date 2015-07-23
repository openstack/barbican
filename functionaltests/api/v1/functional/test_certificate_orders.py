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
import json
import time

from OpenSSL import crypto
import testtools

from barbican.plugin.interface import secret_store as s
from barbican.tasks import certificate_resources as cert_res
from barbican.tests import certificate_utils as certutil
from barbican.tests import keys
from functionaltests.api import base
from functionaltests.api.v1.behaviors import ca_behaviors
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import order_models
from functionaltests.api.v1.models import secret_models

try:
    import pki  # flake8: noqa
    dogtag_imports_ok = True
except ImportError:
    # dogtag libraries not available, assume dogtag not installed
    dogtag_imports_ok = False


NOT_FOUND_CONTAINER_REF = "http://localhost:9311/v1/containers/not_found"
INVALID_CONTAINER_REF = "invalid"


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
        'request_type': 'custom',
        'cert_request_type': 'pkcs10',
        'profile_id': 'caServerCert'
    }
}

create_container_rsa_data = {
    "name": "rsacontainer",
    "type": "rsa",
    "secret_refs": [
        {
            "name": "public_key",
        },
        {
            "name": "private_key",
        },
        {
            "name": "private_key_passphrase"
        }
    ]
}

def get_private_key_req():
    return {'name': 'myprivatekey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': s.SecretType.PRIVATE,
            'payload': base64.b64encode(keys.get_private_key_pem())}


def get_public_key_req():
    return {'name': 'mypublickey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': s.SecretType.PUBLIC,
            'payload': base64.b64encode(keys.get_public_key_pem())}


create_generic_container_data = {
    "name": "containername",
    "type": "generic",
    "secret_refs": [
        {
            "name": "secret1",
        },
        {
            "name": "secret2",
        },
        {
            "name": "secret3"
        }
    ]
}


class CertificatesTestCase(base.TestCase):

    def setUp(self):
        super(CertificatesTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(self.client)
        self.ca_behaviors = ca_behaviors.CABehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client)
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.simple_cmc_data = copy.deepcopy(order_simple_cmc_request_data)
        self.full_cmc_data = copy.deepcopy(order_full_cmc_request_data)
        self.stored_key_data = copy.deepcopy(order_stored_key_request_data)
        self.dogtag_custom_data = copy.deepcopy(
            order_dogtag_custom_request_data)

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(CertificatesTestCase, self).tearDown()

    def wait_for_order(
            self, order_ref, delay_before_check_seconds=1, max_wait_seconds=4):
        time.sleep(delay_before_check_seconds)

        # Make sure we have an order in a terminal state
        time_count = 1
        order_resp = self.behaviors.get_order(order_ref)

        while ((order_resp.model.status != "ACTIVE") and
               (order_resp.model.status != "ERROR") and
               time_count <= max_wait_seconds):
            time.sleep(1)
            time_count += 1
            order_resp = self.behaviors.get_order(order_ref)
        return order_resp

    def create_asymmetric_key_container(self):
        secret_model = secret_models.SecretModel(**get_private_key_req())
        secret_model.secret_type = s.SecretType.PRIVATE
        resp, secret_ref_priv = self.secret_behaviors.create_secret(
            secret_model)
        self.assertEqual(201, resp.status_code)

        secret_model = secret_models.SecretModel(**get_public_key_req())
        secret_model.secret_type = s.SecretType.PUBLIC
        resp, secret_ref_pub = self.secret_behaviors.create_secret(
            secret_model)
        self.assertEqual(201, resp.status_code)

        pub_key_ref = {'name': 'public_key', 'secret_ref': secret_ref_pub}
        priv_key_ref = {'name': 'private_key', 'secret_ref': secret_ref_priv}
        test_model = container_models.ContainerModel(
            **create_container_rsa_data)
        test_model.secret_refs = [pub_key_ref, priv_key_ref]
        resp, container_ref = self.container_behaviors.create_container(
            test_model)
        self.assertEqual(resp.status_code, 201)

        return container_ref

    def create_generic_container(self):
        secret_model = secret_models.SecretModel(**get_private_key_req())
        secret_model.secret_type = s.SecretType.PRIVATE
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(201, resp.status_code)

        test_model = container_models.ContainerModel(**create_generic_container_data)
        test_model.secret_refs = [{
            'name': 'my_secret',
            'secret_ref': secret_ref
        }]
        resp, container_ref = self.container_behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)
        return container_ref

    def get_dogtag_ca_id(self):
        (resp, cas, total, next_ref, prev_ref) = self.ca_behaviors.get_cas()
        for item in cas:
            ca = self.ca_behaviors.get_ca(item)
            if ca.model.plugin_name == (
                    'barbican.plugin.dogtag.DogtagCAPlugin'):
                return ca.model.ca_id
        return None

    def verify_cert_returned(self, order_resp, is_stored_key_type=False):
        container_ref = order_resp.model.container_ref
        self.assertIsNotNone(container_ref, "no cert container returned")

        container_resp = self.container_behaviors.get_container(container_ref)
        self.assertIsNotNone(container_resp, "Cert container returns None")
        self.assertEqual('certificate', container_resp.model.type)

        secret_refs = container_resp.model.secret_refs
        self.assertIsNotNone(secret_refs, "container has no secret refs")

        contains_cert = False
        contains_private_key_ref = False

        for secret in secret_refs:
            if secret.name == 'certificate':
                contains_cert = True
                self.assertIsNotNone(secret.secret_ref)
                self.verify_valid_cert(secret.secret_ref)
            if secret.name == 'intermediates':
                self.assertIsNotNone(secret.secret_ref)
                self.verify_valid_intermediates(secret.secret_ref)
            if is_stored_key_type:
                if secret.name == 'private_key':
                    contains_private_key_ref = True
                    self.assertIsNotNone(secret.secret_ref)

        self.assertTrue(contains_cert)
        if is_stored_key_type:
            self.assertTrue(contains_private_key_ref)

    def verify_valid_cert(self, secret_ref):
        secret_resp = self.secret_behaviors.get_secret(
            secret_ref,
            "application/pkix-cert")
        self.assertIsNotNone(secret_resp)
        self.assertIsNotNone(secret_resp.content)
        cert = secret_resp.content
        crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    def verify_valid_intermediates(self, secret_ref):
        secret_resp = self.secret_behaviors.get_secret(
            secret_ref,
            "application/pkix-cert")
        self.assertIsNotNone(secret_resp)
        self.assertIsNotNone(secret_resp.content)
        cert_chain = secret_resp.content
        crypto.load_pkcs7_data(crypto.FILETYPE_PEM, cert_chain)

    def verify_pending_waiting_for_ca(self, order_resp):
        self.assertEqual('PENDING', order_resp.model.status)
        self.assertEqual(cert_res.ORDER_STATUS_REQUEST_PENDING.id,
                         order_resp.model.sub_status)
        self.assertEqual(cert_res.ORDER_STATUS_REQUEST_PENDING.message,
                         order_resp.model.sub_status_message)

    def confirm_error_message(self, resp, message):
        resp_dict = json.loads(resp.content)
        self.assertEqual(message, resp_dict['description'])

    @testtools.testcase.attr('positive')
    @testtools.skipIf(dogtag_imports_ok, "not applicable with dogtag plugin")
    def test_create_simple_cmc_order(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.verify_pending_waiting_for_ca(order_resp)

        # Wait for retry processing to handle checking for status with the
        # default certificate plugin (which takes about 10 seconds +- 20%).
        order_resp = self.wait_for_order(
            order_ref, delay_before_check_seconds=20, max_wait_seconds=25)

        self.assertEqual('ACTIVE', order_resp.model.status)

    @testtools.testcase.attr('positive')
    def test_create_simple_cmc_order_without_requestor_info(self):
        self.simple_cmc_data.pop("requestor_name", None)
        self.simple_cmc_data.pop("requestor_email", None)
        self.simple_cmc_data.pop("requestor_phone", None)

        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.verify_pending_waiting_for_ca(order_resp)

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_simple_cmc_order_with_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())
        test_model.meta['profile'] = 'caServerCert'
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)

        self.assertEqual('ACTIVE', order_resp.model.status)
        self.verify_cert_returned(order_resp)

    @testtools.testcase.attr('negative')
    def test_create_simple_cmc_with_profile_and_no_ca_id(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())
        test_model.meta['profile'] = 'caServerCert'

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        self.confirm_error_message(
            create_resp,
            "Missing required metadata field for ca_id"
        )

    @testtools.testcase.attr('negative')
    def test_create_simple_cmc_with_profile_and_incorrect_ca_id(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())
        test_model.meta['profile'] = 'caServerCert'
        test_model.meta['ca_id'] = 'incorrect_ca_id'

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        self.confirm_error_message(
            create_resp,
            "Order creation issue seen - The ca_id provided "
            "in the request is invalid."
        )

    @testtools.testcase.attr('negative')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_simple_cmc_with_dogtag_and_invalid_subject_dn(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_csr_with_bad_subject_dn())
        test_model.meta['profile'] = 'caServerCert'
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ERROR', order_resp.model.status)
        self.assertEqual('400', order_resp.model.error_status_code)
        self.assertIn('Problem with data in certificate request',
                      order_resp.model.error_reason)
        # TODO(alee) Dogtag does not currently return a error message
        # when it does, check for that specific error message

    @testtools.testcase.attr('negative')
    def test_create_simple_cmc_order_with_no_base64(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        # do not encode with base64 to force the error
        test_model.meta['request_data'] = certutil.create_bad_csr()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        self.confirm_error_message(create_resp,
                                   "Unable to decode request data.")

    @testtools.testcase.attr('negative')
    def test_create_simple_cmc_order_with_invalid_pkcs10(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_bad_csr())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        self.confirm_error_message(create_resp,
                                   "Invalid PKCS10 Data: Bad format")

    @testtools.testcase.attr('negative')
    def test_create_simple_csc_order_with_unsigned_pkcs10(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_csr_that_has_not_been_signed())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.assertIsNone(order_ref)
        error_description = json.loads(create_resp.content)['description']
        self.assertIn("Invalid PKCS10 Data", error_description)

    @testtools.testcase.attr('negative')
    def test_create_simple_csc_order_with_pkcs10_signed_by_wrong_key(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_csr_signed_with_wrong_key())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Invalid PKCS10 Data: Signing key incorrect"
        )

    @testtools.testcase.attr('negative')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_simple_cmc_order_with_invalid_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())
        test_model.meta['profile'] = 'invalidProfileID'
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ERROR', order_resp.model.status)
        self.assertEqual('400', order_resp.model.error_status_code)
        self.assertIn('Problem with data in certificate request',
                      order_resp.model.error_reason)
        self.assertIn('Profile not found',
                      order_resp.model.error_reason)

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_simple_cmc_order_with_non_approved_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())
        test_model.meta['profile'] = 'caTPSCert'
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.verify_pending_waiting_for_ca(order_resp)

    @testtools.testcase.attr('negative')
    def test_create_simple_cmc_order_with_missing_request(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)
        self.assertIsNone(order_ref)
        self.confirm_error_message(
            create_resp,
            "Missing required metadata field for request_data"
        )

    @testtools.testcase.attr('negative')
    def test_create_full_cmc_order(self):
        test_model = order_models.OrderModel(**self.full_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 400)
        self.assertIsNone(order_ref)
        self.confirm_error_message(
            create_resp,
            "Full CMC Requests are not yet supported."
        )

    @testtools.testcase.attr('negative')
    def test_create_cert_order_with_invalid_type(self):
        test_model = order_models.OrderModel(**self.simple_cmc_data)
        test_model.meta['request_data'] = base64.b64encode(
            certutil.create_good_csr())
        test_model.meta['request_type'] = "invalid_type"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Invalid Certificate Request Type"
        )

    @testtools.testcase.attr('positive')
    def test_create_stored_key_order(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.verify_pending_waiting_for_ca(order_resp)

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_stored_key_order_with_dogtag_profile(self):
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
        self.verify_cert_returned(order_resp, is_stored_key_type=True)

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_invalid_container_ref(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = INVALID_CONTAINER_REF

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Order creation issue seen - "
            "Invalid container: Bad Container Reference "
            + INVALID_CONTAINER_REF + "."
        )

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_not_found_container_ref(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = NOT_FOUND_CONTAINER_REF

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Order creation issue seen - "
            "Invalid container: Container Not Found."
        )

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_missing_container_ref(self):
        test_model = order_models.OrderModel(**self.stored_key_data)

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Missing required metadata field for container_ref"
        )

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_unauthorized_container_ref(self):
        # TODO(alee) - Not sure how to do this
        pass

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_invalid_container_type(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (self.create_generic_container())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Order creation issue seen - "
            "Invalid container: Container Wrong Type."
        )

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_container_secrets_inaccessible(self):
        # TODO(alee) Not sure how to do this
        pass

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_subject_dn_missing(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        del test_model.meta['subject_dn']

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Missing required metadata field for subject_dn"
        )

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_subject_dn_invalid(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        test_model.meta['subject_dn'] = "invalid_subject_dn"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Invalid subject DN: invalid_subject_dn"
        )

    @testtools.testcase.attr('negative')
    def test_create_stored_key_order_with_extensions(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        test_model.meta['extensions'] = "any-extensions"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(400, create_resp.status_code)
        self.confirm_error_message(
            create_resp,
            "Extensions are not yet supported.  "
            "Specify a valid profile instead."
        )

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_stored_key_order_with_non_approved_dogtag_profile(self):
        test_model = order_models.OrderModel(**self.stored_key_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())
        test_model.meta['profile'] = "caTPSCert"
        test_model.meta['ca_id'] = self.get_dogtag_ca_id()

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.verify_pending_waiting_for_ca(order_resp)

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
        self.assertIn('Problem with data in certificate request',
                      order_resp.model.error_reason)
        self.assertIn('Profile not found',
                      order_resp.model.error_reason)

    @testtools.testcase.attr('positive')
    def test_create_cert_order_with_missing_request_type(self):
        # defaults to 'custom' type
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['cert_request'] = base64.b64encode(
            certutil.create_good_csr())
        test_model.meta['profile_id'] = 'caTPSCert'

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.verify_pending_waiting_for_ca(order_resp)

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_cert_order_with_missing_request_type_auto_enroll(self):
        # defaults to 'custom' type
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['cert_request'] = base64.b64encode(
            certutil.create_good_csr())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ACTIVE', order_resp.model.status)
        self.verify_cert_returned(order_resp)

    @testtools.testcase.attr('positive')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_custom_order_with_valid_dogtag_data(self):
        # defaults to 'custom' type
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['cert_request'] = base64.b64encode(
            certutil.create_good_csr())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ACTIVE', order_resp.model.status)
        self.verify_cert_returned(order_resp)

    @testtools.testcase.attr('negative')
    @testtools.skipIf(not dogtag_imports_ok, "Dogtag imports not available")
    def test_create_custom_order_with_invalid_dogtag_data(self):
        # TODO(alee) this test is broken because Dogtag does not return the
        # correct type of exception,  Fix this when Dogtag is fixed.
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['cert_request'] = "invalid_data"

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.wait_for_order(order_ref)
        self.assertEqual('ERROR', order_resp.model.status)
        # TODO(alee) confirm substatus - data error seen

    @testtools.testcase.attr('positive')
    @testtools.skipIf(dogtag_imports_ok, "Non-Dogtag test only")
    def test_create_custom_order_for_generic_plugin(self):
        test_model = order_models.OrderModel(**self.dogtag_custom_data)
        test_model.meta['container_ref'] = (
            self.create_asymmetric_key_container())

        create_resp, order_ref = self.behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertEqual('PENDING', order_resp.model.status)
