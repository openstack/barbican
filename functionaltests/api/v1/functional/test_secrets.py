# Copyright (c) 2014 Rackspace, Inc.
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
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import secret_models
from testtools import testcase

# TODO(tdink) Move to a config file
secret_create_defaults_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

secret_create_nones_data = {
    "name": None,
    "expiration": None,
    "algorithm": None,
    "bit_length": None,
    "mode": None,
    "payload": None,
    "payload_content_type": None,
    "payload_content_encoding": None,
}

secret_create_emptystrings_data = {
    "name": '',
    "expiration": '',
    "algorithm": '',
    "bit_length": '',
    "mode": '',
    "payload": '',
    "payload_content_type": '',
    "payload_content_encoding": '',
}

secret_create_two_phase_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
}

max_allowed_payload_in_bytes = 10000
large_string = str(bytearray().zfill(10001))
len_255_string = str(bytearray().zfill(255))


@utils.parameterized_test_case
class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsTestCase, self).tearDown()

    @testcase.attr('negative')
    def test_secret_create_nones_content_type(self):
        """Checks that secret creation fails with content type but no payload
        """

        test_model = secret_models.SecretModel(**secret_create_nones_data)
        overrides = {"payload_content_type": "application/octet-stream"}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('positive')
    def test_secret_create_defaults_check_content_types(self):
        """Covers checking that content types attribute is shown when secret
        has encrypted data associated with it.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        resp = self.behaviors.get_secret_metadata(secret_ref)
        content_types = resp.model.content_types
        self.assertIsNotNone(content_types)
        self.assertIn('default', content_types)
        self.assertEqual(content_types['default'],
                         test_model.payload_content_type)

    @testcase.attr('positive')
    def test_secret_create_nones(self):
        """Covers case of a POST request with no JSON data."""
        test_model = secret_models.SecretModel(**secret_create_nones_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('negative')
    def test_secret_create_nones_blank_name_and_valid_content_type(self):
        """Fails since there is no payload
         When a test is created with an empty name attribute, the
         system should return the secret's UUID on a get
         - Reported in Barbican GitHub Issue #89
         """
        test_model = secret_models.SecretModel(**secret_create_nones_data)
        overrides = {"name": "",
                     "payload_content_type": "application/json"}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('negative')
    def test_secret_get_secret_doesnt_exist(self):
        """Covers getting a nonexistent secret."""
        resp = self.behaviors.get_secret_metadata('not_a_uuid')
        self.assertEqual(resp.status_code, 404)

    @testcase.attr('negative')
    def test_secret_delete_doesnt_exist(self):
        """Covers case of deleting a non-existent secret.
        Should return 404.
        """
        resp = self.behaviors.delete_secret('not_a_uuid', expected_fail=True)
        self.assertEqual(resp.status_code, 404)

    @testcase.attr('negative')
    def test_secret_get_invalid_mime_type(self):
        """Covers getting a secret with an invalid mime type."""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        resp = self.behaviors.get_secret(secret_ref,
                                         payload_content_type="i/m")
        self.assertEqual(resp.status_code, 406)

    @testcase.attr('negative')
    def test_secret_create_default_int_as_mode(self):
        """Covers case of creating a secret with an integer as the cypher type.
        Should return 400.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"mode": 400}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('negative')
    def test_secret_create_default_int_as_algorithm(self):
        """Covers case of creating a secret with an integer as the algorithm.
        Should return 400.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"algorithm": 400}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('positive')
    def test_secret_create_defaults_w_charset(self):
        """Covers creating a secret with text/plain; charset=utf-8 as content
        type.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"payload_content_type": 'text/plain; charset=utf-8',
                     "payload_content_encoding": None}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('negative')
    def test_secret_create_defaults_bad_expiration_timezone(self):
        """Covers case of a malformed timezone being added to the expiration.
        - Reported in Barbican GitHub Issue #134
        """
        timestamp = utils.create_timestamp_w_tz_and_offset('-5:00', days=0)

        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"expiration": timestamp}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('positive')
    def test_secret_create_defaults_negative_hour_long_expiration(self):
        """Covers case of a malformed timezone being added to the expiration.
        - Reported in Barbican GitHub Issue #134
        :rtype : object
        """
        timestamp = utils.create_timestamp_w_tz_and_offset('-05:00', days=5)

        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"expiration": timestamp}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('positive')
    def test_secret_create_defaults_positive_hour_long_expiration(self):
        """Covers case of a malformed timezone being added to the expiration.
        - Reported in Barbican GitHub Issue #134
        :rtype : object
        """
        timestamp = utils.create_timestamp_w_tz_and_offset('+05:00', days=5)

        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"expiration": timestamp}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('positive')
    def test_secret_create_defaults_negative_hour_short_expiration(self):
        """Covers case of a malformed timezone being added to the expiration.
        - Reported in Barbican GitHub Issue #134
        :rtype : object
        """
        timestamp = utils.create_timestamp_w_tz_and_offset('-01', days=1)

        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"expiration": timestamp}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('positive')
    def test_secret_create_defaults_positive_hour_short_expiration(self):
        """Covers case of a malformed timezone being added to the expiration.
        - Reported in Barbican GitHub Issue #134
        :rtype : object
        """
        timestamp = utils.create_timestamp_w_tz_and_offset('+01', days=1)

        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"expiration": timestamp}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('negative')
    def test_secret_create_defaults_int_as_name(self):
        """Covers case of creating a secret with an integer as the name.
        Should return 400.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"name": 400}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('positive')
    def test_secret_create_defaults_invalid_algorithm(self):
        """Covers case of creating a secret with an invalid algorithm."""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"algorithm": 'invalid_algorithm'}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_expiration(self):
        """Covers creating secret with expiration that has already passed.
        Should return 400.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"expiration": '2000-01-10T14:58:52.546795'}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('positive')
    def test_secret_create_defaults_max_secret_size(self):
        """Covers case of creating secret whose payload is the maximum size
        allowed by Barbican.
        """
        large_string = str(bytearray().zfill(max_allowed_payload_in_bytes))

        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"payload": large_string}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('negative')
    def test_secret_create_nones_valid_content_type_and_encoding(self):
        """Covers creating secret with only content type and encoding, with
        no payload.  Should return 400.
        """
        test_model = secret_models.SecretModel(**secret_create_nones_data)
        overrides = {"payload_content_type": "application/octet-stream",
                     "payload_content_encoding": "base64"}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('negative')
    def test_secret_creating_defaults_text_plain_mime_type_no_payload(self):
        """Covers case of attempting to create a secret with text/plain as
        mime type, with no payload.  Should result in 400
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"payload": None}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('positive')
    def test_secret_create_defaults_text_plain_payload_content_type(self):
        """Covers case of attempting to create a secret with text/plain as
        mime type
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"payload_content_type": 'text/plain',
                     "payload_content_encoding": None}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)
