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

import base64
import binascii
import json

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

    @testcase.attr('negative')
    def test_secret_create_emptystrings(self):
        """Covers case of creating a secret with empty Strings for all
        entries. Should return a 400.
        """
        test_model = secret_models.SecretModel(
            **secret_create_emptystrings_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('positive')
    def test_secret_create_defaults_empty_name(self):
        """When a test is created with an empty or null name attribute, the
         system should return the secret's UUID on a get
         - Reported in Barbican GitHub Issue #89
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"name": ''}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        get_resp = self.behaviors.get_secret_metadata(secret_ref)
        self.assertIn(get_resp.model.name, secret_ref)

    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_content_type(self):
        """Covers case of creating secret with an invalid content type in
        HTTP header.  Should return 415.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {"Content-Type": "crypto/boom"}

        resp, secret_ref = self.behaviors.create_secret(test_model, headers)
        self.assertEqual(resp.status_code, 415)

    @testcase.attr('positive')
    def test_secret_create_defaults_none_as_bit_length(self):
        """When a test is created with None for the bit length attribute, the
         system should successfully return the secret reference URI.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"bit_length": None}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('positive')
    def test_secret_get_defaults_none_as_bit_length(self):
        """When a test is created with None for the bit length attribute, the
         system should successfully return the secret reference URI.
         A get on the secret should also return a None for bit length.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"bit_length": None}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        get_resp = self.behaviors.get_secret_metadata(secret_ref)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.model.bit_length, None)

    @testcase.attr('positive')
    def test_secret_create_defaults_null_name(self):
        """When a test is created with an empty or null name attribute, the
         system should return the secret's UUID on a get
         - Reported in Barbican GitHub Issue #89
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"name": None}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        get_resp = self.behaviors.get_secret_metadata(secret_ref)
        self.assertIn(get_resp.model.name, secret_ref)

    @testcase.attr('negative')
    def test_secret_create_defaults_oversized_payload(self):
        """Covers creating a secret with a secret that is larger than
        the max secret payload size. Should return a 413 if the secret
        size is greater than the maximum allowed size.
        """
        oversized_payload = max_allowed_payload_in_bytes + 1
        data = str(bytearray().zfill(oversized_payload))

        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"payload": data}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 413)

    @testcase.attr('negative')
    def test_secret_put_doesnt_exist(self):
        """Covers case of putting secret information to a non-existent
        secret. Should return 404.
        """
        resp = self.behaviors.update_secret_payload(
            secret_ref='not_a_uuid',
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload='testing putting to non-existent secret')

        self.assertEqual(resp.status_code, 404)

    @testcase.attr('negative')
    def test_secret_put_defaults_data_already_exists(self):
        """Covers case of putting secret information to a secret that already
        has encrypted data associated with it. Should return 409.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload='testing putting data in secret that already has data')
        self.assertEqual(resp.status_code, 409)

    @testcase.attr('negative')
    def test_secret_put_two_phase_empty_payload(self):
        """Covers case of putting empty String to a secret.
        Should return 400.
        """
        test_model = secret_models.SecretModel(**secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload='')
        self.assertEqual(put_resp.status_code, 400)

    @testcase.attr('negative')
    def test_secret_put_two_phase_invalid_content_type(self):
        """Covers case of putting secret information with an
        invalid content type. Should return 415.
        - Reported in Barbican Launchpad Bug #1208601
        - Updated in Barbican blueprint barbican-enforce-content-type
        """
        test_model = secret_models.SecretModel(**secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='crypto/boom',
            payload_content_encoding='base64',
            payload='invalid content type')
        self.assertEqual(put_resp.status_code, 415)

    @testcase.attr('negative')
    def test_secret_put_two_phase_no_payload(self):
        """Covers case of putting null String to a secret.
        Should return 400.
        """
        test_model = secret_models.SecretModel(**secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=None)
        self.assertEqual(put_resp.status_code, 400)

    @testcase.attr('negative')
    def test_secret_put_two_phase_w_oversized_binary_data_no_utf8(self):
        """Covers case of putting an oversized string with binary data that
        doesn't contain UTF-8 code points.  This tests bug 1315498.
        """
        data = bytearray().zfill(max_allowed_payload_in_bytes + 1)

        # put a value in the middle of the data that does not have a UTF-8
        # code point.  Using // to be python3-friendly.
        data[max_allowed_payload_in_bytes // 2] = b'\xb0'

        test_model = secret_models.SecretModel(**secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=str(data))
        self.assertEqual(put_resp.status_code, 413)

    @testcase.attr('negative')
    def test_secret_put_two_phase_oversized_payload(self):
        """Covers case of putting secret data that is larger than the maximum
        secret size allowed by Barbican. Beyond that it should return 413.
        """
        data = bytearray().zfill(max_allowed_payload_in_bytes + 1)

        test_model = secret_models.SecretModel(**secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=str(data))
        self.assertEqual(put_resp.status_code, 413)

    @testcase.attr('positive')
    def test_secret_put_two_phase_valid_binary_data_no_utf8(self):
        """Covers case of putting a string with binary data that doesn't
        contain UTF-8 code points.  This tests bug 1315498.
        """
        # put a value in the data that does not have a UTF-8 code point.
        data = b'\xb0'

        test_model = secret_models.SecretModel(**secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=str(data))
        self.assertEqual(put_resp.status_code, 204)

    @testcase.attr('positive')
    def test_secret_put_two_phase_high_range_unicode_character(self):
        """Ensure a two step secret creation succeeds with Content-Type
        application/octet-stream and a high range unicode character.
        Launchpad bug #1315498
        """
        data = u'\U0001F37A'
        data = data.encode('utf-8')
        test_model = secret_models.SecretModel(**secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=data)
        self.assertEqual(put_resp.status_code, 204)

    def test_secret_get_nones_payload_with_a_octet_stream(self):
        """Tests getting a secret with octet-stream."""
        test_model = secret_models.SecretModel(**secret_create_two_phase_data)
        overrides = {'payload_content_type': 'application/octet-stream',
                     'payload_content_encoding': 'base64',
                     'payload': base64.b64encode('abcdef')}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        get_resp = self.behaviors.get_secret(
            secret_ref,
            payload_content_type=test_model.payload_content_type,
            payload_content_encoding=test_model.payload_content_encoding)
        self.assertIn(test_model.payload,
                      binascii.b2a_base64(get_resp.content))

    def test_secret_create_defaults_bad_content_type_check_message(self):
        """will create a secret with an "invalid" content type
        (plain-text, rather than text/plain).  This will result in
        an error, and we need to ensure that the error msg is
        reasonable.
        """
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {"payload_content_type": 'plain-text'}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)

        # first, ensure that the return code is 400
        self.assertEqual(resp.status_code, 400)

        resp_dict = json.loads(resp.content)

        self.assertIn(
            "Provided object does not match schema 'Secret': "
            "payload_content_type is not one of ['text/plain', "
            "'text/plain;charset=utf-8', 'text/plain; charset=utf-8', "
            "'application/octet-stream'", resp_dict['description'])
        self.assertIn("Bad Request", resp_dict['title'])
