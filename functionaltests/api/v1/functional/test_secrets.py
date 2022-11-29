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

import datetime
from oslo_serialization import base64 as oslo_base64
from oslo_serialization import jsonutils as json
import sys
import testtools
import time

from testtools import testcase

from barbican.plugin.interface import secret_store as ss
from barbican.plugin.util import translations
from barbican.tests import keys
from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.behaviors import secretstores_behaviors
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config


CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
admin_b = CONF.rbac_users.admin_b


def get_pem_content(pem):
    b64_content = translations.get_pem_components(pem)[1]
    return oslo_base64.decode_as_bytes(b64_content)


def get_private_key_req():
    return {'name': 'myprivatekey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': 'private',
            'payload': oslo_base64.encode_as_bytes(keys.get_private_key_pem())}


def get_public_key_req():
    return {'name': 'mypublickey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': 'public',
            'payload': oslo_base64.encode_as_bytes(keys.get_public_key_pem())}


def get_certificate_req():
    return {'name': 'mycertificate',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': 'certificate',
            'payload': oslo_base64.encode_as_bytes(keys.get_certificate_pem())}


def get_passphrase_req():
    return {'name': 'mypassphrase',
            'payload_content_type': 'text/plain',
            'secret_type': 'passphrase',
            'payload': 'mysecretpassphrase'}


def get_default_data():
    return {
        "name": "AES key",
        "expiration": "2030-02-28T19:14:44.180394",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "payload": get_default_payload(),
        "payload_content_type": "application/octet-stream",
        "payload_content_encoding": "base64",
    }


def get_default_payload():
    return b"AQIDBAUGBwgBAgMEBQYHCAECAwQFBgcIAQIDBAUGBwg="


@utils.parameterized_test_case
class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)

        # make a local mutable copies of the default data to prevent
        # possible data contamination if (when?) the data contains
        # any nested dicts.
        # TODO(tdink) Move to a config file
        self.default_secret_create_data = get_default_data()

        self.default_secret_create_all_none_data = {
            "name": None,
            "expiration": None,
            "algorithm": None,
            "bit_length": None,
            "mode": None,
            "payload": None,
            "payload_content_type": None,
            "payload_content_encoding": None,
        }

        self.default_secret_create_emptystrings_data = {
            "name": '',
            "expiration": '',
            "algorithm": '',
            "bit_length": '',
            "mode": '',
            "payload": '',
            "payload_content_type": '',
            "payload_content_encoding": '',
        }

        self.default_secret_create_two_phase_data = {
            "name": "AES key",
            "expiration": "2030-02-28T19:14:44.180394",
            "algorithm": "aes",
            "bit_length": 256,
            "mode": "cbc",
        }

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsTestCase, self).tearDown()

    @testcase.attr('negative')
    def test_secret_create_with_only_content_type_no_payload(self):
        """Create secret with valid content type but no payload."""

        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)
        test_model.payload_content_type = 'application/octet-stream'

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @testcase.attr('positive')
    def test_secret_create_then_check_content_types(self):
        """Check that set content-type attribute is retained in metadata."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        resp = self.behaviors.get_secret_metadata(secret_ref)
        self.assertEqual(200, resp.status_code)
        content_types = resp.model.content_types
        self.assertIsNotNone(content_types)
        self.assertIn('default', content_types)
        self.assertEqual(content_types['default'],
                         test_model.payload_content_type)

    @testcase.attr('positive')
    def test_secret_create_all_none(self):
        """Covers case of a POST request with no JSON data."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

    @testcase.attr('negative')
    def test_secret_get_secret_doesnt_exist(self):
        """GET a non-existent secret.

        Should return a 404.
        """
        resp = self.behaviors.get_secret_metadata('not_a_uuid')
        self.assertEqual(404, resp.status_code)

    @testcase.attr('negative')
    def test_secret_get_secret_payload_doesnt_exist(self):
        """GET a non-existent payload.

        Should return a 404.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        resp = self.behaviors.get_secret(secret_ref, 'text/plain')
        self.assertEqual(404, resp.status_code)

    @testcase.attr('positive')
    def test_secret_get_payload_no_accept_header(self):
        """GET a secret payload, do not pass in accept header.

        Should return a 200.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        get_resp = self.behaviors.get_secret(
            secret_ref,
            payload_content_type='',
            omit_headers=['Accept'])
        self.assertEqual(200, get_resp.status_code)
        self.assertEqual(test_model.payload,
                         oslo_base64.encode_as_bytes(get_resp.content))

    @testcase.attr('negative')
    def test_secret_delete_doesnt_exist(self):
        """DELETE a non-existent secret.

        Should return a 404.
        """
        resp = self.behaviors.delete_secret('not_a_uuid', expected_fail=True)
        self.assertEqual(404, resp.status_code)

    @testcase.attr('negative')
    def test_secret_get_invalid_mime_type(self):
        """Covers getting a secret with an invalid mime type."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        resp = self.behaviors.get_secret(secret_ref,
                                         payload_content_type="i/m")
        self.assertEqual(406, resp.status_code)

    @testcase.attr('negative')
    def test_secret_create_with_expiration_passed(self):
        """Create a secret with an expiration that has already passed.

        Should return a 400.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.expiration = '2000-01-10T14:58:52.546795'

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @testcase.attr('negative')
    def test_secret_create_with_empty_strings(self):
        """Secret create with empty Strings for all attributes.

        Should return a 400.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_emptystrings_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @testcase.attr('negative')
    def test_secret_create_with_invalid_content_type(self):
        """Create secret with an invalid content type in HTTP header.

        Should return a 415.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)

        headers = {"Content-Type": "crypto/boom"}

        resp, secret_ref = self.behaviors.create_secret(test_model, headers)
        self.assertEqual(415, resp.status_code)

    @testcase.attr('negative')
    def test_secret_create_with_oversized_payload(self):
        """Create a secret that is larger than the max payload size.

        Should return a 413 if the secret size is greater than the
        maximum allowed size.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.payload = self.oversized_payload

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(413, resp.status_code)

    @testcase.attr('negative')
    def test_secret_put_when_payload_doesnt_exist(self):
        """PUT secret to a non-existent secret.

        Should return 404.
        """
        resp = self.behaviors.update_secret_payload(
            secret_ref='not_a_uuid',
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload='testing putting to non-existent secret')

        self.assertEqual(404, resp.status_code)

    @testcase.attr('negative')
    def test_secret_put_when_payload_already_exists(self):
        """PUT against a secret that already has encrypted data.

        Should return 409.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload='testing putting data in secret that already has data')
        self.assertEqual(409, resp.status_code)

    @testcase.attr('negative')
    def test_secret_put_two_phase_empty_payload(self):
        """Covers case of putting empty String to a secret.

        Should return 400.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload='')
        self.assertEqual(400, put_resp.status_code)

    @testcase.attr('negative')
    def test_secret_put_two_phase_invalid_content_type(self):
        """PUT with an invalid content type. Should return 415.

        Launchpad bug #1208601
        - Updated in Barbican blueprint barbican-enforce-content-type
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='crypto/boom',
            payload_content_encoding='base64',
            payload='invalid content type')
        self.assertEqual(415, put_resp.status_code)

    @testcase.attr('negative')
    def test_secret_put_two_phase_no_payload(self):
        """Covers case of putting null String to a secret.

        Should return 400.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=None)
        self.assertEqual(400, put_resp.status_code)

    @testcase.attr('negative')
    def test_secret_put_two_phase_w_oversized_binary_data_not_utf8(self):
        """PUT with an oversized binary string that isn't UTF-8.

        Launchpad bug #1315498.
        """
        oversized_payload = bytearray(self.oversized_payload)

        # put a value in the middle of the data that does not have a UTF-8
        # code point.  Using // and 176 to be python3-friendly.
        oversized_payload[self.max_payload_size // 2] = 176  # 0xb0

        test_model = secret_models.SecretModel(
            **self.default_secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=oversized_payload)
        self.assertEqual(413, put_resp.status_code)

    @testcase.attr('negative')
    def test_secret_put_two_phase_oversized_payload(self):
        """PUT with oversized payload should return 413.

        Covers the case of putting secret data that is larger than the maximum
        secret size allowed by Barbican. Beyond that it should return 413.
        """
        oversized_payload = self.oversized_payload

        test_model = secret_models.SecretModel(
            **self.default_secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=oversized_payload)
        self.assertEqual(413, put_resp.status_code)

    @testcase.attr('positive')
    def test_secret_put_two_phase_valid_binary_data_not_utf8(self):
        """A string with binary data that doesn't contain UTF-8 code points.

        Launchpad bug #1315498.
        """
        # put a value in the data that does not have a UTF-8 code point.
        data = b'\xb0'

        test_model = secret_models.SecretModel(
            **self.default_secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=str(data))
        self.assertEqual(204, put_resp.status_code)

    @testcase.attr('positive')
    def test_secret_put_two_phase_high_range_unicode_character(self):
        """Tests a high-range unicode character on a two-step PUT.

        Launchpad bug #1315498
        """
        data = '\U0001F37A'
        data = data.encode('utf-8')
        test_model = secret_models.SecretModel(
            **self.default_secret_create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        put_resp = self.behaviors.update_secret_payload(
            secret_ref=secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            payload=data)
        self.assertEqual(204, put_resp.status_code)

    @testcase.attr('positive')
    def test_secret_get_nones_payload_with_a_octet_stream(self):
        """Tests getting a secret with octet-stream."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_two_phase_data)
        test_model.payload_content_encoding = 'base64'
        test_model.payload_content_type = 'application/octet-stream'
        test_model.payload = oslo_base64.encode_as_bytes('abcdef')

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        get_resp = self.behaviors.get_secret(
            secret_ref,
            payload_content_type=test_model.payload_content_type,
            payload_content_encoding=test_model.payload_content_encoding)
        self.assertEqual(200, get_resp.status_code)
        self.assertEqual(test_model.payload,
                         oslo_base64.encode_as_bytes(get_resp.content))

    @testcase.attr('negative')
    def test_secret_create_defaults_bad_content_type_check_message(self):
        """Verifying the returned error message matches the expected form."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.payload_content_type = 'plain-text'

        resp, secret_ref = self.behaviors.create_secret(test_model)

        # first, ensure that the return code is 400
        self.assertEqual(400, resp.status_code)

        resp_dict = json.loads(resp.content)

        self.assertIn(
            "Provided object does not match schema 'Secret': "
            "payload_content_type is not one of ['text/plain', "
            "'text/plain;charset=utf-8', 'text/plain; charset=utf-8', "
            "'application/octet-stream'", resp_dict['description'])
        self.assertIn("Bad Request", resp_dict['title'])

    @testcase.attr('negative')
    def test_secret_create_then_expire_then_check(self):
        """Covers case where you try to retrieve a secret that is expired.

        This test creates a secret that will soon expire.
        After it expires, check it and verify that it is no longer
        a valid secret.
        """

        # create a secret that expires in 15 seconds
        timestamp = utils.create_timestamp_w_tz_and_offset(seconds=15)

        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.expiration = timestamp

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # now get the secret - will be still valid
        get_resp = self.behaviors.get_secret_metadata(secret_ref)
        self.assertEqual(200, get_resp.status_code)

        # now wait 20 seconds
        time.sleep(20)

        # now get the secret - should be invalid (expired)
        resp = self.behaviors.get_secret_metadata(secret_ref)
        self.assertEqual(404, resp.status_code)

    @utils.parameterized_dataset({
        'alphanumeric': ['1f34ds'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'len_255': [base.TestCase.max_sized_field],
        'empty': [''],
        'null': [None]
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_name(self, name):
        """Covers cases of creating secrets with valid names."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.name = name

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

    @utils.parameterized_dataset({
        'int': [400]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_name(self, name):
        """Create secrets with various invalid names.

        Should return 400.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.name = name

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @testcase.attr('positive', 'non-standard-algorithm')
    @testtools.skipIf(utils.is_kmip_enabled(),
                      "KMIP does not support invalid algorithms")
    def test_secret_create_valid_algorithms(self):
        """Creates secrets with various valid algorithms."""
        algorithm = 'invalid'
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.algorithm = algorithm

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

    @utils.parameterized_dataset({
        'int': [400]
    })
    @testcase.attr('negative')
    def test_secret_create_invalid_algorithms(self, algorithm):
        """Creates secrets with various invalid algorithms."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.algorithm = algorithm

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @testtools.skipIf(utils.is_kmip_enabled(),
                      "KMIP does not support non-standard bit lengths")
    @utils.parameterized_dataset({
        'sixteen': [16],
        'fifteen': [15],
        'eight': [8],
        'seven': [7],
        'one': [1],
        'none': [None]
    })
    @testcase.attr('positive', 'non-standard-algorithm')
    def test_secret_create_with_non_standard_bit_length(self, bit_length):
        """Covers cases of creating secrets with valid bit lengths."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.bit_length = bit_length

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

    @utils.parameterized_dataset({
        '128': [128],
        '192': [192],
        '256': [256]
    })
    @testcase.attr('positive')
    def test_secret_create_with_valid_bit_length(self, bit_length):
        """Covers cases of creating secrets with valid bit lengths."""
        byte_length = bit_length // 8
        secret = bytearray(byte_length)
        for x in range(0, byte_length):
            secret[x] = x
        secret64 = oslo_base64.encode_as_bytes(secret)

        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.bit_length = bit_length
        test_model.payload = secret64

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

    @utils.parameterized_dataset({
        'str_type': ['not-an-int'],
        'empty': [''],
        'blank': [' '],
        'negative_maxint': [-sys.maxsize],
        'negative_one': [-1],
        'zero': [0]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_bit_length(self, bit_length):
        """Covers cases of creating secrets with invalid bit lengths."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.bit_length = bit_length

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @utils.parameterized_dataset({
        'cbc': ['cbc'],
        'unknown_positive': ['unknown']
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_mode(self, mode):
        """Covers cases of creating secrets with valid modes."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.mode = mode

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

    @utils.parameterized_dataset({
        'zero': [0],
        'oversized_string': [base.TestCase.oversized_field],
        'int': [400]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_mode(self, mode):
        """Covers cases of creating secrets with invalid modes."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.mode = mode

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @utils.parameterized_dataset({
        'text_content_type_none_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': None},

        # TODO(dmend): Fix content negotiation
        # 'utf8_text_content_type_none_encoding': {
        #    'payload_content_type': 'text/plain; charset=utf-8',
        #    'payload_content_encoding': None},

        # 'no_space_utf8_text_content_type_none_encoding': {
        #    'payload_content_type': 'text/plain;charset=utf-8',
        #    'payload_content_encoding': None},

        'octet_content_type_base64_encoding': {
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64'}
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_types_and_encoding(
            self, payload_content_type, payload_content_encoding):
        """Creates secrets with various content types and encodings."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.payload_content_type = payload_content_type
        test_model.payload_content_encoding = payload_content_encoding

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        get_resp = self.behaviors.get_secret(
            secret_ref,
            payload_content_type=payload_content_type,
            payload_content_encoding=payload_content_encoding)
        self.assertEqual(200, get_resp.status_code)

        if payload_content_encoding == 'base64':
            self.assertEqual(test_model.payload,
                             oslo_base64.encode_as_bytes(get_resp.content))
        else:
            self.assertEqual(test_model.payload, get_resp.content)

    @utils.parameterized_dataset({
        'text_content_type_none_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': None},

        # TODO(dmend): Fix content negotiation
        # 'utf8_text_content_type_none_encoding': {
        #    'payload_content_type': 'text/plain; charset=utf-8',
        #    'payload_content_encoding': None},

        # 'no_space_utf8_text_content_type_none_encoding': {
        #    'payload_content_type': 'text/plain;charset=utf-8',
        #    'payload_content_encoding': None},

        'octet_content_type_base64_encoding': {
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64'}
    })
    @testcase.attr('positive', 'deprecated')
    def test_secret_create_defaults_valid_types_and_encoding_old_way(
            self, payload_content_type, payload_content_encoding):
        """Creates secrets with various content types and encodings."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.payload_content_type = payload_content_type
        test_model.payload_content_encoding = payload_content_encoding

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        get_resp = self.behaviors.get_secret_based_on_content_type(
            secret_ref,
            payload_content_type=payload_content_type,
            payload_content_encoding=payload_content_encoding)
        self.assertEqual(200, get_resp.status_code)

        if payload_content_encoding == 'base64':
            self.assertEqual(test_model.payload,
                             oslo_base64.encode_as_bytes(get_resp.content))
        else:
            self.assertEqual(test_model.payload, get_resp.content)

    @utils.parameterized_dataset({
        'empty_content_type_and_encoding': {
            'payload_content_type': '',
            'payload_content_encoding': ''},

        'none_content_type_and_encoding': {
            'payload_content_type': None,
            'payload_content_encoding': None},

        'large_string_content_type_and_encoding': {
            'payload_content_type': base.TestCase.oversized_field,
            'payload_content_encoding': base.TestCase.oversized_field},

        'int_content_type_and_encoding': {
            'payload_content_type': 123,
            'payload_content_encoding': 123},

        'none_content_type_base64_content_encoding': {
            'payload_content_type': None,
            'payload_content_encoding': 'base64'},

        'text_content_type_none_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': ''},

        'text_no_subtype_content_type_none_content_encoding': {
            'payload_content_type': 'text',
            'payload_content_encoding': None},

        'text_slash_no_subtype_content_type_none_content_encoding': {
            'payload_content_type': 'text/',
            'payload_content_encoding': None},

        'text_content_type_empty_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': ' '},

        'text_content_type_spaces_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': '       '},

        'text_content_type_base64_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': 'base64'},

        'text_and_utf88_content_type_none_content_encoding': {
            'payload_content_type': 'text/plain; charset=utf-88',
            'payload_content_encoding': None},

        'invalid_content_type_base64_content_encoding': {
            'payload_content_type': 'invalid',
            'payload_content_encoding': 'base64'},

        'invalid_content_type_none_content_encoding': {
            'payload_content_type': 'invalid',
            'payload_content_encoding': None},

        'octet_content_type_invalid_content_encoding': {
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'invalid'},

        'text_content_type_invalid_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': 'invalid'},

        'none_content_type_invalid_content_encoding': {
            'payload_content_type': None,
            'payload_content_encoding': 'invalid'},
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_types_and_encoding(
            self, payload_content_type, payload_content_encoding):
        """Creating secrets with invalid payload types and encodings."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.payload_content_type = payload_content_type
        test_model.payload_content_encoding = payload_content_encoding

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @utils.parameterized_dataset({
        'max_payload_string': [base.TestCase.max_sized_payload]
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_payload(self, payload):
        """Create secrets with a various valid payloads."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        overrides = {"payload": payload}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

    @utils.parameterized_dataset({
        'empty': [''],
        'array': [['boom']],
        'int': [123],
        'none': [None],
        'bad_character': [chr(0x0080)],
        'bad_characters': [chr(0x1111) + chr(0xffff)]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_payload(self, payload):
        """Covers creating secrets with various invalid payloads."""
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        overrides = {"payload_content_type": "application/octet-stream",
                     "payload_content_encoding": "base64",
                     "payload": payload}
        test_model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @utils.parameterized_dataset({
        'negative_five_long_expire': {
            'timezone': '-05:00',
            'days': 5},

        'positive_five_long_expire': {
            'timezone': '+05:00',
            'days': 5},

        'negative_one_short_expire': {
            'timezone': '-01',
            'days': 1},

        'positive_one_short_expire': {
            'timezone': '+01',
            'days': 1}
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_expiration(self, timezone, days):
        """Create secrets with a various valid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(timezone=timezone,
                                                           days=days)

        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.expiration = timestamp

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

    @utils.parameterized_dataset({
        'malformed_timezone': {
            'timezone': '-5:00',
            'days': 0}
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_expiration(self, timezone, days):
        """Create secrets with various invalid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(timezone=timezone,
                                                           days=days)

        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.expiration = timestamp

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)

    @testcase.skipIf(not base.conf_host_href_used, 'response href using '
                     'wsgi request instead of CONF.host_href')
    @testcase.attr('positive')
    def test_secret_create_change_host_with_header_not_allowed(self, **kwargs):
        """Create a secret with a (possibly) malicious host name in header."""

        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)

        malicious_hostname = 'some.bad.server.com'
        changed_host_header = {'Host': malicious_hostname}

        resp, secret_ref = self.behaviors.create_secret(
            test_model, extra_headers=changed_host_header)

        self.assertEqual(201, resp.status_code)

        # get Location field from result and assert that it is NOT the
        # malicious one.
        regex = '.*{0}.*'.format(malicious_hostname)
        self.assertNotRegex(resp.headers['location'], regex)

    @testcase.skipIf(base.conf_host_href_used, 'response href using '
                     'CONF.host_href instead of wsgi request')
    @testcase.attr('positive')
    def test_secret_get_change_host_with_header_allowed(self, **kwargs):
        """Get secret metadata with alternative proxy host name in header."""

        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)

        another_proxy_hostname = 'proxy2.server.com'
        changed_host_header = {'Host': another_proxy_hostname}

        # In test, cannot pass different host header during create as returned
        # secret_ref in response contains that host in url. That url is used in
        # deleting that secret during cleanup step
        resp, secret_ref = self.behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)

        resp = self.behaviors.get_secret_metadata(
            secret_ref, extra_headers=changed_host_header)
        # Check returned href has provided proxy hostname
        regex = '.*{0}.*'.format(another_proxy_hostname)
        self.assertRegex(resp.model.secret_ref, regex)

    @utils.parameterized_dataset({
        'symmetric': ['symmetric',
                      oslo_base64.decode_as_bytes(
                          get_default_payload()),
                      get_default_data()],
        'private': ['private',
                    keys.get_private_key_pem(),
                    get_private_key_req()],
        'public': ['public',
                   keys.get_public_key_pem(),
                   get_public_key_req()],
        'certificate': ['certificate',
                        keys.get_certificate_pem(),
                        get_certificate_req()],
        'passphrase': ['passphrase',
                       b'mysecretpassphrase',
                       get_passphrase_req()]
    })
    @testcase.attr('positive')
    def test_secret_create_with_secret_type(self, secret_type, expected, spec):
        """Create secrets with various secret types."""
        test_model = secret_models.SecretModel(**spec)
        test_model.secret_type = secret_type

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        resp = self.behaviors.get_secret_metadata(secret_ref)
        secret_type_response = resp.model.secret_type
        self.assertIsNotNone(secret_type_response)
        self.assertEqual(secret_type, secret_type_response)

        content_type = spec['payload_content_type']
        get_resp = self.behaviors.get_secret(secret_ref,
                                             content_type)
        self.assertEqual(expected, get_resp.content)

    @utils.parameterized_dataset({
        'invalid_http_content_type_characaters_latin': {
            'http_content_type': '\u00c4'.encode('utf-8')},

        'invalid_http_content_type_characaters_arabic': {
            'http_content_type': '\u060f'.encode('utf-8')},

        'invalid_http_content_type_characaters_cyrillic': {
            'http_content_type': '\u0416'.encode('utf-8')},

        'invalid_http_content_type_characaters_replacement_character': {
            'http_content_type': '\ufffd'.encode('utf-8')},
    })
    @testcase.attr('negative')
    def test_secret_create_with_invalid_http_content_type_characters(
            self, http_content_type):
        """Attempt to create secrets with invalid unicode characters in the

        HTTP request's Content-Type header. Should return a 415.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)

        headers = {"Content-Type": http_content_type}

        resp, secret_ref = self.behaviors.create_secret(test_model, headers)
        self.assertEqual(415, resp.status_code)

    @utils.parameterized_dataset({
        'invalid_http_content_type_characaters_latin': {
            'payload_content_type': '\u00c4'.encode('utf-8')},

        'invalid_http_content_type_characaters_arabic': {
            'payload_content_type': '\u060f'.encode('utf-8')},

        'invalid_http_content_type_characaters_cyrillic': {
            'payload_content_type': '\u0416'.encode('utf-8')},

        'invalid_http_content_type_characaters_replacement_character': {
            'payload_content_type': '\ufffd'.encode('utf-8')},
    })
    @testcase.attr('negative')
    def test_secret_create_with_invalid_payload_content_type_characters(
            self, payload_content_type):
        """Attempt to create secrets with non-ascii characters in the

        payload's content type attribute. Should return a 400.
        """
        test_model = secret_models.SecretModel(
            **self.default_secret_create_data)
        test_model.payload_content_type = payload_content_type

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(400, resp.status_code)


@utils.parameterized_test_case
class ListingSecretsTestCase(base.TestCase):

    def setUp(self):
        super(ListingSecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(ListingSecretsTestCase, self).tearDown()

    @utils.parameterized_dataset({
        'query_by_name': {
            'secret_1_dict': dict(name="name1"),
            'secret_2_dict': dict(name="name2"),
            'query_dict': dict(name="name1")
        },
        'query_by_algorithm': {
            'secret_1_dict': dict(algorithm="algorithm1"),
            'secret_2_dict': dict(algorithm="algorithm2"),
            'query_dict': dict(alg="algorithm1")
        },
        'query_by_mode': {
            'secret_1_dict': dict(mode="mode1"),
            'secret_2_dict': dict(mode="mode2"),
            'query_dict': dict(mode="mode1")
        },
        'query_by_bit_length': {
            'secret_1_dict': dict(bit_length=1024),
            'secret_2_dict': dict(bit_length=2048),
            'query_dict': dict(bits=1024)
        },
        'query_by_secret_type': {
            'secret_1_dict': dict(secret_type=ss.SecretType.SYMMETRIC),
            'secret_2_dict': dict(secret_type=ss.SecretType.OPAQUE),
            'query_dict': dict(secret_type=ss.SecretType.SYMMETRIC)
        },
    })
    @testcase.attr('positive')
    def test_secret_list_with_filter(self, secret_1_dict, secret_2_dict,
                                     query_dict):
        secret_1 = secret_models.SecretModel(**secret_1_dict)
        secret_2 = secret_models.SecretModel(**secret_2_dict)

        self.behaviors.create_secret(secret_1)
        self.behaviors.create_secret(secret_2)

        resp, secrets_list, next_ref, prev_ref = self.behaviors.get_secrets(
            **query_dict)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(secrets_list))

    @utils.parameterized_dataset({
        'created': {
            'date_type': 'created',
        },
        'updated': {
            'date_type': 'updated',
        },
        'expiration': {
            'date_type': 'expiration',
        },
    })
    @testcase.attr('positive')
    def test_secret_list_with_date_filter(self, date_type):
        expiration_1 = str(
            datetime.datetime.utcnow() + datetime.timedelta(days=3))
        expiration_2 = str(
            datetime.datetime.utcnow() + datetime.timedelta(days=5))

        two_phase_model = secret_models.SecretModel(expiration=expiration_1)
        resp, secret_ref_1 = self.behaviors.create_secret(two_phase_model)
        # Assert that the secret metadata was created successfully
        self.assertEqual(201, resp.status_code)
        payload = "gF6+lLoF3ohA9aPRpt+6bQ=="
        payload_content_type = "application/octet-stream"
        payload_content_encoding = "base64"
        update_resp = self.behaviors.update_secret_payload(
            secret_ref_1, payload=payload,
            payload_content_type=payload_content_type,
            payload_content_encoding=payload_content_encoding)
        # Assert that the secret payload was uploaded successfully
        self.assertEqual(204, update_resp.status_code)

        time.sleep(1)
        model = secret_models.SecretModel(expiration=expiration_2)
        resp, secret_ref_2 = self.behaviors.create_secret(model)

        resp_1 = self.behaviors.get_secret_metadata(secret_ref_1)
        resp_2 = self.behaviors.get_secret_metadata(secret_ref_2)

        time_to_search_1 = getattr(resp_1.model, date_type)
        time_to_search_2 = getattr(resp_2.model, date_type)

        # Search for secrets with secret 1's time
        query_dict = {date_type: time_to_search_1}

        resp, secrets_list, next_ref, prev_ref = self.behaviors.get_secrets(
            **query_dict)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(secrets_list))
        self.assertEqual(secret_ref_1, secrets_list[0].secret_ref)

        # Search for secrets with time < secret 2, i.e. secret 1
        query_dict = {date_type: 'lt:' + time_to_search_2}

        resp, secrets_list, next_ref, prev_ref = self.behaviors.get_secrets(
            **query_dict)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(secrets_list))
        self.assertEqual(secret_ref_1, secrets_list[0].secret_ref)

        # Search for secrets with time <= secret 2, i.e. both secrets
        query_dict = {date_type: 'lte:' + time_to_search_2,
                      'sort': date_type + ':asc'}

        resp, secrets_list, next_ref, prev_ref = self.behaviors.get_secrets(
            **query_dict)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(2, len(secrets_list))
        self.assertEqual(secret_ref_1, secrets_list[0].secret_ref)
        self.assertEqual(secret_ref_2, secrets_list[1].secret_ref)

        # Search for secrets with time > secret 1, i.e. secret 2
        query_dict = {date_type: 'gt:' + time_to_search_1}

        resp, secrets_list, next_ref, prev_ref = self.behaviors.get_secrets(
            **query_dict)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(secrets_list))
        self.assertEqual(secret_ref_2, secrets_list[0].secret_ref)

        # Search for secrets with time >= secret 1, i.e. both secrets
        query_dict = {date_type: 'gte:' + time_to_search_1,
                      'sort': date_type + ':asc'}

        resp, secrets_list, next_ref, prev_ref = self.behaviors.get_secrets(
            **query_dict)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(2, len(secrets_list))
        self.assertEqual(secret_ref_1, secrets_list[0].secret_ref)
        self.assertEqual(secret_ref_2, secrets_list[1].secret_ref)


class SecretsPagingTestCase(base.PagingTestCase):

    def setUp(self):
        super(SecretsPagingTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)

        # make a local mutable copy of the default data to prevent
        # possible data contamination
        self.create_default_data = get_default_data()

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsPagingTestCase, self).tearDown()

    def create_model(self):
        return secret_models.SecretModel(**self.create_default_data)

    def create_resources(self, count=0, model=None):
        for x in range(0, count):
            self.behaviors.create_secret(model)

    def get_resources(self, limit=10, offset=0, filter=None):
        return self.behaviors.get_secrets(limit=limit, offset=offset,
                                          name=filter)

    def set_filter_field(self, unique_str, model):
        '''Set the name field which we use in the get_resources '''
        model.name = unique_str


class SecretsUnauthedTestCase(base.TestCase):

    def setUp(self):
        super(SecretsUnauthedTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.default_secret_create_data = get_default_data()
        self.dummy_secret_ref = 'orders/dummy-7b86-4071-935d-ef6b83729200'
        self.dummy_project_id = 'dummy'

        resp, self.real_secret_ref = self.behaviors.create_secret(
            secret_models.SecretModel(**self.default_secret_create_data)
        )

        stored_auth = self.client._auth[
            self.client._default_user_name].stored_auth
        project_id = list(stored_auth.values())[0]['project_id']
        self.project_id_header = {
            'X-Project-Id': project_id
        }
        self.dummy_project_id_header = {
            'X-Project-Id': self.dummy_project_id
        }

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsUnauthedTestCase, self).tearDown()

    @testcase.attr('negative', 'security')
    def test_secret_create_unauthed_no_proj_id(self):
        """Attempt to create a secret without a token or project id

        Should return 401
        """

        model = secret_models.SecretModel(self.default_secret_create_data)
        resp, secret_ref = self.behaviors.create_secret(model, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_create_unauthed_fake_proj_id(self):
        """Attempt to create a secret with a project id but no token

        Should return 401
        """

        model = secret_models.SecretModel(self.default_secret_create_data)

        resp, secret_ref = self.behaviors.create_secret(
            model, extra_headers=self.dummy_project_id_header, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_create_unauthed_real_proj_id(self):
        """Attempt to create a secret with a project id but no token

        Should return 401
        """

        model = secret_models.SecretModel(self.default_secret_create_data)

        resp, secret_ref = self.behaviors.create_secret(
            model, extra_headers=self.project_id_header, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_get_unauthed_no_proj_id_fake_secret(self):
        """Attempt to read a non-existant secret without a token or project id

        Should return 401
        """

        resp = self.behaviors.get_secret(
            self.dummy_secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64', use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_get_unauthed_no_proj_id_real_secret(self):
        """Attempt to read an existing secret without a token or project id

        Should return 401
        """

        resp = self.behaviors.get_secret(
            self.real_secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64', use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_get_unauthed_fake_proj_id_fake_secret(self):
        """Attempt to get a non-existant secret with a project id but no token

        Should return 401
        """

        resp = self.behaviors.get_secret(
            self.dummy_secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            extra_headers=self.dummy_project_id_header,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_get_unauthed_fake_proj_id_real_secret(self):
        """Attempt to get an existing secret with a project id but no token

        Should return 401
        """

        resp = self.behaviors.get_secret(
            self.real_secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            extra_headers=self.dummy_project_id_header,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_get_unauthed_real_proj_id_fake_secret(self):
        """Attempt to get a non-existant secret with a project id but no token

        Should return 401
        """

        resp = self.behaviors.get_secret(
            self.dummy_secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            extra_headers=self.project_id_header,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_get_unauthed_real_proj_id_real_secret(self):
        """Attempt to get an existing secret with a project id but no token

        Should return 401
        """

        resp = self.behaviors.get_secret(
            self.real_secret_ref,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            extra_headers=self.project_id_header,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_put_unauthed_no_proj_id_fake_secret(self):
        """Attempt to update a non-existant secret without a token or project id

        Should return 401
        """

        resp = self.behaviors.update_secret_payload(
            self.dummy_secret_ref, payload=None,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64', use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_put_unauthed_no_proj_id_real_secret(self):
        """Attempt to update an existing secret without a token or project id

        Should return 401
        """

        resp = self.behaviors.update_secret_payload(
            self.real_secret_ref, payload=None,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64', use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_put_unauthed_fake_proj_id_fake_secret(self):
        """Attempt to update a non-existant secret with a project id, but no token

        Should return 401
        """

        resp = self.behaviors.update_secret_payload(
            self.dummy_secret_ref, payload=None,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            extra_headers=self.dummy_project_id_header,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_put_unauthed_fake_proj_id_real_secret(self):
        """Attempt to update an existing secret with a project id, but no token

        Should return 401
        """

        resp = self.behaviors.update_secret_payload(
            self.real_secret_ref, payload=None,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            extra_headers=self.dummy_project_id_header,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_put_unauthed_real_proj_id_fake_secret(self):
        """Attempt to update a non-existant secret with a project id, but no token

        Should return 401
        """

        resp = self.behaviors.update_secret_payload(
            self.dummy_secret_ref, payload=None,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            extra_headers=self.project_id_header,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_put_unauthed_real_proj_id_real_secret(self):
        """Attempt to update an existing secret with a project id, but no token

        Should return 401
        """

        resp = self.behaviors.update_secret_payload(
            self.real_secret_ref, payload=None,
            payload_content_type='application/octet-stream',
            payload_content_encoding='base64',
            extra_headers=self.project_id_header,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_delete_unauthed_no_proj_id_fake_secret(self):
        """Attempt to delete a non-existant secret without a token or project id

        Should return 401
        """

        resp = self.behaviors.delete_secret(
            self.dummy_secret_ref, expected_fail=True, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_delete_unauthed_no_proj_id_real_secret(self):
        """Attempt to delete an existing secret without a token or project id

        Should return 401
        """

        resp = self.behaviors.delete_secret(
            self.real_secret_ref, expected_fail=True, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_delete_unauthed_fake_proj_id_fake_secret(self):
        """Attempt to delete a non-existant secret with a project id, but no token

        Should return 401
        """

        resp = self.behaviors.delete_secret(
            self.dummy_secret_ref,
            extra_headers=self.dummy_project_id_header, expected_fail=True,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_delete_unauthed_fake_proj_id_real_secret(self):
        """Attempt to delete an existing secret with a project id, but no token

        Should return 401
        """

        resp = self.behaviors.delete_secret(
            self.real_secret_ref,
            extra_headers=self.dummy_project_id_header, expected_fail=True,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_delete_unauthed_real_proj_id_fake_secret(self):
        """Attempt to delete a non-existant secret with a project id, but no token

        Should return 401
        """

        resp = self.behaviors.delete_secret(
            self.dummy_secret_ref,
            extra_headers=self.project_id_header, expected_fail=True,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_delete_unauthed_real_proj_id_real_secret(self):
        """Attempt to delete an existing secret with a project id, but no token

        Should return 401
        """

        resp = self.behaviors.delete_secret(
            self.real_secret_ref,
            extra_headers=self.project_id_header, expected_fail=True,
            use_auth=False
        )
        self.assertEqual(401, resp.status_code)


@utils.parameterized_test_case
class SecretsMultipleBackendTestCase(base.TestCase):

    def setUp(self):
        super(SecretsMultipleBackendTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.ss_behaviors = secretstores_behaviors.SecretStoresBehaviors(
            self.client)
        self.default_secret_create_data = get_default_data()
        if base.conf_multiple_backends_enabled:
            # set preferred secret store for admin_a (project a) user
            # and don't set preferred secret store for admin_b (project b) user
            resp, stores = self.ss_behaviors.get_all_secret_stores(
                user_name=admin_a)
            self.assertEqual(200, resp.status_code)
            global_ss = None
            first_non_global_ss = None
            for store in stores['secret_stores']:
                if store['global_default']:
                    global_ss = store['secret_store_ref']
                else:
                    first_non_global_ss = store['secret_store_ref']
                    break
            self.ss_behaviors.set_preferred_secret_store(
                first_non_global_ss or global_ss,
                user_name=admin_a
            )

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        if base.conf_multiple_backends_enabled:
            self.ss_behaviors.cleanup_preferred_secret_store_entities()
        super(SecretsMultipleBackendTestCase, self).tearDown()

    @testcase.skipUnless(base.conf_multiple_backends_enabled, 'executed only '
                         'when multiple backends support is enabled in '
                         'barbican server side')
    @utils.parameterized_dataset({
        'symmetric_type_preferred_store': [
            admin_a,
            'symmetric',
            oslo_base64.decode_as_bytes(get_default_payload()),
            get_default_data()
        ],
        'private_type_preferred_store': [
            admin_a,
            'private',
            keys.get_private_key_pem(),
            get_private_key_req()
        ],
        'public_type_preferred_store': [
            admin_a,
            'public',
            keys.get_public_key_pem(),
            get_public_key_req()
        ],
        'certificate_type_preferred_store': [
            admin_a,
            'certificate',
            keys.get_certificate_pem(),
            get_certificate_req()
        ],
        'passphrase_type_preferred_store': [
            admin_a,
            'passphrase',
            'mysecretpassphrase',
            get_passphrase_req()
        ],
        'symmetric_type_no_preferred_store': [
            admin_b,
            'symmetric',
            oslo_base64.decode_as_bytes(get_default_payload()),
            get_default_data()
        ],
        'private_type_no_preferred_store': [
            admin_b,
            'private',
            keys.get_private_key_pem(),
            get_private_key_req()
        ],
        'public_type_no_preferred_store': [
            admin_b,
            'public',
            keys.get_public_key_pem(),
            get_public_key_req()
        ],
        'certificate_type_no_preferred_store': [
            admin_b,
            'certificate',
            keys.get_certificate_pem(),
            get_certificate_req()
        ],
        'passphrase_type_no_preferred_store': [
            admin_b,
            'passphrase',
            b'mysecretpassphrase',
            get_passphrase_req()
        ],
    })
    def test_secret_create_for(self, user_name, secret_type, expected, spec):
        """Create secrets with various secret types with multiple backends."""
        test_model = secret_models.SecretModel(**spec)
        test_model.secret_type = secret_type

        resp, secret_ref = self.behaviors.create_secret(test_model,
                                                        user_name=user_name,
                                                        admin=user_name)
        self.assertEqual(201, resp.status_code)

        resp = self.behaviors.get_secret_metadata(secret_ref,
                                                  user_name=user_name)
        secret_type_response = resp.model.secret_type
        self.assertIsNotNone(secret_type_response)
        self.assertEqual(secret_type, secret_type_response)

        content_type = spec['payload_content_type']
        get_resp = self.behaviors.get_secret(secret_ref,
                                             content_type,
                                             user_name=user_name)
        self.assertEqual(expected, get_resp.content)
