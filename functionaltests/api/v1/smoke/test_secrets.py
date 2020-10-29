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
import copy

from oslo_serialization import base64 as oslo_base64
from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import secret_models

default_secret_create_data = {
    "name": "AES key",
    "expiration": "2030-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": b"gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

# Any field with None will be created in the model with None as the value
# but will be omitted in the final request to the server.
#
# secret_create_nones_data is effectively an empty json request to the server.
default_secret_create_all_none_data = {
    "name": None,
    "expiration": None,
    "algorithm": None,
    "bit_length": None,
    "mode": None,
    "payload": None,
    "payload_content_type": None,
    "payload_content_encoding": None,
}

default_secret_create_emptystrings_data = {
    "name": '',
    "expiration": '',
    "algorithm": '',
    "bit_length": '',
    "mode": '',
    "payload": b'',
    "payload_content_type": '',
    "payload_content_encoding": '',
}

default_secret_create_two_phase_data = {
    "name": "AES key",
    "expiration": "2030-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
}


@utils.parameterized_test_case
class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)

        # make a local mutable copies of the default data to prevent
        # possible data contamination if (when?) the data contains
        # any nested dicts.
        self.create_default_data = copy.deepcopy(default_secret_create_data)
        self.create_all_none_data = copy.deepcopy(
            default_secret_create_all_none_data)
        self.create_emptystrings = copy.deepcopy(
            default_secret_create_emptystrings_data)
        self.create_two_phase_data = copy.deepcopy(
            default_secret_create_two_phase_data)

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_secret_create_no_expiration(self):
        """Covers creating a secret without an expiration."""
        test_model = secret_models.SecretModel(**self.create_default_data)
        test_model.expiration = None

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        resp = self.behaviors.get_secret_metadata(secret_ref)
        self.assertEqual(200, resp.status_code)
        self.assertEqual("ACTIVE", resp.model.status)
        self.assertTrue(resp.model.secret_ref)

    @utils.parameterized_dataset({
        'alphanumeric': ['1f34ds'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'len_255': [base.TestCase.max_sized_field],
        'empty': [''],
        'null': [None]
    })
    @testcase.attr('positive')
    def test_secret_get_metadata_w_valid_name(self, name):
        """Covers getting and checking a secret's metadata."""
        test_model = secret_models.SecretModel(**self.create_default_data)
        test_model.name = name

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        resp = self.behaviors.get_secret_metadata(secret_ref)
        self.assertEqual(200, resp.status_code)
        self.assertEqual("ACTIVE", resp.model.status)
        self.assertEqual(test_model.name, resp.model.name)
        self.assertEqual(test_model.mode, resp.model.mode)
        self.assertEqual(test_model.algorithm, resp.model.algorithm)
        self.assertEqual(test_model.bit_length, resp.model.bit_length)

    @testcase.attr('positive')
    def test_secret_create(self):
        """Covers single phase secret creation.

        Verify that a secret gets created with the correct http
        response code and a secret reference.
        """
        test_model = secret_models.SecretModel(**self.create_default_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)
        self.assertIsNotNone(secret_ref)

    @testcase.attr('positive')
    def test_secret_delete(self):
        """Covers deleting a secret."""
        test_model = secret_models.SecretModel(**self.create_default_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        del_resp = self.behaviors.delete_secret(secret_ref)
        self.assertEqual(204, del_resp.status_code)

    @testcase.attr('positive')
    def test_secret_delete_minimal_secret_w_no_metadata(self):
        """Covers deleting a secret with nones data."""
        test_model = secret_models.SecretModel(**self.create_all_none_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        del_resp = self.behaviors.delete_secret(secret_ref)
        self.assertEqual(204, del_resp.status_code)

    @testcase.attr('positive')
    def test_secret_get(self):
        """Covers getting a secret's payload data."""
        test_model = secret_models.SecretModel(**self.create_default_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        get_resp = self.behaviors.get_secret(secret_ref,
                                             test_model.payload_content_type)
        self.assertEqual(200, get_resp.status_code)
        self.assertEqual(test_model.payload,
                         oslo_base64.encode_as_bytes(get_resp.content))

    @testcase.attr('positive')
    def test_secret_update_two_phase(self):
        """Covers updating a secret's payload data."""

        # Create
        test_model = secret_models.SecretModel(**self.create_two_phase_data)

        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # Update
        payload = b"gF6+lLoF3ohA9aPRpt+6bQ=="
        payload_content_type = "application/octet-stream"
        payload_content_encoding = "base64"

        update_resp = self.behaviors.update_secret_payload(
            secret_ref, payload=payload,
            payload_content_type=payload_content_type,
            payload_content_encoding=payload_content_encoding)
        self.assertEqual(204, update_resp.status_code)

        # Get/Check Updated
        sec_resp = self.behaviors.get_secret(
            secret_ref=secret_ref,
            payload_content_type=payload_content_type)
        self.assertEqual(200, sec_resp.status_code)
        self.assertEqual(b'gF6+lLoF3ohA9aPRpt+6bQ==',
                         oslo_base64.encode_as_bytes(sec_resp.content))

    @testcase.attr('positive')
    def test_secrets_get_multiple_secrets(self):
        """Covers getting a list of secrets.

        Creates 11 secrets then returns a list of 2 secrets
        """
        test_model = secret_models.SecretModel(**self.create_default_data)
        limit = 2
        offset = 0

        for i in range(0, 11):
            self.behaviors.create_secret(test_model)

        resp, secrets_list, next_ref, prev_ref = self.behaviors.get_secrets(
            limit=limit, offset=offset)

        self.assertEqual(200, resp.status_code)
        self.assertEqual(limit, len(secrets_list))
        self.assertIsNone(prev_ref)
        self.assertIsNotNone(next_ref)
