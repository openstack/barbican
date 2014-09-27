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
import testtools

from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import secret_models


one_phase_create_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

two_phase_create_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload_content_encoding": "base64",
}


class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.one_phase_secret_model = secret_models.SecretModel(
            **one_phase_create_data)
        self.two_phase_secret_model = secret_models.SecretModel(
            **two_phase_create_data)

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsTestCase, self).tearDown()

    def test_create_secret_single_phase(self):
        """Covers single phase secret creation.

        Verify that a secret gets created with the correct http
        response code and a secret reference.
        """
        resp, secret_ref = self.behaviors.create_secret(
            self.one_phase_secret_model)

        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

    def test_get_created_secret_metadata(self):
        """Covers retrieval of a created secret's metadata."""

        create_model = self.one_phase_secret_model
        resp, secret_ref = self.behaviors.create_secret(create_model)

        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret_metadata(secret_ref)
        get_model = get_resp.model

        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_model.name, create_model.name)
        self.assertEqual(get_model.algorithm, create_model.algorithm)
        self.assertEqual(get_model.bit_length, create_model.bit_length)
        self.assertEqual(get_model.mode, create_model.mode)

    @testtools.skip('Skip until we can fix two-step creation')
    def test_create_secret_two_phase(self):
        """Covers two phase secret creation.

        Verify that a secret gets created with the correct http
        response code and a secret reference.
        """

        # Phase 1
        resp, secret_ref = self.behaviors.create_secret(
            self.two_phase_secret_model)

        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        # Phase 2
        update_resp = self.behaviors.update_secret_payload(
            secret_ref, 'YmFt', 'text/plain')

        self.assertEqual(update_resp.status_code, 204)

    def test_create_secret_with_oversized_name_string(self):
        """Covers negative case for an oversized name string."""
        create_model = self.one_phase_secret_model
        create_model.name = 'a' * 256

        resp, secret_ref = self.behaviors.create_secret(create_model)
        self.assertEqual(resp.status_code, 400)

    def test_create_secret_with_oversized_algorithm_string(self):
        """Covers negative case for an oversized algorithm string."""
        create_model = self.one_phase_secret_model
        create_model.algorithm = 'a' * 256

        resp, secret_ref = self.behaviors.create_secret(create_model)
        self.assertEqual(resp.status_code, 400)

    def test_create_secret_with_oversized_mode_string(self):
        """Covers negative case for an oversized mode string."""
        create_model = self.one_phase_secret_model
        create_model.mode = 'a' * 256

        resp, secret_ref = self.behaviors.create_secret(create_model)
        self.assertEqual(resp.status_code, 400)

    def test_create_secret_with_oversized_expiration_string(self):
        """Covers negative case for an oversized expiration string."""
        create_model = self.one_phase_secret_model
        create_model.expiration = 'a' * 256

        resp, secret_ref = self.behaviors.create_secret(create_model)
        self.assertEqual(resp.status_code, 400)

    def test_create_secret_with_oversized_content_type_string(self):
        """Covers negative case for an oversized content type string."""
        create_model = self.one_phase_secret_model
        create_model.payload_content_type = 'a' * 256

        resp, secret_ref = self.behaviors.create_secret(create_model)
        self.assertEqual(resp.status_code, 400)

    def test_create_secret_with_oversized_content_encoding_string(self):
        """Covers negative case for an oversized content encoding string."""
        create_model = self.one_phase_secret_model
        create_model.payload_content_encoding = 'a' * 256

        resp, secret_ref = self.behaviors.create_secret(create_model)
        self.assertEqual(resp.status_code, 400)

    def test_delete_secret_with_accept_application_json(self):
        """Covers Launchpad Bug #1326481."""
        create_model = self.one_phase_secret_model
        resp, secret_ref = self.behaviors.create_secret(create_model)

        self.assertEqual(resp.status_code, 201)

        headers = {'Accept': 'application/json'}
        resp = self.behaviors.delete_secret(secret_ref, extra_headers=headers)

        self.assertEqual(resp.status_code, 204)
