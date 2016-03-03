# Copyright (c) 2016 IBM
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
import json
from testtools import testcase
import uuid

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.behaviors import secretmeta_behaviors
from functionaltests.api.v1.models import secret_models


@utils.parameterized_test_case
class SecretMetadataTestCase(base.TestCase):
    def setUp(self):
        super(SecretMetadataTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.behaviors = secretmeta_behaviors.SecretMetadataBehaviors(
            self.client)

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

        self.valid_metadata = {
            "metadata": {
                "latitude": "30.393805",
                "longitude": "-97.724077"
            }
        }

        self.invalid_metadata = {
            "metadataaaaaaaa": {
                "latitude": "30.393805",
                "longitude": "-97.724077"
            }
        }

        self.valid_metadatum_key = 'access-limit'
        self.valid_metadatum = {
            'key': self.valid_metadatum_key,
            'value': '2'
        }

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        super(SecretMetadataTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_secret_metadata_create(self):
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        meta_resp, metadata_ref = self.behaviors.create_or_update_metadata(
            secret_ref, self.valid_metadata)

        self.assertEqual(meta_resp.status_code, 201)
        self.assertEqual(secret_ref + '/metadata', metadata_ref)

    @testcase.attr('negative')
    def test_secret_metadata_create_no_secret(self):
        secret_ref = 'http://localhost:9311/secrets/%s' % uuid.uuid4().hex

        meta_resp, metadata_ref = self.behaviors.create_or_update_metadata(
            secret_ref, self.invalid_metadata)

        self.assertEqual(meta_resp.status_code, 404)

    @testcase.attr('positive')
    def test_secret_metadata_get(self):
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        meta_resp, metadata_ref = self.behaviors.create_or_update_metadata(
            secret_ref, self.valid_metadata)

        self.assertEqual(meta_resp.status_code, 201)
        self.assertEqual(secret_ref + '/metadata', metadata_ref)

        get_resp = self.behaviors.get_metadata(secret_ref)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.content, json.dumps(self.valid_metadata))

    @testcase.attr('negative')
    def test_secret_metadata_get_no_secret(self):
        secret_ref = 'http://localhost:9311/secrets/%s' % uuid.uuid4().hex

        get_resp = self.behaviors.get_metadata(secret_ref)
        self.assertEqual(get_resp.status_code, 404)

    @testcase.attr('positive')
    def test_secret_metadatum_create(self):
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        meta_resp, metadata_ref = self.behaviors.create_metadatum(
            secret_ref, self.valid_metadatum)

        self.assertEqual(meta_resp.status_code, 201)

    @testcase.attr('positive')
    def test_secret_metadatum_update(self):
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        meta_resp, metadata_ref = self.behaviors.create_metadatum(
            secret_ref, self.valid_metadatum)

        self.assertEqual(meta_resp.status_code, 201)

        updated_meta = {
            'key': self.valid_metadatum_key,
            'value': '10'
        }

        put_resp = self.behaviors.update_metadatum(
            secret_ref, self.valid_metadatum_key, updated_meta)

        self.assertEqual(put_resp.status_code, 200)

    @testcase.attr('positive')
    def test_secret_metadatum_get(self):
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        meta_resp, metadata_ref = self.behaviors.create_metadatum(
            secret_ref, self.valid_metadatum)

        self.assertEqual(meta_resp.status_code, 201)

        get_resp = self.behaviors.get_metadatum(secret_ref,
                                                self.valid_metadatum_key)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.content, json.dumps(self.valid_metadatum,
                                                      sort_keys=True))

    @testcase.attr('negative')
    def test_secret_metadatum_get_wrong_key(self):
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        meta_resp, metadata_ref = self.behaviors.create_metadatum(
            secret_ref, self.valid_metadatum)

        self.assertEqual(meta_resp.status_code, 201)

        get_resp = self.behaviors.get_metadatum(secret_ref,
                                                'other_key')
        self.assertEqual(get_resp.status_code, 404)

    @testcase.attr('positive')
    def test_secret_metadatum_delete(self):
        test_model = secret_models.SecretModel(
            **self.default_secret_create_all_none_data)

        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 201)

        meta_resp, metadata_ref = self.behaviors.create_metadatum(
            secret_ref, self.valid_metadatum)

        self.assertEqual(meta_resp.status_code, 201)

        get_resp = self.behaviors.get_metadatum(secret_ref,
                                                self.valid_metadatum_key)
        self.assertEqual(get_resp.status_code, 200)
        delete_resp = self.behaviors.delete_metadatum(secret_ref,
                                                      self.valid_metadatum_key)
        self.assertEqual(delete_resp.status_code, 204)
