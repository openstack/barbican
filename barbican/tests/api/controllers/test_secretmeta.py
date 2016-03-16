# Copyright (c) 2017 IBM
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
import mock
import os
import uuid

from barbican.tests import utils


@utils.parameterized_test_case
class WhenTestingSecretMetadataResource(utils.BarbicanAPIBaseTestCase):

    def setUp(self):
        super(WhenTestingSecretMetadataResource, self).setUp()

        self.valid_metadata = {
            "metadata": {
                "latitude": "30.393805",
                "longitude": "-97.724077"
            }
        }

    def test_create_secret_metadata(self):
        secret_resp, secret_uuid = create_secret(self.app)
        meta_resp = create_secret_metadata(self.app,
                                           self.valid_metadata,
                                           secret_resp)

        self.assertEqual(201, meta_resp.status_int)
        self.assertIsNotNone(meta_resp.json)

    def test_can_get_secret_metadata(self):
        secret_resp, secret_uuid = create_secret(self.app)
        meta_resp = create_secret_metadata(self.app,
                                           self.valid_metadata,
                                           secret_resp)

        self.assertEqual(201, meta_resp.status_int)

        get_resp = self.app.get('/secrets/%s/metadata' % secret_resp)

        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(self.valid_metadata, get_resp.json)

    def test_get_secret_metadata_invalid_secret_should_fail(self):
        secret_resp, secret_uuid = create_secret(self.app)
        create_secret_metadata(self.app,
                               self.valid_metadata,
                               secret_resp)

        get_resp = self.app.get('/secrets/%s/metadata' % uuid.uuid4().hex,
                                expect_errors=True)
        self.assertEqual(404, get_resp.status_int)


@utils.parameterized_test_case
class WhenTestingSecretMetadatumResource(utils.BarbicanAPIBaseTestCase):

    def setUp(self):
        super(WhenTestingSecretMetadatumResource, self).setUp()

        self.valid_metadata = {
            "metadata": {
                "latitude": "30.393805",
                "longitude": "-97.724077"
            }
        }

        self.updated_valid_metadata = {
            "metadata": {
                "latitude": "30.393805",
                "longitude": "-97.724077",
                "access-limit": "2"
            }
        }
        self.valid_metadatum = {
            'key': 'access-limit',
            'value': '2'
        }

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_can_create_secret_metadatum(self, mocked_get):
        secret_resp, secret_uuid = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        meta_resp = create_secret_metadatum(self.app,
                                            self.valid_metadatum,
                                            secret_resp)

        self.assertEqual(201, meta_resp.status_int)
        self.assertIsNotNone(meta_resp.json)

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_conflict_create_same_key_secret_metadatum(self, mocked_get):
        secret_resp, secret_uuid = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        latitude_metadatum = {
            "key": "latitude",
            "value": "30.393805"
        }
        meta_resp = create_secret_metadatum(self.app,
                                            latitude_metadatum,
                                            secret_resp,
                                            expect_errors=True)

        self.assertEqual(409, meta_resp.status_int)
        self.assertIsNotNone(meta_resp.json)

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_can_delete_secret_metadatum(self, mocked_get):
        secret_resp, secret_uuid = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        meta_resp = create_secret_metadatum(self.app,
                                            self.valid_metadatum,
                                            secret_resp)
        self.assertEqual(201, meta_resp.status_int)

        delete_resp = self.app.delete('/secrets/%s/metadata/access-limit' %
                                      secret_resp)

        self.assertEqual(204, delete_resp.status_int)

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_can_get_secret_metadatum(self, mocked_get):
        secret_resp, secret_uuid = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        meta_resp = create_secret_metadatum(self.app,
                                            self.valid_metadatum,
                                            secret_resp)
        self.assertEqual(201, meta_resp.status_int)

        mocked_get.return_value = self.updated_valid_metadata['metadata']
        get_resp = self.app.get('/secrets/%s/metadata/access-limit' %
                                secret_resp)
        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(self.valid_metadatum, get_resp.json)

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_get_secret_metadatum_not_found(self, mocked_get):
        secret_resp, secret_uuid = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        meta_resp = create_secret_metadatum(self.app,
                                            self.valid_metadatum,
                                            secret_resp)
        self.assertEqual(201, meta_resp.status_int)

        mocked_get.return_value = self.updated_valid_metadata['metadata']
        get_resp = self.app.get('/secrets/%s/metadata/nothere' %
                                secret_resp,
                                expect_errors=True)
        self.assertEqual(404, get_resp.status_int)

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_can_update_secret_metadatum(self, mocked_get):
        secret_resp, secret_uuid = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        meta_resp = create_secret_metadatum(self.app,
                                            self.valid_metadatum,
                                            secret_resp)
        self.assertEqual(201, meta_resp.status_int)

        new_metadatum = {
            'key': 'access-limit',
            'value': '5'
        }
        new_metadatum_json = json.dumps(new_metadatum)

        mocked_get.return_value = self.updated_valid_metadata['metadata']
        put_resp = self.app.put('/secrets/%s/metadata/access-limit' %
                                secret_resp,
                                new_metadatum_json,
                                headers={'Content-Type': 'application/json'})

        self.assertEqual(200, put_resp.status_int)
        self.assertEqual(new_metadatum, put_resp.json)

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_can_update_secret_metadatum_not_found(self, mocked_get):
        secret_resp, secret_uuid = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        meta_resp = create_secret_metadatum(self.app,
                                            self.valid_metadatum,
                                            secret_resp)
        self.assertEqual(201, meta_resp.status_int)

        new_metadatum = {
            'key': 'newwwww',
            'value': '5'
        }
        new_metadatum_json = json.dumps(new_metadatum)

        mocked_get.return_value = self.updated_valid_metadata['metadata']
        put_resp = self.app.put('/secrets/%s/metadata/newwwww' %
                                secret_resp,
                                new_metadatum_json,
                                headers={'Content-Type': 'application/json'},
                                expect_errors=True)

        self.assertEqual(404, put_resp.status_int)

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_conflict_update_secret_metadatum(self, mocked_get):
        secret_resp, secret_uuid = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        meta_resp = create_secret_metadatum(self.app,
                                            self.valid_metadatum,
                                            secret_resp)
        self.assertEqual(201, meta_resp.status_int)

        new_metadatum = {
            'key': 'snoop',
            'value': '5'
        }
        new_metadatum_json = json.dumps(new_metadatum)
        mocked_get.return_value = self.updated_valid_metadata['metadata']
        put_resp = self.app.put('/secrets/%s/metadata/access-limit' %
                                secret_resp,
                                new_metadatum_json,
                                headers={'Content-Type': 'application/json'},
                                expect_errors=True)

        self.assertEqual(409, put_resp.status_int)

    def test_returns_405_for_delete_on_metadata(self):
        secret_id, secret_resp = create_secret(self.app)
        resp = self.app.delete('/secrets/{0}/metadata/'.format(secret_id),
                               expect_errors=True)
        self.assertEqual(405, resp.status_int)

    @mock.patch('barbican.model.repositories.SecretUserMetadatumRepo.'
                'get_metadata_for_secret')
    def test_returns_405_for_head_on_metadatum(self, mocked_get):
        secret_id, secret_resp = create_secret(self.app)

        mocked_get.return_value = self.valid_metadata['metadata']
        meta_resp = create_secret_metadatum(self.app,
                                            self.valid_metadatum,
                                            secret_id)
        self.assertEqual(201, meta_resp.status_int)

        resp = self.app.head('/secrets/{0}/metadata/access-limit'.format(
            secret_id), expect_errors=True)
        self.assertEqual(405, resp.status_int)


# ----------------------- Helper Functions ---------------------------
def create_secret(app, name=None, algorithm=None, bit_length=None, mode=None,
                  expiration=None, payload='not-encrypted',
                  content_type='text/plain',
                  content_encoding=None, transport_key_id=None,
                  transport_key_needed=None, expect_errors=False):
    request = {
        'name': name,
        'algorithm': algorithm,
        'bit_length': bit_length,
        'mode': mode,
        'expiration': expiration,
        'payload': payload,
        'payload_content_type': content_type,
        'payload_content_encoding': content_encoding,
        'transport_key_id': transport_key_id,
        'transport_key_needed': transport_key_needed
    }
    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    resp = app.post_json(
        '/secrets/',
        cleaned_request,
        expect_errors=expect_errors
    )
    created_uuid = None
    if resp.status_int == 201:
        secret_ref = resp.json.get('secret_ref', '')
        _, created_uuid = os.path.split(secret_ref)

    return created_uuid, resp


def create_secret_metadata(app, metadata, secret_uuid,
                           expect_errors=False):
    request = {}

    for metadatum in metadata:
        request[metadatum] = metadata.get(metadatum)

    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    url = '/secrets/%s/metadata/' % secret_uuid

    resp = app.put_json(
        url,
        cleaned_request,
        expect_errors=expect_errors
    )

    return resp


def create_secret_metadatum(app, metadata, secret_uuid, remainder=None,
                            update=False, expect_errors=False):
    request = {}

    for metadatum in metadata:
        request[metadatum] = metadata.get(metadatum)

    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    url = '/secrets/%s/metadata/' % secret_uuid
    if remainder:
        url = url + remainder

    if update:
        resp = app.put_json(
            url,
            cleaned_request,
            expect_errors=expect_errors
        )
    else:
        resp = app.post_json(
            url,
            cleaned_request,
            expect_errors=expect_errors
        )

    return resp
