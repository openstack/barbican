# Copyright (c) 2015 Rackspace, Inc.
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
import os

import mock

from barbican.common import validators
from barbican.model import models
from barbican.model import repositories
from barbican.openstack.common import timeutils
from barbican.tests import utils

project_repo = repositories.get_project_repository()
secrets_repo = repositories.get_secret_repository()
tkey_repo = repositories.get_transport_key_repository()


class WhenTestingSecretsResource(utils.BarbicanAPIBaseTestCase):

    def test_can_create_new_secret_one_step(self):
        resp, secret_uuid = create_secret(
            self.app,
            payload=b'not-encrypted',
            content_type='text/plain'
        )

        self.assertEqual(resp.status_int, 201)
        self.assertIsNotNone(secret_uuid)

    def test_can_create_new_secret_without_payload(self):
        resp, secret_uuid = create_secret(self.app, name='test')
        self.assertEqual(resp.status_int, 201)

        secret = secrets_repo.get(secret_uuid, self.project_id)
        self.assertEqual(secret.name, 'test')
        self.assertEqual(secret.encrypted_data, [])

    def test_can_create_new_secret_if_project_doesnt_exist(self):
        # Build new context
        new_project_context = self._build_context('test_project_id')
        self.app.extra_environ = {'barbican.context': new_project_context}

        # Create a generic secret
        resp, _ = create_secret(self.app, name='test_secret')
        self.assertEqual(resp.status_int, 201)

        # Verify the new project was created
        project = project_repo.find_by_external_project_id('test_project_id')
        self.assertIsNotNone(project)

    def test_can_create_new_secret_with_payload_just_under_max(self):
        large_payload = b'A' * (validators.DEFAULT_MAX_SECRET_BYTES - 8)
        resp, _ = create_secret(
            self.app,
            payload=large_payload,
            content_type='text/plain'
        )

        self.assertEqual(resp.status_int, 201)

    def test_creating_new_secret_with_oversized_payload_should_fail(self):
        oversized_payload = b'A' * (validators.DEFAULT_MAX_SECRET_BYTES + 10)
        resp, _ = create_secret(
            self.app,
            payload=oversized_payload,
            content_type='text/plain',
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 413)

    def test_create_new_secret_with_empty_payload_should_fail(self):
        resp, _ = create_secret(
            self.app,
            payload='',
            content_type='text/plain',
            expect_errors=True
        )
        self.assertEqual(resp.status_int, 400)

    def test_expiration_should_be_normalized_with_new_secret(self):
        target_expiration = '2114-02-28 12:14:44.180394-05:00'
        resp, secret_uuid = create_secret(
            self.app,
            expiration=target_expiration
        )

        self.assertEqual(resp.status_int, 201)

        # Verify that the system normalizes time to UTC
        secret = secrets_repo.get(secret_uuid, self.project_id)
        local_datetime = timeutils.parse_isotime(target_expiration)
        datetime_utc = timeutils.normalize_time(local_datetime)

        self.assertEqual(secret.expiration, datetime_utc)

    @mock.patch('barbican.plugin.resources.store_secret')
    def test_can_create_new_secret_meta_w_transport_key(self, mocked_store):
        transport_key_model = models.TransportKey('default_plugin', 'tkey1234')

        # TODO(jvrbanac): Look into removing this patch
        mocked_store.return_value = models.Secret(), transport_key_model

        # Make sure to add the transport key
        tkey_repo.create_from(transport_key_model)
        transport_key_id = transport_key_model.id

        resp, secret_uuid = create_secret(
            self.app,
            name='test',
            transport_key_needed='true'
        )
        self.assertEqual(resp.status_int, 201)
        self.assertIsNotNone(secret_uuid)
        self.assertIn(transport_key_id, resp.json.get('transport_key_ref'))

    @mock.patch('barbican.plugin.resources.store_secret')
    def test_can_create_new_secret_with_transport_key(self, mocked_store):
        # TODO(jvrbanac): Look into removing this patch
        mocked_store.return_value = models.Secret(), None

        # Create Transport Key (keeping for session scoping reasons)
        transport_key_model = models.TransportKey('default_plugin', 'tkey1234')
        transport_key_id = transport_key_model.id
        tkey_repo.create_from(transport_key_model)

        # Create a normal secret with the TransportKey
        resp, secret_uuid = create_secret(
            self.app,
            payload=b'not-encrypted',
            content_type='text/plain',
            transport_key_id=transport_key_id
        )

        self.assertEqual(resp.status_int, 201)
        # We're interested in the transport key values
        mocked_store.assert_called_once_with(
            'not-encrypted',
            'text/plain',
            None,
            mock.ANY,
            None,
            mock.ANY,
            transport_key_id=transport_key_id,
            transport_key_needed=False
        )


# ----------------------- Helper Functions ---------------------------
def create_secret(app, name=None, algorithm=None, bit_length=None, mode=None,
                  expiration=None, payload=None, content_type=None,
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

    return (resp, created_uuid)
