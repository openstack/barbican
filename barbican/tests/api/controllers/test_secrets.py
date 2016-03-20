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
import base64
import os

import mock
from oslo_utils import timeutils

from barbican.common import validators
from barbican.model import models
from barbican.model import repositories
from barbican.tests import utils

project_repo = repositories.get_project_repository()
secrets_repo = repositories.get_secret_repository()
tkey_repo = repositories.get_transport_key_repository()


@utils.parameterized_test_case
class WhenTestingSecretsResource(utils.BarbicanAPIBaseTestCase):

    def test_can_create_new_secret_one_step(self):
        resp, secret_uuid = create_secret(
            self.app,
            payload=b'not-encrypted',
            content_type='text/plain'
        )

        self.assertEqual(201, resp.status_int)
        self.assertIsNotNone(secret_uuid)

    def test_can_create_new_secret_without_payload(self):
        resp, secret_uuid = create_secret(self.app, name='test')
        self.assertEqual(201, resp.status_int)

        secret = secrets_repo.get(secret_uuid, self.project_id)
        self.assertEqual('test', secret.name)
        self.assertEqual([], secret.encrypted_data)

    def test_can_create_new_secret_if_project_doesnt_exist(self):
        # Build new context
        new_project_context = self._build_context('test_project_id')
        self.app.extra_environ = {'barbican.context': new_project_context}

        # Create a generic secret
        resp, _ = create_secret(self.app, name='test_secret')
        self.assertEqual(201, resp.status_int)

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

        self.assertEqual(201, resp.status_int)

    def test_creating_new_secret_with_oversized_payload_should_fail(self):
        oversized_payload = b'A' * (validators.DEFAULT_MAX_SECRET_BYTES + 10)
        resp, _ = create_secret(
            self.app,
            payload=oversized_payload,
            content_type='text/plain',
            expect_errors=True
        )
        self.assertEqual(413, resp.status_int)

    def test_create_new_secret_with_empty_payload_should_fail(self):
        resp, _ = create_secret(
            self.app,
            payload='',
            content_type='text/plain',
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    def test_expiration_should_be_normalized_with_new_secret(self):
        target_expiration = '2114-02-28 12:14:44.180394-05:00'
        resp, secret_uuid = create_secret(
            self.app,
            expiration=target_expiration
        )

        self.assertEqual(201, resp.status_int)

        # Verify that the system normalizes time to UTC
        secret = secrets_repo.get(secret_uuid, self.project_id)
        local_datetime = timeutils.parse_isotime(target_expiration)
        datetime_utc = timeutils.normalize_time(local_datetime)

        self.assertEqual(datetime_utc, secret.expiration)

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
        self.assertEqual(201, resp.status_int)
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

        self.assertEqual(201, resp.status_int)
        # We're interested in the transport key values
        mocked_store.assert_called_once_with(
            unencrypted_raw='not-encrypted',
            content_type_raw='text/plain',
            content_encoding=None,
            secret_model=mock.ANY,
            project_model=mock.ANY,
            transport_key_id=transport_key_id,
            transport_key_needed=False
        )

    def test_new_secret_fails_with_invalid_transport_key_ref(self):
        resp, _ = create_secret(
            self.app,
            payload=b'superdupersecret',
            content_type='text/plain',
            transport_key_id="non_existing_transport_key_id",
            transport_key_needed="true",
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    def test_new_secret_w_unsupported_content_type_should_fail(self):
        resp, _ = create_secret(
            self.app,
            payload=b'something_here',
            content_type='bogus_content_type',
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    @utils.parameterized_dataset({
        'no_encoding': [None, 'application/octet-stream'],
        'bad_encoding': ['purple', 'application/octet-stream'],
        'no_content_type': ['base64', None]
    })
    def test_new_secret_fails_with_binary_payload_and(self, encoding=None,
                                                      content_type=None):
        resp, _ = create_secret(
            self.app,
            payload=b'lOtfqHaUUpe6NqLABgquYQ==',
            content_type=content_type,
            content_encoding=encoding,
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    def test_new_secret_fails_with_bad_payload(self):
        resp, _ = create_secret(
            self.app,
            payload='AAAAAAAAA',
            content_type='application/octet-stream',
            content_encoding='base64',
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)


class WhenGettingSecretsList(utils.BarbicanAPIBaseTestCase):

    def test_list_secrets_by_name(self):
        # Creating a secret to be retrieved later
        create_resp, _ = create_secret(
            self.app,
            name='secret mission'
        )

        self.assertEqual(201, create_resp.status_int)

        params = {'name': 'secret mission'}

        get_resp = self.app.get('/secrets/', params)

        self.assertEqual(200, get_resp.status_int)
        secret_list = get_resp.json.get('secrets')
        self.assertEqual('secret mission', secret_list[0].get('name'))

    def test_list_secrets(self):
        # Creating a secret to be retrieved later
        create_resp, _ = create_secret(
            self.app,
            name='James Bond'
        )

        self.assertEqual(201, create_resp.status_int)

        get_resp = self.app.get('/secrets/')

        self.assertEqual(200, get_resp.status_int,)
        self.assertIn('total', get_resp.json)
        secret_list = get_resp.json.get('secrets')
        self.assertGreater(len(secret_list), 0)

    def test_pagination_attributes(self):
        # Create a list of secrets greater than default limit (10)
        for _ in range(11):
            create_resp, _ = create_secret(self.app, name='Sterling Archer')
            self.assertEqual(201, create_resp.status_int)
        params = {'limit': '2', 'offset': '2'}

        get_resp = self.app.get('/secrets/', params)

        self.assertEqual(200, get_resp.status_int)
        self.assertIn('previous', get_resp.json)
        self.assertIn('next', get_resp.json)

        previous_ref = get_resp.json.get('previous')
        next_ref = get_resp.json.get('next')

        self.assertIn('offset=0', previous_ref)
        self.assertIn('offset=4', next_ref)

    def test_empty_list_of_secrets(self):
        params = {'name': 'Austin Powers'}

        get_resp = self.app.get('/secrets/', params)
        self.assertEqual(200, get_resp.status_int)

        secret_list = get_resp.json.get('secrets')
        self.assertEqual(0, len(secret_list))

        # These should never exist in this scenario
        self.assertNotIn('previous', get_resp.json)
        self.assertNotIn('next', get_resp.json)


class WhenGettingPuttingOrDeletingSecret(utils.BarbicanAPIBaseTestCase):

    def test_get_secret_as_plain(self):
        payload = 'this message will self destruct in 10 seconds'
        resp, secret_uuid = create_secret(
            self.app,
            payload=payload,
            content_type='text/plain'
        )

        self.assertEqual(201, resp.status_int)

        headers = {'Accept': 'text/plain'}
        get_resp = self.app.get(
            '/secrets/{0}'.format(secret_uuid), headers=headers
        )
        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(payload, get_resp.body)

    def test_get_secret_payload_with_pecan_default_accept_header(self):
        payload = 'a very interesting string'
        resp, secret_uuid = create_secret(
            self.app,
            payload=payload,
            content_type='text/plain'
        )

        self.assertEqual(201, resp.status_int)

        headers = {'Accept': '*/*'}
        get_resp = self.app.get(
            '/secrets/{0}/payload'.format(secret_uuid), headers=headers
        )
        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(payload, get_resp.body)

    def test_get_secret_payload_with_blank_accept_header(self):
        payload = 'a very interesting string'
        resp, secret_uuid = create_secret(
            self.app,
            payload=payload,
            content_type='text/plain'
        )

        self.assertEqual(201, resp.status_int)

        headers = {'Accept': ''}
        get_resp = self.app.get(
            '/secrets/{0}/payload'.format(secret_uuid), headers=headers
        )
        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(payload, get_resp.body)

    def test_get_secret_payload_with_no_accept_header(self):
        payload = 'a very interesting string'
        resp, secret_uuid = create_secret(
            self.app,
            payload=payload,
            content_type='text/plain'
        )

        self.assertEqual(201, resp.status_int)

        headers = {}
        get_resp = self.app.get(
            '/secrets/{0}/payload'.format(secret_uuid), headers=headers
        )
        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(payload, get_resp.body)

    def test_get_secret_is_decoded_for_binary(self):
        payload = 'a123'
        resp, secret_uuid = create_secret(
            self.app,
            payload=payload,
            content_type='application/octet-stream',
            content_encoding='base64'
        )
        headers = {
            'Accept': 'application/octet-stream',
        }
        get_resp = self.app.get(
            '/secrets/{0}'.format(secret_uuid), headers=headers
        )
        decoded = 'k]\xb7'

        self.assertEqual(decoded, get_resp.body)

    def test_returns_404_on_get_when_not_found(self):
        get_resp = self.app.get(
            '/secrets/98c876d9-aaac-44e4-8ea8-441932962b05',
            headers={'Accept': 'application/json'},
            expect_errors=True
        )
        self.assertEqual(404, get_resp.status_int)

    def test_returns_404_on_get_with_bad_uuid(self):
        get_resp = self.app.get(
            '/secrets/98c876d9-aaac-44e4-8ea8-441932962b05X',
            headers={'Accept': 'application/json'},
            expect_errors=True
        )
        self.assertEqual(404, get_resp.status_int)

    def test_returns_406_with_get_bad_accept_header(self):
        resp, secret_uuid = create_secret(
            self.app,
            payload='blah',
            content_type='text/plain'
        )

        self.assertEqual(201, resp.status_int)

        get_resp = self.app.get(
            '/secrets/{0}'.format(secret_uuid),
            headers={'Accept': 'golden gun', 'Accept-Encoding': 'gzip'},
            expect_errors=True
        )

        self.assertEqual(406, get_resp.status_int)

    def test_put_plain_text_secret(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        message = 'Babou! Serpentine!'

        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            message,
            headers={'Content-Type': 'text/plain'}
        )

        self.assertEqual(204, put_resp.status_int)

        get_resp = self.app.get(
            '/secrets/{0}'.format(secret_uuid),
            headers={'Accept': 'text/plain'}
        )

        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(message, get_resp.body)

    def test_put_binary_secret(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        binary_string = b'a binary string'
        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            binary_string,
            headers={'Content-Type': 'application/octet-stream'}
        )

        self.assertEqual(204, put_resp.status_int)

        get_resp = self.app.get(
            '/secrets/{0}'.format(secret_uuid),
            headers={'Accept': 'application/octet-stream'}
        )

        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(binary_string, get_resp.body)

    def test_put_base64_secret(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        payload = base64.b64encode('I had something for this')
        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            payload,
            headers={
                'Content-Type': 'application/octet-stream',
                'Content-Encoding': 'base64'
            }
        )

        self.assertEqual(204, put_resp.status_int)

        get_resp = self.app.get(
            '/secrets/{0}'.format(secret_uuid),
            headers={
                'Accept': 'application/octet-stream',
                'Content-Encoding': 'base64'
            }
        )

        self.assertEqual(200, get_resp.status_int)
        self.assertEqual(base64.b64decode(payload), get_resp.body)

    def test_returns_400_with_put_unknown_encoding(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        payload = base64.b64encode('I had something for this')
        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            payload,
            headers={
                'Accept': 'text/plain',
                'Content-Type': 'application/octet-stream',
                'Content-Encoding': 'unknownencoding'
            },
            expect_errors=True
        )

        self.assertEqual(400, put_resp.status_int)

    def test_returns_415_with_put_unsupported_media_type(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            'rampage',
            headers={
                'Content-Type': 'application/json'
            },
            expect_errors=True
        )

        self.assertEqual(415, put_resp.status_int)

    def test_returns_415_with_put_no_media_type(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            'rampage again',
            headers={
                'Content-Type': ''
            },
            expect_errors=True
        )

        self.assertEqual(415, put_resp.status_int)

    def test_returns_404_put_secret_not_found(self):
        put_resp = self.app.put(
            '/secrets/98c876d9-aaac-44e4-8ea8-441932962b05',
            'some text',
            headers={'Content-Type': 'text/plain'},
            expect_errors=True
        )

        self.assertEqual(404, put_resp.status_int)

    def test_returns_409_put_to_existing_secret(self):
        resp, secret_uuid = create_secret(
            self.app,
            payload='blah',
            content_type='text/plain'
        )

        self.assertEqual(201, resp.status_int)

        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            'do not want',
            headers={'Content-Type': 'text/plain'},
            expect_errors=True
        )

        self.assertEqual(409, put_resp.status_int)

    def test_returns_400_put_no_payload(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            headers={'Content-Type': 'text/plain'},
            expect_errors=True
        )

        self.assertEqual(400, put_resp.status_int)

    def test_returns_400_put_with_empty_payload(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            '',
            headers={'Content-Type': 'text/plain'},
            expect_errors=True
        )

        self.assertEqual(400, put_resp.status_int)

    def test_returns_413_put_with_text_too_large(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        text_too_big = 'x' * 10050
        put_resp = self.app.put(
            '/secrets/{0}'.format(secret_uuid),
            text_too_big,
            headers={'Content-Type': 'text/plain'},
            expect_errors=True
        )

        self.assertEqual(413, put_resp.status_int)

    def test_delete_secret(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        delete_resp = self.app.delete(
            '/secrets/{0}/'.format(secret_uuid)
        )

        self.assertEqual(204, delete_resp.status_int)

    def test_raise_404_for_delete_secret_not_found(self):
        delete_resp = self.app.delete(
            '/secrets/98c876d9-aaac-44e4-8ea8-441932962b05',
            expect_errors=True
        )

        self.assertEqual(404, delete_resp.status_int)
        self.assertEqual('application/json', delete_resp.content_type)

    def test_delete_with_json_accept_header(self):
        resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, resp.status_int)

        delete_resp = self.app.delete(
            '/secrets/{0}/'.format(secret_uuid),
            headers={'Accept': 'application/json'}
        )

        self.assertEqual(204, delete_resp.status_int)


@utils.parameterized_test_case
class WhenPerformingUnallowedOperations(utils.BarbicanAPIBaseTestCase):

    def test_returns_405_for_put_json_on_secrets(self):
        test_json = {
            'name': 'Barry',
            'algorithm': 'AES',
            'bit_length': 256,
            'mode': 'CBC'
        }
        resp = self.app.put_json(
            '/secrets/',
            test_json,
            expect_errors=True
        )

        self.assertEqual(405, resp.status_int)

    def test_returns_405_for_delete_on_secrets(self):
        resp = self.app.delete(
            '/secrets/',
            expect_errors=True
        )

        self.assertEqual(405, resp.status_int)

    def test_returns_405_for_get_payload(self):
        created_resp, secret_uuid = create_secret(
            self.app
        )
        resp = self.app.post(
            '/secrets/{0}/payload'.format(secret_uuid),
            'Do you want ants? This is how you get ants!',
            headers={'Content-Type': 'text/plain'},
            expect_errors=True
        )

        self.assertEqual(405, resp.status_int)

    @utils.parameterized_dataset({
        'delete': ['delete'],
        'put': ['put'],
        'post': ['post']
    })
    def test_returns_405_for_calling_secret_payload_uri_with(
            self, http_verb=None
    ):
        created_resp, secret_uuid = create_secret(
            self.app
        )

        self.assertEqual(201, created_resp.status_int)
        operation = getattr(self.app, http_verb)
        resp = operation(
            '/secrets/{0}/payload'.format(secret_uuid),
            'boop',
            expect_errors=True
        )

        self.assertEqual(405, resp.status_int)


# ----------------------- Helper Functions ---------------------------
def create_secret(app, name=None, algorithm=None, bit_length=None, mode=None,
                  expiration=None, payload=None, content_type=None,
                  content_encoding=None, transport_key_id=None,
                  transport_key_needed=None, expect_errors=False):
    # TODO(chellygel): Once test resources is split out, refactor this
    # and similar functions into a generalized helper module and reduce
    # duplication.
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
