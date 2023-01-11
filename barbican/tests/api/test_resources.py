# Copyright (c) 2013-2014 Rackspace, Inc.
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

"""
This test module focuses on typical-flow business logic tests with the API
resource classes. For RBAC tests of these classes, see the
'resources_policy_test.py' module.
"""
import mimetypes
from unittest import mock

import pecan
from testtools import testcase
import webtest

from barbican import api
from barbican.api import app
from barbican.api import controllers
from barbican.common import exception as excep
from barbican.common import hrefs
from barbican.common import utils as barbican_utils
import barbican.context
from barbican.model import models
from barbican.tests import utils


def get_barbican_env(external_project_id):
    """Create and return a barbican.context for use with the RBAC decorator

    Injects the provided external_project_id.
    """
    kwargs = {'roles': None,
              'user_id': None,
              'project_id': external_project_id,
              'is_admin': True}
    ctx = barbican.context.RequestContext(**kwargs)
    ctx.policy_enforcer = None
    barbican_env = {'barbican.context': ctx}
    return barbican_env


def create_secret(id_ref="id", name="name",
                  algorithm=None, bit_length=None, mode=None,
                  encrypted_datum=None, content_type=None, project_id=None):
    """Generate a Secret entity instance."""
    info = {
        'id': id_ref,
        'name': name,
        'algorithm': algorithm,
        'bit_length': bit_length,
        'mode': mode,
        'project_id': project_id,
    }
    secret = models.Secret(info)
    secret.id = id_ref
    if encrypted_datum:
        secret.encrypted_data = [encrypted_datum]
    if content_type:
        content_meta = models.SecretStoreMetadatum('content_type',
                                                   content_type)
        secret.secret_store_metadata['content_type'] = content_meta
    return secret


def create_order_with_meta(id_ref="id", order_type="certificate", meta={},
                           status='PENDING'):
    """Generate an Order entity instance with Metadata."""
    order = models.Order()
    order.id = id_ref
    order.type = order_type
    order.meta = meta
    order.status = status
    return order


def validate_datum(test, datum):
    test.assertIsNone(datum.kek_meta_extended)
    test.assertIsNotNone(datum.kek_meta_project)
    test.assertTrue(datum.kek_meta_project.bind_completed)
    test.assertIsNotNone(datum.kek_meta_project.plugin_name)
    test.assertIsNotNone(datum.kek_meta_project.kek_label)


def create_container(id_ref, project_id=None, external_project_id=None):
    """Generate a Container entity instance."""
    container = models.Container()
    container.id = id_ref
    container.name = 'test name'
    container.type = 'rsa'
    container_secret = models.ContainerSecret()
    container_secret.container_id = id_ref
    container_secret.secret_id = '123'
    container.container_secrets.append(container_secret)

    if project_id:
        project = models.Project()
        project.id = project_id
        project.external_id = external_project_id
        container.project = project
    return container


def create_container_consumer(container_id, project_id, id_ref):
    """Generate a ContainerConsumerMetadatum entity instance."""
    data = {
        'name': 'test name',
        'URL': 'http://test/url'
    }
    consumer = models.ContainerConsumerMetadatum(container_id,
                                                 project_id,
                                                 data)
    consumer.id = id_ref
    return consumer


def create_secret_consumer(secret_id, project_id, id_ref):
    """Generate a SecretConsumerMetadatum entity instance."""
    consumer = models.SecretConsumerMetadatum(
        secret_id,
        project_id,
        "service",
        "resource_type",
        "resource_id",
    )
    consumer.id = id_ref
    return consumer


class SecretAllowAllMimeTypesDecoratorTest(utils.BaseTestCase):

    def setUp(self):
        super(SecretAllowAllMimeTypesDecoratorTest, self).setUp()
        self.mimetype_values = set(mimetypes.types_map.values())

    @pecan.expose(generic=True)
    @barbican_utils.allow_all_content_types
    def _empty_pecan_exposed_function(self):
        pass

    def _empty_function(self):
        pass

    def test_mimetypes_successfully_added_to_mocked_function(self):
        empty_function = mock.MagicMock()
        empty_function._pecan = {}
        func = barbican_utils.allow_all_content_types(empty_function)
        cfg = func._pecan
        self.assertEqual(len(self.mimetype_values), len(cfg['content_types']))

    def test_mimetypes_successfully_added_to_pecan_exposed_function(self):
        cfg = self._empty_pecan_exposed_function._pecan
        self.assertEqual(len(self.mimetype_values), len(cfg['content_types']))

    def test_decorator_raises_if_function_not_pecan_exposed(self):
        self.assertRaises(AttributeError,
                          barbican_utils.allow_all_content_types,
                          self._empty_function)


class FunctionalTest(utils.BaseTestCase, utils.MockModelRepositoryMixin,
                     testcase.WithAttributes):

    def setUp(self):
        super(FunctionalTest, self).setUp()
        root = self.root
        config = {'app': {'root': root}}
        pecan.set_config(config, overwrite=True)
        self.app = webtest.TestApp(pecan.make_app(root))

    def tearDown(self):
        super(FunctionalTest, self).tearDown()
        pecan.set_config({}, overwrite=True)

    @property
    def root(self):
        return controllers.versions.VersionController()


class BaseSecretsResource(FunctionalTest):
    """Base test class for the Secrets resource."""

    def setUp(self):
        super(BaseSecretsResource, self).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController()

        return RootController()

    def _init(self, payload=b'not-encrypted',
              payload_content_type='text/plain',
              payload_content_encoding=None):
        self.name = 'name'
        self.payload = payload
        self.payload_content_type = payload_content_type
        self.payload_content_encoding = payload_content_encoding
        self.secret_algorithm = 'AES'
        self.secret_bit_length = 256
        self.secret_mode = 'CBC'
        self.secret_req = {'name': self.name,
                           'algorithm': self.secret_algorithm,
                           'bit_length': self.secret_bit_length,
                           'creator_id': None,
                           'mode': self.secret_mode}
        if payload:
            self.secret_req['payload'] = payload
        if payload_content_type:
            self.secret_req['payload_content_type'] = payload_content_type
        if payload_content_encoding:
            self.secret_req['payload_content_encoding'] = (
                payload_content_encoding)

        # Set up mocked project
        self.external_project_id = 'keystone1234'
        self.project_entity_id = 'tid1234'
        self.project = models.Project()
        self.project.id = self.project_entity_id
        self.project.external_id = self.external_project_id

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.find_by_external_project_id.return_value = (
            self.project)
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked secret
        self.secret = models.Secret()
        self.secret.id = utils.generate_test_valid_uuid()

        # Set up mocked secret repo
        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = self.secret
        self.setup_secret_repository_mock(self.secret_repo)

        # Set up mocked encrypted datum repo
        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None
        self.setup_encrypted_datum_repository_mock(self.datum_repo)

        # Set up mocked kek datum
        self.kek_datum = models.KEKDatum()
        self.kek_datum.kek_label = "kek_label"
        self.kek_datum.bind_completed = False
        self.kek_datum.algorithm = ''
        self.kek_datum.bit_length = 0
        self.kek_datum.mode = ''
        self.kek_datum.plugin_meta = ''

        # Set up mocked kek datum repo
        self.kek_repo = mock.MagicMock()
        self.kek_repo.find_or_create_kek_datum.return_value = self.kek_datum
        self.setup_kek_datum_repository_mock(self.kek_repo)

        # Set up mocked secret meta repo
        self.setup_secret_meta_repository_mock()

        # Set up mocked transport key
        self.transport_key = models.TransportKey(
            'default_plugin_name', 'XXXABCDEF')
        self.transport_key_id = 'tkey12345'
        self.tkey_url = hrefs.convert_transport_key_to_href(
            self.transport_key.id)

        # Set up mocked transport key
        self.setup_transport_key_repository_mock()


class WhenGettingPuttingOrDeletingSecretUsingSecretResource(FunctionalTest):
    def setUp(self):
        super(
            WhenGettingPuttingOrDeletingSecretUsingSecretResource, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController()

        return RootController()

    def _init(self):
        self.project_id = 'projectid1234'
        self.external_project_id = 'keystone1234'
        self.name = 'name1234'

        secret_id = utils.generate_test_valid_uuid()
        datum_id = "iddatum1"
        kek_id = "idkek1"

        self.secret_algorithm = "AES"
        self.secret_bit_length = 256
        self.secret_mode = "CBC"

        self.kek_project = models.KEKDatum()
        self.kek_project.id = kek_id
        self.kek_project.active = True
        self.kek_project.bind_completed = False
        self.kek_project.kek_label = "kek_label"

        self.datum = models.EncryptedDatum()
        self.datum.id = datum_id
        self.datum.secret_id = secret_id
        self.datum.kek_id = kek_id
        self.datum.kek_meta_project = self.kek_project
        self.datum.content_type = "text/plain"
        self.datum.cypher_text = "aaaa"  # base64 value.

        self.secret = create_secret(id_ref=secret_id,
                                    name=self.name,
                                    algorithm=self.secret_algorithm,
                                    bit_length=self.secret_bit_length,
                                    mode=self.secret_mode,
                                    encrypted_datum=self.datum,
                                    content_type=self.datum.content_type)

        self.secret.secret_acls = []
        self.secret.project = mock.MagicMock()
        self.secret.project.external_id = self.external_project_id

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_id
        self.project.external_id = self.external_project_id

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.project_repo.find_by_external_project_id.return_value = (
            self.project)
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked secret repo
        self.secret_repo = mock.Mock()
        self.secret_repo.get = mock.Mock(return_value=self.secret)
        self.secret_repo.get_secret_by_id = mock.Mock(return_value=self.secret)
        self.secret_repo.delete_entity_by_id = mock.Mock(return_value=None)
        self.setup_secret_repository_mock(self.secret_repo)

        # Set up mocked encrypted datum repo
        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None
        self.setup_encrypted_datum_repository_mock(self.datum_repo)

        # Set up mocked kek datum repo
        self.setup_kek_datum_repository_mock()

        # Set up mocked secret meta repo
        self.secret_meta_repo = mock.MagicMock()
        self.secret_meta_repo.get_metadata_for_secret.return_value = None
        self.setup_secret_meta_repository_mock(self.secret_meta_repo)

        # Set up mocked transport key
        self.transport_key_model = models.TransportKey(
            "default_plugin", "my transport key")

        # Set up mocked transport key repo
        self.transport_key_repo = mock.MagicMock()
        self.transport_key_repo.get.return_value = self.transport_key_model
        self.setup_transport_key_repository_mock(self.transport_key_repo)

        self.transport_key_id = 'tkey12345'

    @mock.patch('barbican.plugin.resources.get_transport_key_id_for_retrieval')
    def _test_should_get_secret_as_json(self, mock_get_transport_key):
        mock_get_transport_key.return_value = None
        resp = self.app.get(
            '/secrets/{0}/'.format(self.secret.id),
            headers={'Accept': 'application/json', 'Accept-Encoding': 'gzip'}
        )
        self.secret_repo.get_secret_by_id.assert_called_once_with(
            entity_id=self.secret.id,
            suppress_exception=True)
        self.assertEqual(200, resp.status_int)

        self.assertNotIn('content_encodings', resp.namespace)
        self.assertIn('content_types', resp.namespace)
        self.assertIn(self.datum.content_type,
                      resp.namespace['content_types'].values())
        self.assertNotIn('mime_type', resp.namespace)

        return resp.json

    def test_should_get_secret_as_json_v0(self):
        secret = self._test_should_get_secret_as_json()
        self.assertNotIn('consumers', secret)

    def test_should_get_secret_as_json_v1(self):
        utils.set_version(self.app, '1.1')
        secret = self._test_should_get_secret_as_json()
        self.assertIn('consumers', secret)

    @testcase.attr('deprecated')
    @mock.patch('barbican.plugin.resources.get_secret')
    def test_should_get_secret_as_plain_based_on_content_type(self,
                                                              mock_get_secret):
        data = 'unencrypted_data'
        mock_get_secret.return_value = data

        resp = self.app.get(
            '/secrets/{0}/payload/'.format(self.secret.id),
            headers={'Accept': 'text/plain'}
        )

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            entity_id=self.secret.id,
            suppress_exception=True)
        self.assertEqual(200, resp.status_int)

        self.assertEqual(data, resp.body.decode())
        mock_get_secret.assert_called_once_with(
            'text/plain',
            self.secret,
            self.project,
            None,
            None
        )

    @mock.patch('barbican.plugin.resources.get_secret')
    def test_should_get_secret_as_plain_with_twsk(self, mock_get_secret):
        data = 'encrypted_data'
        mock_get_secret.return_value = data

        twsk = "trans_wrapped_session_key"
        resp = self.app.get(
            ('/secrets/{0}/payload/'
             '?trans_wrapped_session_key={1}&transport_key_id={2}')
            .format(self.secret.id, twsk, self.transport_key_id),
            headers={'Accept': 'text/plain'}
        )

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            entity_id=self.secret.id,
            suppress_exception=True)
        self.assertEqual(200, resp.status_int)

        self.assertEqual(data, resp.body.decode())
        mock_get_secret.assert_called_once_with(
            'text/plain',
            self.secret,
            self.project,
            twsk,
            self.transport_key_model.transport_key
        )

    @testcase.attr('deprecated')
    @mock.patch('barbican.plugin.resources.get_secret')
    def test_should_get_secret_as_plain_with_twsk_based_on_content_type(
            self, mock_get_secret):
        data = 'encrypted_data'
        mock_get_secret.return_value = data

        twsk = "trans_wrapped_session_key"
        resp = self.app.get(
            ('/secrets/{0}/'
             '?trans_wrapped_session_key={1}&transport_key_id={2}')
            .format(self.secret.id, twsk, self.transport_key_id),
            headers={'Accept': 'text/plain'}
        )

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            entity_id=self.secret.id,
            suppress_exception=True)
        self.assertEqual(200, resp.status_int)

        self.assertEqual(data, resp.body.decode())
        mock_get_secret.assert_called_once_with(
            'text/plain',
            self.secret,
            self.project,
            twsk,
            self.transport_key_model.transport_key
        )

    @mock.patch('barbican.plugin.resources.get_secret')
    def test_should_throw_exception_for_get_when_twsk_but_no_tkey_id(
            self, mock_get_secret):
        data = 'encrypted_data'
        mock_get_secret.return_value = data

        twsk = "trans_wrapped_session_key"
        resp = self.app.get(
            '/secrets/{0}/payload/?trans_wrapped_session_key={1}'.format(
                self.secret.id, twsk),
            headers={'Accept': 'text/plain'},
            expect_errors=True
        )

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            entity_id=self.secret.id,
            suppress_exception=True)
        self.assertEqual(400, resp.status_int)

    @testcase.attr('deprecated')
    @mock.patch('barbican.plugin.resources.get_secret')
    def test_should_throw_exception_for_get_when_twsk_but_no_tkey_id_old_way(
            self, mock_get_secret):
        data = 'encrypted_data'
        mock_get_secret.return_value = data

        twsk = "trans_wrapped_session_key"
        resp = self.app.get(
            '/secrets/{0}/payload/?trans_wrapped_session_key={1}'.format(
                self.secret.id, twsk),
            headers={'Accept': 'text/plain'},
            expect_errors=True
        )

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            entity_id=self.secret.id,
            suppress_exception=True)
        self.assertEqual(400, resp.status_int)

    @mock.patch('barbican.plugin.resources.get_transport_key_id_for_retrieval')
    def test_should_get_secret_meta_for_binary(self, mock_get_transport_key):
        mock_get_transport_key.return_value = None
        self.datum.content_type = "application/octet-stream"
        self.secret.secret_store_metadata['content_type'].value = (
            self.datum.content_type
        )
        self.datum.cypher_text = 'aaaa'

        resp = self.app.get(
            '/secrets/{0}/'.format(self.secret.id),
            headers={'Accept': 'application/json', 'Accept-Encoding': 'gzip'}
        )

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            entity_id=self.secret.id,
            suppress_exception=True)

        self.assertEqual(200, resp.status_int)

        self.assertIsNotNone(resp.namespace)
        self.assertIn('content_types', resp.namespace)
        self.assertIn(self.datum.content_type,
                      resp.namespace['content_types'].values())

    @mock.patch('barbican.plugin.resources.get_transport_key_id_for_retrieval')
    def test_should_get_secret_meta_for_binary_with_tkey(
            self, mock_get_transport_key_id):
        mock_get_transport_key_id.return_value = self.transport_key_id
        self.datum.content_type = "application/octet-stream"
        self.secret.secret_store_metadata['content_type'].value = (
            self.datum.content_type
        )
        self.datum.cypher_text = 'aaaa'

        resp = self.app.get(
            '/secrets/{0}/?transport_key_needed=true'.format(
                self.secret.id),
            headers={'Accept': 'application/json', 'Accept-Encoding': 'gzip'}
        )

        self.secret_repo.get_secret_by_id.assert_called_once_with(
            entity_id=self.secret.id,
            suppress_exception=True)

        self.assertEqual(200, resp.status_int)

        self.assertIsNotNone(resp.namespace)
        self.assertIn('content_types', resp.namespace)
        self.assertIn(self.datum.content_type,
                      resp.namespace['content_types'].values())
        self.assertIn('transport_key_ref', resp.namespace)
        self.assertEqual(
            hrefs.convert_transport_key_to_href(self.transport_key_id),
            resp.namespace['transport_key_ref']
        )

    @testcase.attr('deprecated')
    @mock.patch('barbican.plugin.resources.get_secret')
    def test_should_get_secret_as_binary_based_on_content_type(
            self, mock_get_secret):
        data = 'unencrypted_data'
        mock_get_secret.return_value = data

        self.datum.content_type = "application/octet-stream"
        self.datum.cypher_text = 'aaaa'

        resp = self.app.get(
            '/secrets/{0}/'.format(self.secret.id),
            headers={
                'Accept': 'application/octet-stream',
                'Accept-Encoding': 'gzip'
            }
        )

        self.assertEqual(data, resp.body.decode())

        mock_get_secret.assert_called_once_with(
            'application/octet-stream',
            self.secret,
            self.project,
            None,
            None
        )

    @mock.patch('barbican.plugin.resources.store_secret')
    def test_should_put_secret_as_plain_with_tkey_id(self, mock_store_secret):
        self.secret.encrypted_data = []
        self.secret.secret_store_metadata = {}

        resp = self.app.put(
            '/secrets/{0}/?transport_key_id={1}'.format(
                self.secret.id, self.transport_key_id),
            'plain text',
            headers={'Accept': 'text/plain', 'Content-Type': 'text/plain'},
        )

        self.assertEqual(204, resp.status_int)

        mock_store_secret.assert_called_once_with(
            unencrypted_raw=b'plain text',
            content_type_raw='text/plain',
            content_encoding=None,
            secret_model=self.secret,
            project_model=self.project,
            transport_key_id=self.transport_key_id
        )

    @mock.patch('barbican.plugin.resources.store_secret')
    def test_should_put_secret_as_binary_with_tkey_id(self, mock_store_secret):
        self.secret.encrypted_data = []
        self.secret.secret_store_metadata = {}

        resp = self.app.put(
            '/secrets/{0}/?transport_key_id={1}'.format(
                self.secret.id, self.transport_key_id),
            'plain text',
            headers={
                'Accept': 'text/plain',
                'Content-Type': 'application/octet-stream'
            },
        )

        self.assertEqual(204, resp.status_int)

        mock_store_secret.assert_called_once_with(
            unencrypted_raw=b'plain text',
            content_type_raw='application/octet-stream',
            content_encoding=None,
            secret_model=self.secret,
            project_model=self.project,
            transport_key_id=self.transport_key_id
        )


class WhenAddingNavigationHrefs(utils.BaseTestCase):

    def setUp(self):
        super(WhenAddingNavigationHrefs, self).setUp()

        self.resource_name = 'orders'
        self.external_project_id = '12345'
        self.num_elements = 100
        self.data = {}

    def test_add_nav_hrefs_adds_next_only(self):
        offset = 0
        limit = 10

        data_with_hrefs = hrefs.add_nav_hrefs(
            self.resource_name, offset, limit, self.num_elements, self.data)

        self.assertNotIn('previous', data_with_hrefs)
        self.assertIn('next', data_with_hrefs)

    def test_add_nav_hrefs_adds_both_next_and_previous(self):
        offset = 10
        limit = 10

        data_with_hrefs = hrefs.add_nav_hrefs(
            self.resource_name, offset, limit, self.num_elements, self.data)

        self.assertIn('previous', data_with_hrefs)
        self.assertIn('next', data_with_hrefs)

    def test_add_nav_hrefs_adds_previous_only(self):
        offset = 90
        limit = 10

        data_with_hrefs = hrefs.add_nav_hrefs(
            self.resource_name, offset, limit, self.num_elements, self.data)

        self.assertIn('previous', data_with_hrefs)
        self.assertNotIn('next', data_with_hrefs)


class TestingJsonSanitization(utils.BaseTestCase):

    def test_json_sanitization_without_array(self):
        json_without_array = {"name": "name", "algorithm": "AES",
                              "payload_content_type": "  text/plain   ",
                              "mode": "CBC", "bit_length": 256,
                              "payload": "not-encrypted"}

        self.assertTrue(json_without_array['payload_content_type']
                        .startswith(' '), "whitespace should be there")
        self.assertTrue(json_without_array['payload_content_type']
                        .endswith(' '), "whitespace should be there")
        api.strip_whitespace(json_without_array)
        self.assertFalse(json_without_array['payload_content_type']
                         .startswith(' '), "whitespace should be gone")
        self.assertFalse(json_without_array['payload_content_type']
                         .endswith(' '), "whitespace should be gone")

    def test_json_sanitization_with_array(self):
        json_with_array = {"name": "name", "algorithm": "AES",
                           "payload_content_type": "text/plain",
                           "mode": "CBC", "bit_length": 256,
                           "payload": "not-encrypted",
                           "an-array":
                           [{"name": " item 1"},
                            {"name": "item2 "}]}

        self.assertTrue(json_with_array['an-array'][0]['name']
                        .startswith(' '), "whitespace should be there")
        self.assertTrue(json_with_array['an-array'][1]['name']
                        .endswith(' '), "whitespace should be there")
        api.strip_whitespace(json_with_array)
        self.assertFalse(json_with_array['an-array'][0]['name']
                         .startswith(' '), "whitespace should be gone")
        self.assertFalse(json_with_array['an-array'][1]['name']
                         .endswith(' '), "whitespace should be gone")


class WhenCreatingContainerConsumersUsingResource(FunctionalTest):
    def setUp(self):
        super(
            WhenCreatingContainerConsumersUsingResource, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            containers = controllers.containers.ContainersController()

        return RootController()

    def _init(self):
        self.name = 'test container name'
        self.type = 'generic'
        self.secret_refs = [
            {
                'name': 'test secret 1',
                'secret_ref': '1231'
            },
            {
                'name': 'test secret 2',
                'secret_ref': '1232'
            },
            {
                'name': 'test secret 3',
                'secret_ref': '1233'
            }
        ]

        self.consumer_ref = {
            'name': 'test_consumer1',
            'URL': 'http://consumer/1'
        }

        self.project_internal_id = 'projectid1234'
        self.external_project_id = 'keystoneid1234'

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_internal_id
        self.project.external_id = self.external_project_id

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked quota enforcer
        self.quota_patch = mock.patch(
            'barbican.common.quota.QuotaEnforcer.enforce', return_value=None)
        self.quota_patch.start()
        self.addCleanup(self.quota_patch.stop)

        # Set up mocked container
        self.container = create_container(
            id_ref=utils.generate_test_valid_uuid(),
            project_id=self.project_internal_id,
            external_project_id=self.external_project_id)

        # Set up mocked container repo
        self.container_repo = mock.MagicMock()
        self.container_repo.get_container_by_id.return_value = self.container
        self.setup_container_repository_mock(self.container_repo)

        # Set up secret repo
        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = None
        self.setup_secret_repository_mock(self.secret_repo)

        # Set up container consumer repo
        self.consumer_repo = mock.MagicMock()
        self.consumer_repo.create_from.return_value = None
        self.setup_container_consumer_repository_mock(self.consumer_repo)

        self.container_req = {'name': self.name,
                              'type': self.type,
                              'secret_refs': self.secret_refs}

    def test_should_add_new_consumer(self):
        resp = self.app.post_json(
            '/containers/{0}/consumers/'.format(self.container.id),
            self.consumer_ref
        )
        self.assertEqual(200, resp.status_int)
        self.assertNotIn(self.external_project_id, resp.headers['Location'])

        args, kwargs = self.consumer_repo.create_or_update_from.call_args
        consumer = args[0]
        self.assertIsInstance(consumer, models.ContainerConsumerMetadatum)

    def test_should_fail_consumer_bad_json(self):
        resp = self.app.post(
            '/containers/{0}/consumers/'.format(self.container.id),
            '',
            expect_errors=True
        )
        self.assertEqual(415, resp.status_int)

    def test_should_404_when_container_ref_doesnt_exist(self):
        self.container_repo.get_container_by_id.return_value = None
        resp = self.app.post_json(
            '/containers/{0}/consumers/'.format('bad_id'),
            self.consumer_ref, expect_errors=True
        )
        self.assertEqual(404, resp.status_int)


class WhenGettingOrDeletingContainerConsumersUsingResource(FunctionalTest):

    def setUp(self):
        super(
            WhenGettingOrDeletingContainerConsumersUsingResource, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            containers = controllers.containers.ContainersController()

        return RootController()

    def _init(self):
        self.external_project_id = 'keystoneid1234'
        self.project_internal_id = 'projectid1234'

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_internal_id
        self.project.external_id = self.external_project_id

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked container
        self.container = create_container(
            id_ref=utils.generate_test_valid_uuid(),
            project_id=self.project_internal_id,
            external_project_id=self.external_project_id)

        # Set up mocked consumers
        self.consumer = create_container_consumer(
            self.container.id, self.project_internal_id,
            id_ref=utils.generate_test_valid_uuid())
        self.consumer2 = create_container_consumer(
            self.container.id, self.project_internal_id,
            id_ref=utils.generate_test_valid_uuid())

        self.consumer_ref = {
            'name': self.consumer.name,
            'URL': self.consumer.URL
        }

        # Set up mocked container repo
        self.container_repo = mock.MagicMock()
        self.container_repo.get_container_by_id.return_value = self.container
        self.setup_container_repository_mock(self.container_repo)

        # Set up mocked container consumer repo
        self.consumer_repo = mock.MagicMock()
        self.consumer_repo.get_by_values.return_value = self.consumer
        self.consumer_repo.delete_entity_by_id.return_value = None
        self.setup_container_consumer_repository_mock(self.consumer_repo)

        # Set up mocked secret repo
        self.setup_secret_repository_mock()

    def test_should_get_consumer(self):
        ret_val = ([self.consumer], 0, 0, 1)
        self.consumer_repo.get_by_container_id.return_value = ret_val

        resp = self.app.get('/containers/{0}/consumers/'.format(
            self.container.id
        ))
        self.assertEqual(200, resp.status_int)

        self.consumer_repo.get_by_container_id.assert_called_once_with(
            self.container.id,
            limit_arg=None,
            offset_arg=0,
            suppress_exception=True
        )

        self.assertEqual(self.consumer.name, resp.json['consumers'][0]['name'])
        self.assertEqual(self.consumer.URL, resp.json['consumers'][0]['URL'])

    def test_should_404_when_container_ref_doesnt_exist(self):
        self.container_repo.get_container_by_id.return_value = None
        resp = self.app.get('/containers/{0}/consumers/'.format(
            'bad_id'
        ), expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_consumer_by_id(self):
        self.consumer_repo.get.return_value = self.consumer
        resp = self.app.get('/containers/{0}/consumers/{1}/'.format(
            self.container.id, self.consumer.id
        ))
        self.assertEqual(200, resp.status_int)

    def test_should_404_with_bad_consumer_id(self):
        self.consumer_repo.get.return_value = None
        resp = self.app.get('/containers/{0}/consumers/{1}/'.format(
            self.container.id, 'bad_id'
        ), expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_no_consumers(self):
        self.consumer_repo.get_by_container_id.return_value = ([], 0, 0, 0)
        resp = self.app.get('/containers/{0}/consumers/'.format(
            self.container.id
        ))
        self.assertEqual(200, resp.status_int)

    def test_should_delete_consumer(self):
        self.app.delete_json('/containers/{0}/consumers/'.format(
            self.container.id
        ), self.consumer_ref)

        self.consumer_repo.delete_entity_by_id.assert_called_once_with(
            self.consumer.id, self.external_project_id)

    def test_should_fail_deleting_consumer_bad_json(self):
        resp = self.app.delete(
            '/containers/{0}/consumers/'.format(self.container.id),
            '',
            expect_errors=True
        )
        self.assertEqual(415, resp.status_int)

    def test_should_404_on_delete_when_consumer_not_found(self):
        old_return = self.consumer_repo.get_by_values.return_value
        self.consumer_repo.get_by_values.return_value = None
        resp = self.app.delete_json('/containers/{0}/consumers/'.format(
            self.container.id
        ), self.consumer_ref, expect_errors=True)
        self.consumer_repo.get_by_values.return_value = old_return
        self.assertEqual(404, resp.status_int)
        # Error response should have json content type
        self.assertEqual("application/json", resp.content_type)

    def test_should_404_on_delete_when_consumer_not_found_later(self):
        self.consumer_repo.delete_entity_by_id.side_effect = excep.NotFound()
        resp = self.app.delete_json('/containers/{0}/consumers/'.format(
            self.container.id
        ), self.consumer_ref, expect_errors=True)
        self.consumer_repo.delete_entity_by_id.side_effect = None
        self.assertEqual(404, resp.status_int)
        # Error response should have json content type
        self.assertEqual("application/json", resp.content_type)

    def test_should_delete_consumers_on_container_delete(self):
        consumers = [self.consumer, self.consumer2]
        ret_val = (consumers, 0, 0, 1)
        self.consumer_repo.get_by_container_id.return_value = ret_val

        resp = self.app.delete(
            '/containers/{0}/'.format(self.container.id)
        )
        self.assertEqual(204, resp.status_int)

        # Verify consumers were deleted
        calls = []
        for consumer in consumers:
            calls.append(mock.call(consumer.id, self.external_project_id))
        self.consumer_repo.delete_entity_by_id.assert_has_calls(
            calls, any_order=True
        )

    def test_should_pass_on_container_delete_with_missing_consumers(self):
        consumers = [self.consumer, self.consumer2]
        ret_val = (consumers, 0, 0, 1)
        self.consumer_repo.get_by_container_id.return_value = ret_val
        self.consumer_repo.delete_entity_by_id.side_effect = excep.NotFound

        resp = self.app.delete(
            '/containers/{0}/'.format(self.container.id)
        )
        self.assertEqual(204, resp.status_int)

        # Verify consumers were deleted
        calls = []
        for consumer in consumers:
            calls.append(mock.call(consumer.id, self.external_project_id))
        self.consumer_repo.delete_entity_by_id.assert_has_calls(
            calls, any_order=True
        )


class WhenPerformingUnallowedOperationsOnContainerConsumers(FunctionalTest):
    def setUp(self):
        super(
            WhenPerformingUnallowedOperationsOnContainerConsumers, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            containers = controllers.containers.ContainersController()

        return RootController()

    def _init(self):
        self.name = 'test container name'
        self.type = 'generic'
        self.secret_refs = [
            {
                'name': 'test secret 1',
                'secret_ref': '1231'
            },
            {
                'name': 'test secret 2',
                'secret_ref': '1232'
            },
            {
                'name': 'test secret 3',
                'secret_ref': '1233'
            }
        ]

        self.consumer_ref = {
            'name': 'test_consumer1',
            'URL': 'http://consumer/1'
        }
        self.external_project_id = 'keystoneid1234'
        self.project_internal_id = 'projectid1234'

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_internal_id
        self.project.external_id = self.external_project_id

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked container
        self.container = create_container(
            id_ref=utils.generate_test_valid_uuid(),
            project_id=self.project_internal_id,
            external_project_id=self.external_project_id)

        # Set up mocked container consumers
        self.consumer = create_container_consumer(
            self.container.id, self.project_internal_id,
            id_ref=utils.generate_test_valid_uuid())
        self.consumer2 = create_container_consumer(
            self.container.id, self.project_internal_id,
            id_ref=utils.generate_test_valid_uuid())

        self.consumer_ref = {
            'name': self.consumer.name,
            'URL': self.consumer.URL
        }

        # Set up container repo
        self.container_repo = mock.MagicMock()
        self.container_repo.get_container_by_id.return_value = self.container
        self.setup_container_repository_mock(self.container_repo)

        # Set up container consumer repo
        self.consumer_repo = mock.MagicMock()
        self.consumer_repo.get_by_values.return_value = self.consumer
        self.consumer_repo.delete_entity_by_id.return_value = None
        self.setup_container_consumer_repository_mock(self.consumer_repo)

        # Set up secret repo
        self.setup_secret_repository_mock()

    def test_should_not_allow_put_on_consumers(self):
        ret_val = ([self.consumer], 0, 0, 1)
        self.consumer_repo.get_by_container_id.return_value = ret_val

        resp = self.app.put_json(
            '/containers/{0}/consumers/'.format(self.container.id),
            self.consumer_ref,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_post_on_consumer_by_id(self):
        self.consumer_repo.get.return_value = self.consumer
        resp = self.app.post_json(
            '/containers/{0}/consumers/{1}/'.format(self.container.id,
                                                    self.consumer.id),
            self.consumer_ref,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_put_on_consumer_by_id(self):
        self.consumer_repo.get.return_value = self.consumer
        resp = self.app.put_json(
            '/containers/{0}/consumers/{1}/'.format(self.container.id,
                                                    self.consumer.id),
            self.consumer_ref,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_delete_on_consumer_by_id(self):
        self.consumer_repo.get.return_value = self.consumer
        resp = self.app.delete(
            '/containers/{0}/consumers/{1}/'.format(self.container.id,
                                                    self.consumer.id),
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)


class WhenOwnershipMismatchForContainerConsumer(FunctionalTest):

    def setUp(self):
        super(
            WhenOwnershipMismatchForContainerConsumer, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            containers = controllers.containers.ContainersController()
        return RootController()

    def _init(self):
        self.external_project_id = 'keystoneid1234'
        self.project_internal_id = 'projectid1234'

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_internal_id
        self.project.external_id = self.external_project_id

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked container
        self.container = create_container(
            id_ref=utils.generate_test_valid_uuid(),
            project_id=self.project_internal_id,
            external_project_id='differentProjectId')

        # Set up mocked consumers
        self.consumer = create_container_consumer(self.container.id,
                                                  self.project_internal_id,
                                                  id_ref='id2')
        self.consumer2 = create_container_consumer(self.container.id,
                                                   self.project_internal_id,
                                                   id_ref='id3')

        self.consumer_ref = {
            'name': self.consumer.name,
            'URL': self.consumer.URL
        }

        # Set up mocked container repo
        self.container_repo = mock.MagicMock()
        self.container_repo.get.return_value = self.container
        self.container_repo.get_container_by_id.return_value = self.container
        self.setup_container_repository_mock(self.container_repo)

        # Set up mocked container consumer repo
        self.consumer_repo = mock.MagicMock()
        self.consumer_repo.get_by_values.return_value = self.consumer
        self.consumer_repo.delete_entity_by_id.return_value = None
        self.setup_container_consumer_repository_mock(self.consumer_repo)

        # Set up mocked secret repo
        self.setup_secret_repository_mock()

    def test_consumer_check_ownership_mismatch(self):
        resp = self.app.delete_json(
            '/containers/{0}/consumers/'.format(self.container.id),
            self.consumer_ref, expect_errors=True)
        self.assertEqual(403, resp.status_int)


class WhenCreatingSecretConsumersUsingResource(FunctionalTest):
    def setUp(self):
        super(
            WhenCreatingSecretConsumersUsingResource, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController()

        return RootController()

    def _init(self):
        self.name = 'test container name'
        self.external_project_id = 'keystoneid1234'
        self.project_internal_id = 'projectid1234'

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_internal_id
        self.project.external_id = self.external_project_id

        # Set up mocked secret
        secret_id = utils.generate_test_valid_uuid()
        datum_id = "iddatum1"
        kek_id = "idkek1"

        self.secret_algorithm = "AES"
        self.secret_bit_length = 256
        self.secret_mode = "CBC"

        self.kek_project = models.KEKDatum()
        self.kek_project.id = kek_id
        self.kek_project.active = True
        self.kek_project.bind_completed = False
        self.kek_project.kek_label = "kek_label"

        self.datum = models.EncryptedDatum()
        self.datum.id = datum_id
        self.datum.secret_id = secret_id
        self.datum.kek_id = kek_id
        self.datum.kek_meta_project = self.kek_project
        self.datum.content_type = "text/plain"
        self.datum.cypher_text = "aaaa"  # base64 value.

        self.secret = create_secret(id_ref=secret_id,
                                    name=self.name,
                                    algorithm=self.secret_algorithm,
                                    bit_length=self.secret_bit_length,
                                    mode=self.secret_mode,
                                    encrypted_datum=self.datum,
                                    content_type=self.datum.content_type)
        self.secret.project = self.project
        self.secret.project_id = self.project_internal_id

        # Set up consumer ref
        self.consumer_ref = {
            "service": "service",
            "resource_type": "resource_type",
            "resource_id": "resource_id",
        }

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked quota enforcer
        self.quota_patch = mock.patch(
            'barbican.common.quota.QuotaEnforcer.enforce', return_value=None)
        self.quota_patch.start()
        self.addCleanup(self.quota_patch.stop)

        # Set up mocked secret repo
        self.secret_repo = mock.MagicMock()
        self.secret_repo.get_secret_by_id.return_value = self.secret
        self.setup_secret_repository_mock(self.secret_repo)

        # Set up mocked secret meta repo
        self.secret_meta_repo = mock.MagicMock()
        self.secret_meta_repo.get_metadata_for_secret.return_value = None
        self.setup_secret_meta_repository_mock(self.secret_meta_repo)

        # Set up mocked secret consumer repo
        self.consumer_repo = mock.MagicMock()
        self.consumer_repo.create_from.return_value = None
        self.setup_secret_consumer_repository_mock(self.consumer_repo)

    def test_should_add_new_consumer(self):
        resp = self.app.post_json(
            '/secrets/{0}/consumers/'.format(self.secret.id),
            self.consumer_ref
        )
        self.assertEqual(200, resp.status_int)
        self.assertNotIn(self.external_project_id, resp.headers['Location'])

        args, kwargs = self.consumer_repo.create_or_update_from.call_args
        consumer = args[0]
        self.assertIsInstance(consumer, models.SecretConsumerMetadatum)
        self.assertIn('content_types', resp.namespace)

    def test_should_fail_consumer_bad_json(self):
        resp = self.app.post(
            '/secrets/{0}/consumers/'.format(self.secret.id),
            '',
            expect_errors=True
        )
        self.assertEqual(415, resp.status_int)

    def test_should_404_when_secret_ref_doesnt_exist(self):
        self.secret_repo.get_secret_by_id.return_value = None
        resp = self.app.post_json(
            '/secrets/{0}/consumers/'.format('bad_id'),
            self.consumer_ref, expect_errors=True
        )
        self.assertEqual(404, resp.status_int)


class WhenGettingOrDeletingSecretConsumersUsingResource(FunctionalTest):

    def setUp(self):
        super(
            WhenGettingOrDeletingSecretConsumersUsingResource, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController()

        return RootController()

    def _init(self):
        self.name = 'test container name'
        self.external_project_id = 'keystoneid1234'
        self.project_internal_id = 'projectid1234'

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_internal_id
        self.project.external_id = self.external_project_id

        # Set up mocked secret
        secret_id = utils.generate_test_valid_uuid()
        datum_id = "iddatum1"
        kek_id = "idkek1"

        self.secret_algorithm = "AES"
        self.secret_bit_length = 256
        self.secret_mode = "CBC"

        self.kek_project = models.KEKDatum()
        self.kek_project.id = kek_id
        self.kek_project.active = True
        self.kek_project.bind_completed = False
        self.kek_project.kek_label = "kek_label"

        self.datum = models.EncryptedDatum()
        self.datum.id = datum_id
        self.datum.secret_id = secret_id
        self.datum.kek_id = kek_id
        self.datum.kek_meta_project = self.kek_project
        self.datum.content_type = "text/plain"
        self.datum.cypher_text = "aaaa"  # base64 value.

        self.secret = create_secret(id_ref=secret_id,
                                    name=self.name,
                                    algorithm=self.secret_algorithm,
                                    bit_length=self.secret_bit_length,
                                    mode=self.secret_mode,
                                    encrypted_datum=self.datum,
                                    content_type=self.datum.content_type)
        self.secret.project = self.project
        self.secret.project_id = self.project_internal_id

        # Set up mocked consumers
        self.consumer = create_secret_consumer(
            self.secret.id, self.project_internal_id,
            id_ref=utils.generate_test_valid_uuid())
        self.consumer2 = create_secret_consumer(
            self.secret.id, self.project_internal_id,
            id_ref=utils.generate_test_valid_uuid())

        self.consumer_ref = {
            "service": self.consumer.service,
            "resource_type": self.consumer.resource_type,
            "resource_id": self.consumer.resource_type,
        }

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked secret repo
        self.secret_repo = mock.MagicMock()
        self.secret_repo.get_secret_by_id.return_value = self.secret
        self.setup_secret_repository_mock(self.secret_repo)

        # Set up mocked secret meta repo
        self.secret_meta_repo = mock.MagicMock()
        self.secret_meta_repo.get_metadata_for_secret.return_value = None
        self.setup_secret_meta_repository_mock(self.secret_meta_repo)

        # Set up mocked secret consumer repo
        self.consumer_repo = mock.MagicMock()
        self.consumer_repo.get_by_values.return_value = self.consumer
        self.consumer_repo.delete_entity_by_id.return_value = None
        self.setup_secret_consumer_repository_mock(self.consumer_repo)

    def test_should_get_consumer(self):
        ret_val = ([self.consumer], 0, 0, 1)
        self.consumer_repo.get_by_secret_id.return_value = ret_val

        resp = self.app.get('/secrets/{0}/consumers/'.format(
            self.secret.id
        ))
        self.assertEqual(200, resp.status_int)

        self.consumer_repo.get_by_secret_id.assert_called_once_with(
            self.secret.id,
            limit_arg=None,
            offset_arg=0,
            suppress_exception=True
        )

        self.assertEqual(
            self.consumer.service,
            resp.json["consumers"][0]["service"],
        )
        self.assertEqual(
            self.consumer.resource_type,
            resp.json["consumers"][0]["resource_type"]
        )
        self.assertEqual(
            self.consumer.resource_id,
            resp.json["consumers"][0]["resource_id"]
        )

    def test_should_404_when_secret_ref_doesnt_exist(self):
        self.secret_repo.get_secret_by_id.return_value = None
        resp = self.app.get('/secrets/{0}/consumers/'.format(
            'bad_id'
        ), expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_consumer_by_id(self):
        self.consumer_repo.get.return_value = self.consumer
        resp = self.app.get('/secrets/{0}/consumers/{1}/'.format(
            self.secret.id, self.consumer.id
        ))
        self.assertEqual(200, resp.status_int)

    def test_should_404_with_bad_consumer_id(self):
        self.consumer_repo.get.return_value = None
        resp = self.app.get('/secrets/{0}/consumers/{1}/'.format(
            self.secret.id, 'bad_id'
        ), expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_get_no_consumers(self):
        self.consumer_repo.get_by_secret_id.return_value = ([], 0, 0, 0)
        resp = self.app.get('/secrets/{0}/consumers/'.format(
            self.secret.id
        ))
        self.assertEqual(200, resp.status_int)

    def test_should_delete_consumer(self):
        resp = self.app.delete_json('/secrets/{0}/consumers/'.format(
            self.secret.id
        ), self.consumer_ref)

        self.consumer_repo.delete_entity_by_id.assert_called_once_with(
            self.consumer.id, self.external_project_id)
        self.assertIn('content_types', resp.namespace)

    def test_should_fail_deleting_consumer_bad_json(self):
        resp = self.app.delete(
            '/secrets/{0}/consumers/'.format(self.secret.id),
            '',
            expect_errors=True
        )
        self.assertEqual(415, resp.status_int)

    def test_should_404_on_delete_when_consumer_not_found(self):
        old_return = self.consumer_repo.get_by_values.return_value
        self.consumer_repo.get_by_values.return_value = None
        resp = self.app.delete_json('/secrets/{0}/consumers/'.format(
            self.secret.id
        ), self.consumer_ref, expect_errors=True)
        self.consumer_repo.get_by_values.return_value = old_return
        self.assertEqual(404, resp.status_int)
        # Error response should have json content type
        self.assertEqual("application/json", resp.content_type)

    def test_should_404_on_delete_when_consumer_not_found_later(self):
        self.consumer_repo.delete_entity_by_id.side_effect = excep.NotFound()
        resp = self.app.delete_json('/secrets/{0}/consumers/'.format(
            self.secret.id
        ), self.consumer_ref, expect_errors=True)
        self.consumer_repo.delete_entity_by_id.side_effect = None
        self.assertEqual(404, resp.status_int)
        # Error response should have json content type
        self.assertEqual("application/json", resp.content_type)

    def test_should_delete_consumers_on_secret_delete(self):
        consumers = [self.consumer, self.consumer2]
        ret_val = (consumers, 0, 0, 1)
        self.consumer_repo.get_by_secret_id.return_value = ret_val

        resp = self.app.delete(
            '/secrets/{0}/'.format(self.secret.id)
        )
        self.assertEqual(204, resp.status_int)

        # Verify consumers were deleted
        calls = []
        for consumer in consumers:
            calls.append(mock.call(consumer.id, self.external_project_id))
        self.consumer_repo.delete_entity_by_id.assert_has_calls(
            calls, any_order=True
        )

    def test_should_pass_on_secret_delete_with_missing_consumers(self):
        consumers = [self.consumer, self.consumer2]
        ret_val = (consumers, 0, 0, 1)
        self.consumer_repo.get_by_secret_id.return_value = ret_val
        self.consumer_repo.delete_entity_by_id.side_effect = excep.NotFound

        resp = self.app.delete(
            '/secrets/{0}/'.format(self.secret.id)
        )
        self.assertEqual(204, resp.status_int)

        # Verify consumers were deleted
        calls = []
        for consumer in consumers:
            calls.append(mock.call(consumer.id, self.external_project_id))
        self.consumer_repo.delete_entity_by_id.assert_has_calls(
            calls, any_order=True
        )


class WhenPerformingUnallowedOperationsOnSecretConsumers(FunctionalTest):
    def setUp(self):
        super(
            WhenPerformingUnallowedOperationsOnSecretConsumers, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController()

        return RootController()

    def _init(self):
        self.external_project_id = 'keystoneid1234'
        self.project_internal_id = 'projectid1234'

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_internal_id
        self.project.external_id = self.external_project_id

        # Set up mocked secret
        self.secret = models.Secret()
        self.secret.id = utils.generate_test_valid_uuid()
        self.secret.project_id = self.project_internal_id

        # Set up mocked secret consumers
        self.consumer = create_secret_consumer(
            self.secret.id, self.project_internal_id,
            id_ref=utils.generate_test_valid_uuid())
        self.consumer_ref = {
            "service": self.consumer.service,
            "resource_type": self.consumer.resource_type,
            "resource_id": self.consumer.resource_type,
        }

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        # Set up secret repo
        self.secret_repo = mock.MagicMock()
        self.secret_repo.get_secret_by_id.return_value = self.secret
        self.setup_secret_repository_mock(self.secret_repo)

        # Set up secret consumer repo
        self.consumer_repo = mock.MagicMock()
        self.consumer_repo.get_by_values.return_value = self.consumer
        self.consumer_repo.delete_entity_by_id.return_value = None
        self.setup_secret_consumer_repository_mock(self.consumer_repo)

    def test_should_not_allow_put_on_consumers(self):
        ret_val = ([self.consumer], 0, 0, 1)
        self.consumer_repo.get_by_secret_id.return_value = ret_val

        resp = self.app.put_json(
            '/secrets/{0}/consumers/'.format(self.secret.id),
            self.consumer_ref,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_post_on_consumer_by_id(self):
        self.consumer_repo.get.return_value = self.consumer
        resp = self.app.post_json(
            '/secrets/{0}/consumers/{1}/'.format(self.secret.id,
                                                 self.consumer.id),
            self.consumer_ref,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_put_on_consumer_by_id(self):
        self.consumer_repo.get.return_value = self.consumer
        resp = self.app.put_json(
            '/secrets/{0}/consumers/{1}/'.format(self.secret.id,
                                                 self.consumer.id),
            self.consumer_ref,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_delete_on_consumer_by_id(self):
        self.consumer_repo.get.return_value = self.consumer
        resp = self.app.delete(
            '/secrets/{0}/consumers/{1}/'.format(self.secret.id,
                                                 self.consumer.id),
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)


class WhenOwnershipMismatchForSecretConsumer(FunctionalTest):

    def setUp(self):
        super(
            WhenOwnershipMismatchForSecretConsumer, self
        ).setUp()
        self.app = webtest.TestApp(app.build_wsgi_app(self.root))
        self.app.extra_environ = get_barbican_env(self.external_project_id)

    @property
    def root(self):
        self._init()

        class RootController(object):
            secrets = controllers.secrets.SecretsController()
        return RootController()

    def _init(self):
        self.external_project_id = 'keystoneid1234'
        self.project_internal_id = 'projectid1234'

        # Set up mocked project
        self.project = models.Project()
        self.project.id = self.project_internal_id
        self.project.external_id = self.external_project_id

        # Set up mocked secret
        self.secret = models.Secret()
        self.secret.id = utils.generate_test_valid_uuid()
        self.secret.project = models.Project()
        self.secret.project.external_id = "differentProjectId"

        # Set up mocked consumer
        self.consumer = create_secret_consumer(self.secret.id,
                                               self.project_internal_id,
                                               id_ref='consumerid1234')

        self.consumer_ref = {
            "service": self.consumer.service,
            "resource_type": self.consumer.resource_type,
            "resource_id": self.consumer.resource_type,
        }

        # Set up mocked project repo
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project
        self.setup_project_repository_mock(self.project_repo)

        # Set up mocked secret repo
        self.secret_repo = mock.MagicMock()
        self.secret_repo.get.return_value = self.secret
        self.secret_repo.get_secret_by_id.return_value = self.secret
        self.setup_secret_repository_mock(self.secret_repo)

        # Set up mocked secret consumer repo
        self.consumer_repo = mock.MagicMock()
        self.consumer_repo.get_by_values.return_value = self.consumer
        self.consumer_repo.delete_entity_by_id.return_value = None
        self.setup_secret_consumer_repository_mock(self.consumer_repo)

    def test_consumer_check_ownership_mismatch(self):
        resp = self.app.delete_json(
            '/secrets/{0}/consumers/'.format(self.secret.id),
            self.consumer_ref, expect_errors=True)
        self.assertEqual(403, resp.status_int)
