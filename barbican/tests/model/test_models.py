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

import datetime

from barbican.model import models
from barbican.openstack.common import jsonutils as json
from barbican.tests import utils


class WhenCreatingNewSecret(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewSecret, self).setUp()
        self.parsed_secret = {'name': 'name',
                              'algorithm': 'algorithm',
                              'bit_length': 512,
                              'mode': 'mode',
                              'plain_text': 'not-encrypted'}

        self.parsed_order = {'secret': self.parsed_secret}

    def test_new_secret_is_created_from_dict(self):
        date_time = datetime.datetime.now().isoformat()
        self.parsed_secret['expiration'] = date_time
        secret = models.Secret(self.parsed_secret)
        self.assertEqual(secret.name, self.parsed_secret['name'])
        self.assertEqual(secret.algorithm, self.parsed_secret['algorithm'])
        self.assertEqual(secret.bit_length, self.parsed_secret['bit_length'])
        self.assertEqual(secret.mode, self.parsed_secret['mode'])
        self.assertIsInstance(secret.expiration, datetime.datetime)
        self.assertEqual(secret.created_at, secret.updated_at)


class WhenCreatingNewOrder(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewOrder, self).setUp()
        self.parsed_order = {
            'type': 'certificate',
            'meta': {
                'email': 'email@email.com'
            },
            'sub_status': 'Pending',
            'sub_status_message': 'Waiting for instructions...'
        }

    def test_new_order_is_created(self):
        order = models.Order(self.parsed_order)

        self.assertEqual(order.type, self.parsed_order['type'])
        self.assertEqual(order.meta, self.parsed_order['meta'])
        self.assertEqual(order.sub_status, self.parsed_order['sub_status'])
        self.assertEqual(
            order.sub_status_message,
            self.parsed_order['sub_status_message']
        )


class WhenCreatingNewContainer(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewContainer, self).setUp()
        self.parsed_container = {'name': 'name',
                                 'type': 'generic',
                                 'secret_refs': [
                                     {'name': 'test secret 1',
                                      'secret_ref': '123'},
                                     {'name': 'test secret 2',
                                      'secret_ref': '123'},
                                     {'name': 'test secret 3',
                                      'secret_ref': '123'}
                                 ]}

    def test_new_container_is_created_from_dict(self):
        container = models.Container(self.parsed_container)
        self.assertEqual(container.name, self.parsed_container['name'])
        self.assertEqual(container.type, self.parsed_container['type'])
        self.assertEqual(len(container.container_secrets),
                         len(self.parsed_container['secret_refs']))

        self.assertEqual(container.container_secrets[0].name,
                         self.parsed_container['secret_refs'][0]['name'])
        self.assertEqual(container.container_secrets[0].secret_id,
                         self.parsed_container['secret_refs'][0]['secret_ref'])

        self.assertEqual(container.container_secrets[1].name,
                         self.parsed_container['secret_refs'][1]['name'])
        self.assertEqual(container.container_secrets[1].secret_id,
                         self.parsed_container['secret_refs'][1]['secret_ref'])

        self.assertEqual(container.container_secrets[2].name,
                         self.parsed_container['secret_refs'][2]['name'])
        self.assertEqual(container.container_secrets[2].secret_id,
                         self.parsed_container['secret_refs'][2]['secret_ref'])

    def test_new_certificate_container_is_created_from_dict(self):
        self.parsed_container['type'] = 'certificate'
        container = models.Container(self.parsed_container)
        self.assertEqual(container.name, self.parsed_container['name'])
        self.assertEqual(container.type, self.parsed_container['type'])
        self.assertEqual(len(container.container_secrets),
                         len(self.parsed_container['secret_refs']))

        self.assertEqual(container.container_secrets[0].name,
                         self.parsed_container['secret_refs'][0]['name'])
        self.assertEqual(container.container_secrets[0].secret_id,
                         self.parsed_container['secret_refs'][0]['secret_ref'])

        self.assertEqual(container.container_secrets[1].name,
                         self.parsed_container['secret_refs'][1]['name'])
        self.assertEqual(container.container_secrets[1].secret_id,
                         self.parsed_container['secret_refs'][1]['secret_ref'])

        self.assertEqual(container.container_secrets[2].name,
                         self.parsed_container['secret_refs'][2]['name'])
        self.assertEqual(container.container_secrets[2].secret_id,
                         self.parsed_container['secret_refs'][2]['secret_ref'])

    def test_parse_secret_ref_uri(self):
        self.parsed_container['secret_refs'][0]['secret_ref'] = (
            'http://localhost:9110/123/secrets/123456')
        container = models.Container(self.parsed_container)
        self.assertEqual(container.container_secrets[0].secret_id, '123456')

        self.parsed_container['secret_refs'][0]['secret_ref'] = (
            'http://localhost:9110/123/secrets/123456/')
        container = models.Container(self.parsed_container)
        self.assertEqual(container.container_secrets[0].secret_id, '123456')


class WhenCreatingNewConsumer(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewConsumer, self).setUp()
        self.parsed_consumer = {'name': 'name',
                                'URL': 'URL'}
        self.container_id = '12345container'

    def test_new_consumer_is_created_from_dict(self):
        consumer = models.ContainerConsumerMetadatum(self.container_id,
                                                     self.parsed_consumer)
        self.assertEqual(consumer.name, self.parsed_consumer['name'])
        self.assertEqual(consumer.URL, self.parsed_consumer['URL'])
        self.assertEqual(consumer.status, models.States.ACTIVE)

    def test_new_consumer_has_correct_hash(self):
        consumer_one = models.ContainerConsumerMetadatum(self.container_id,
                                                         self.parsed_consumer)
        consumer_two = models.ContainerConsumerMetadatum(self.container_id,
                                                         self.parsed_consumer)
        different_container = '67890container'
        consumer_three = models.ContainerConsumerMetadatum(
            different_container, self.parsed_consumer)
        self.assertEqual(consumer_one.data_hash, consumer_two.data_hash)
        self.assertNotEqual(consumer_one.data_hash, consumer_three.data_hash)


class WhenProcessingJsonBlob(utils.BaseTestCase):
    def setUp(self):
        super(WhenProcessingJsonBlob, self).setUp()
        self.json_blob = models.JsonBlob()

    def test_process_bind_param_w_dict(self):
        res = self.json_blob.process_bind_param({'test': True}, None)
        self.assertEqual(res, '{"test": true}')

    def test_process_result_value_w_json_str(self):
        res = self.json_blob.process_result_value('{"test": true}', None)
        self.assertTrue(res.get('test'))


class WhenCreatingOrderRetryTask(utils.BaseTestCase):

    def test_create_new_order_task(self):
        order = models.Order({
            'type': 'certificate',
            'meta': {
                'email': 'email@email.com'
            },
            'sub_status': 'Pending',
            'sub_status_message': 'Waiting for instructions...'
        })
        at = datetime.datetime.utcnow()
        order_retry_task = models.OrderRetryTask(
            order_id=order.id,
            retry_task="foobar",
            retry_at=at,
            retry_args=json.dumps(["one", "two"]),
            retry_kwargs=json.dumps({"three": "four"}),
        )

        self.assertEqual(order_retry_task.order_id, order.id)
        self.assertEqual(order_retry_task.retry_task, "foobar")
        self.assertEqual(order_retry_task.retry_at, at)
        self.assertEqual(
            order_retry_task.retry_args,
            json.dumps(["one", "two"]),
        )
        self.assertEqual(
            order_retry_task.retry_kwargs,
            json.dumps({"three": "four"}),
        )

    def test_get_retry_params(self):
        order_retry_task = models.OrderRetryTask(
            retry_args=json.dumps(["one", "two"]),
            retry_kwargs=json.dumps({"three": "four"}),
        )

        self.assertEqual(
            order_retry_task.get_retry_params(),
            (["one", "two"], {"three": "four"}),
        )


class WhenCreatingNewCertificateAuthority(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewCertificateAuthority, self).setUp()
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=10))
        self.parsed_ca = {'plugin_name': 'dogtag_plugin',
                          'plugin_ca_id': 'ca_master',
                          'expiration': expiration.isoformat(),
                          'name': 'Dogtag CA',
                          'description': 'Master CA for Dogtag plugin',
                          'ca_signing_certificate': 'XXXXX',
                          'intermediates': 'YYYYY'}

    def test_new_ca_is_created_from_dict(self):
        ca = models.CertificateAuthority(self.parsed_ca)
        self.assertEqual(self.parsed_ca['plugin_name'], ca.plugin_name)
        self.assertEqual(self.parsed_ca['plugin_ca_id'], ca.plugin_ca_id)
        self.assertEqual(self.parsed_ca['name'], ca.ca_meta['name'].value)
        self.assertEqual(self.parsed_ca['description'],
                         ca.ca_meta['description'].value)
        self.assertEqual(self.parsed_ca['ca_signing_certificate'],
                         ca.ca_meta['ca_signing_certificate'].value)
        self.assertEqual(self.parsed_ca['intermediates'],
                         ca.ca_meta['intermediates'].value)
        self.assertIsInstance(ca.expiration, datetime.datetime)
        self.assertEqual(ca.created_at, ca.updated_at)


class WhenCreatingNewProjectCertificateAuthority(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewProjectCertificateAuthority, self).setUp()
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=10))
        self.parsed_ca = {'plugin_name': 'dogtag_plugin',
                          'plugin_ca_id': 'ca_master',
                          'expiration': expiration.isoformat(),
                          'name': 'Dogtag CA',
                          'description': 'Master CA for Dogtag plugin',
                          'ca_signing_certificate': 'XXXXX',
                          'intermediates': 'YYYYY'}

    def test_create_new_project_ca(self):
        ca = models.CertificateAuthority(self.parsed_ca)
        ca.id = '67890'
        project = models.Project()
        project.id = '12345'
        project_ca = models.ProjectCertificateAuthority(project.id, ca.id)

        self.assertEqual(ca.id, project_ca.ca_id)
        self.assertEqual(project.id, project_ca.project_id)


class WhenCreatingNewPreferredCertificateAuthority(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewPreferredCertificateAuthority, self).setUp()
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=10))
        self.parsed_ca = {'plugin_name': 'dogtag_plugin',
                          'plugin_ca_id': 'ca_master',
                          'expiration': expiration.isoformat(),
                          'name': 'Dogtag CA',
                          'description': 'Master CA for Dogtag plugin',
                          'ca_signing_certificate': 'XXXXX',
                          'intermediates': 'YYYYY'}

    def test_create_new_preferred_ca(self):
        ca = models.CertificateAuthority(self.parsed_ca)
        ca.id = '67890'
        project = models.Project()
        project.id = '12345'
        preferred_ca = models.PreferredCertificateAuthority(project.id, ca.id)

        self.assertEqual(ca.id, preferred_ca.ca_id)
        self.assertEqual(project.id, preferred_ca.project_id)
