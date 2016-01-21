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
import unittest

from barbican.common import exception
from barbican.model import models
from barbican.plugin.interface import secret_store
from barbican.tests import utils


class WhenCreatingNewSecret(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewSecret, self).setUp()
        self.parsed_secret = {'name': 'name',
                              'secret_type': secret_store.SecretType.OPAQUE,
                              'algorithm': 'algorithm',
                              'bit_length': 512,
                              'mode': 'mode',
                              'plain_text': 'not-encrypted',
                              'creator_id': 'creator12345'}

        self.parsed_order = {'secret': self.parsed_secret}

    def test_new_secret_is_created_from_dict(self):
        date_time = datetime.datetime.now().isoformat()
        self.parsed_secret['expiration'] = date_time
        secret = models.Secret(self.parsed_secret)
        self.assertEqual(self.parsed_secret['name'], secret.name)
        self.assertEqual(self.parsed_secret['secret_type'], secret.secret_type)
        self.assertEqual(self.parsed_secret['algorithm'], secret.algorithm)
        self.assertEqual(self.parsed_secret['bit_length'], secret.bit_length)
        self.assertEqual(self.parsed_secret['mode'], secret.mode)
        self.assertIsInstance(secret.expiration, datetime.datetime)
        self.assertEqual(self.parsed_secret['creator_id'], secret.creator_id)
        self.assertEqual(secret.created_at, secret.updated_at)

        fields = secret.to_dict_fields()
        self.assertEqual(self.parsed_secret['secret_type'],
                         fields['secret_type'])
        self.assertEqual(self.parsed_secret['algorithm'], fields['algorithm'])
        self.assertEqual(self.parsed_secret['creator_id'],
                         fields['creator_id'])

    def test_new_secret_is_created_with_default_secret_type(self):
        secret_spec = dict(self.parsed_secret)
        date_time = datetime.datetime.now().isoformat()
        secret_spec['expiration'] = date_time
        del secret_spec['secret_type']
        secret = models.Secret(secret_spec)
        self.assertEqual(self.parsed_secret['secret_type'], secret.secret_type)


class WhenCreatingNewSecretMetadata(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewSecretMetadata, self).setUp()
        self.key = 'dog'
        self.value = 'poodle'

        self.metadata = {
            'key': self.key,
            'value': self.value
        }

    def test_new_secret_metadata_is_created_from_dict(self):
        secret_meta = models.SecretUserMetadatum(self.key, self.value)

        self.assertEqual(self.key, secret_meta.key)
        self.assertEqual(self.value, secret_meta.value)

        fields = secret_meta.to_dict_fields()
        self.assertEqual(self.metadata['key'],
                         fields['key'])
        self.assertEqual(self.metadata['value'],
                         fields['value'])

    def test_should_raise_exception_metadata_with_no_key(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.SecretUserMetadatum,
                          None,
                          self.value)

    def test_should_raise_exception_metadata_with_no_value(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.SecretUserMetadatum,
                          self.key,
                          None)


class WhenCreatingNewOrder(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewOrder, self).setUp()
        self.parsed_order = {
            'type': 'certificate',
            'meta': {
                'email': 'email@email.com'
            },
            'sub_status': 'Pending',
            'sub_status_message': 'Waiting for instructions...',
            'creator_id': 'creator12345'
        }

    def test_new_order_is_created(self):
        order = models.Order(self.parsed_order)

        self.assertEqual(self.parsed_order['type'], order.type)
        self.assertEqual(self.parsed_order['meta'], order.meta)
        self.assertEqual(self.parsed_order['sub_status'], order.sub_status)
        self.assertEqual(self.parsed_order['creator_id'], order.creator_id)
        self.assertEqual(
            self.parsed_order['sub_status_message'],
            order.sub_status_message
        )
        fields = order.to_dict_fields()
        self.assertEqual(self.parsed_order['sub_status'], fields['sub_status'])
        self.assertEqual(self.parsed_order['type'], fields['type'])
        self.assertEqual(self.parsed_order['creator_id'],
                         fields['creator_id'])


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
                                 ],
                                 'creator_id': 'creator123456'}

    def test_new_container_is_created_from_dict(self):
        container = models.Container(self.parsed_container)
        self.assertEqual(self.parsed_container['name'], container.name)
        self.assertEqual(self.parsed_container['type'], container.type)
        self.assertEqual(self.parsed_container['creator_id'],
                         container.creator_id)
        self.assertEqual(len(self.parsed_container['secret_refs']),
                         len(container.container_secrets))

        self.assertEqual(self.parsed_container['secret_refs'][0]['name'],
                         container.container_secrets[0].name)
        self.assertEqual(self.parsed_container['secret_refs'][0]['secret_ref'],
                         container.container_secrets[0].secret_id)

        self.assertEqual(self.parsed_container['secret_refs'][1]['name'],
                         container.container_secrets[1].name)
        self.assertEqual(self.parsed_container['secret_refs'][1]['secret_ref'],
                         container.container_secrets[1].secret_id)

        self.assertEqual(self.parsed_container['secret_refs'][2]['name'],
                         container.container_secrets[2].name)
        self.assertEqual(self.parsed_container['secret_refs'][2]['secret_ref'],
                         container.container_secrets[2].secret_id)
        fields = container.to_dict_fields()
        self.assertEqual(self.parsed_container['name'], fields['name'])
        self.assertEqual(self.parsed_container['type'], fields['type'])
        self.assertEqual(self.parsed_container['creator_id'],
                         fields['creator_id'])

    def test_new_certificate_container_is_created_from_dict(self):
        self.parsed_container['type'] = 'certificate'
        container = models.Container(self.parsed_container)
        self.assertEqual(self.parsed_container['name'], container.name)
        self.assertEqual(self.parsed_container['type'], container.type)
        self.assertEqual(self.parsed_container['creator_id'],
                         container.creator_id)
        self.assertEqual(len(self.parsed_container['secret_refs']),
                         len(container.container_secrets))

        self.assertEqual(self.parsed_container['secret_refs'][0]['name'],
                         container.container_secrets[0].name)
        self.assertEqual(self.parsed_container['secret_refs'][0]['secret_ref'],
                         container.container_secrets[0].secret_id)

        self.assertEqual(self.parsed_container['secret_refs'][1]['name'],
                         container.container_secrets[1].name,)
        self.assertEqual(self.parsed_container['secret_refs'][1]['secret_ref'],
                         container.container_secrets[1].secret_id)

        self.assertEqual(self.parsed_container['secret_refs'][2]['name'],
                         container.container_secrets[2].name)
        self.assertEqual(self.parsed_container['secret_refs'][2]['secret_ref'],
                         container.container_secrets[2].secret_id)

    def test_parse_secret_ref_uri(self):
        self.parsed_container['secret_refs'][0]['secret_ref'] = (
            'http://localhost:9110/123/secrets/123456')
        container = models.Container(self.parsed_container)
        self.assertEqual('123456', container.container_secrets[0].secret_id)

        self.parsed_container['secret_refs'][0]['secret_ref'] = (
            'http://localhost:9110/123/secrets/123456/')
        container = models.Container(self.parsed_container)
        self.assertEqual('123456', container.container_secrets[0].secret_id)


class WhenCreatingNewConsumer(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewConsumer, self).setUp()
        self.parsed_consumer = {'name': 'name',
                                'URL': 'URL'}
        self.project_id = '12345project'
        self.container_id = '12345container'

    def test_new_consumer_is_created_from_dict(self):
        consumer = models.ContainerConsumerMetadatum(self.container_id,
                                                     self.project_id,
                                                     self.parsed_consumer)
        self.assertEqual(self.parsed_consumer['name'], consumer.name)
        self.assertEqual(self.parsed_consumer['URL'], consumer.URL)
        self.assertEqual(models.States.ACTIVE, consumer.status)

    def test_new_consumer_has_correct_hash(self):
        consumer_one = models.ContainerConsumerMetadatum(self.container_id,
                                                         self.project_id,
                                                         self.parsed_consumer)
        consumer_two = models.ContainerConsumerMetadatum(self.container_id,
                                                         self.project_id,
                                                         self.parsed_consumer)
        different_container = '67890container'
        consumer_three = models.ContainerConsumerMetadatum(
            different_container, self.project_id, self.parsed_consumer)
        self.assertEqual(consumer_one.data_hash, consumer_two.data_hash)
        self.assertNotEqual(consumer_one.data_hash, consumer_three.data_hash)


class WhenProcessingJsonBlob(utils.BaseTestCase):
    def setUp(self):
        super(WhenProcessingJsonBlob, self).setUp()
        self.json_blob = models.JsonBlob()

    def test_process_bind_param_w_dict(self):
        res = self.json_blob.process_bind_param({'test': True}, None)
        self.assertEqual('{"test": true}', res)

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
        order_retry_task = models.OrderRetryTask()
        order_retry_task.order_id = order.id
        order_retry_task.retry_task = "foobar"
        order_retry_task.retry_at = at
        order_retry_task.retry_args = ["one", "two"]
        order_retry_task.retry_kwargs = {"three": "four"}

        self.assertEqual(order.id, order_retry_task.order_id)
        self.assertEqual("foobar", order_retry_task.retry_task)
        self.assertEqual(at, order_retry_task.retry_at)
        self.assertEqual(
            ["one", "two"],
            order_retry_task.retry_args,
        )
        self.assertEqual(
            {"three": "four"},
            order_retry_task.retry_kwargs,
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
                          'intermediates': 'YYYYY',
                          'creator_id': 'user12345',
                          'parent_ca_id': '12330-223-22',
                          'project_id': '12345'}

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
        self.assertEqual(self.parsed_ca['creator_id'], ca.creator_id)
        self.assertEqual(self.parsed_ca['project_id'], ca.project_id)


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


class WhenCreatingNewSecretACL(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewSecretACL, self).setUp()
        self.secret_id = 'secret123456'
        self.user_ids = ['user12345', 'user67890']
        self.operation = 'read'
        self.project_access = True

    def test_new_secretacl_for_given_all_input(self):
        acl = models.SecretACL(self.secret_id, self.operation,
                               self.project_access, self.user_ids)
        self.assertEqual(self.secret_id, acl.secret_id)
        self.assertEqual(self.operation, acl.operation)
        self.assertEqual(self.project_access, acl.project_access)
        self.assertTrue(all(acl_user.user_id in self.user_ids for acl_user
                            in acl.acl_users))

    def test_new_secretacl_check_to_dict_fields(self):
        acl = models.SecretACL(self.secret_id, self.operation,
                               self.project_access, self.user_ids)
        self.assertEqual(self.secret_id, acl.to_dict_fields()['secret_id'])
        self.assertEqual(self.operation, acl.to_dict_fields()['operation'])
        self.assertEqual(self.project_access,
                         acl.to_dict_fields()['project_access'])
        self.assertTrue(all(user_id in self.user_ids for user_id in
                            acl.to_dict_fields()['users']))
        self.assertIsNone(acl.to_dict_fields()['acl_id'])

    def test_new_secretacl_for_bare_minimum_input(self):
        acl = models.SecretACL(self.secret_id, self.operation,
                               None, None)
        self.assertEqual(self.secret_id, acl.secret_id)
        self.assertEqual(0, len(acl.acl_users))
        self.assertEqual(self.operation, acl.operation)
        self.assertIsNone(acl.project_access)

    def test_new_secretacl_with_duplicate_userids_input(self):
        user_ids = list(self.user_ids)
        user_ids = user_ids * 2  # duplicate ids
        acl = models.SecretACL(self.secret_id, self.operation,
                               None, user_ids=user_ids)
        self.assertEqual(self.secret_id, acl.secret_id)
        self.assertEqual(self.operation, acl.operation)
        self.assertIsNone(acl.project_access)
        self.assertEqual(2, len(acl.acl_users))

    def test_should_throw_exception_missing_secret_id(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.SecretACL, None, 'read',
                          ['user246'], None)

    def test_should_throw_exception_missing_operation(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.SecretACL, self.secret_id, None,
                          None, ['user246'])

    def test_new_secretacl_expect_user_ids_as_list(self):
        acl = models.SecretACL(self.secret_id, self.operation,
                               None, {'aUser': '12345'})
        self.assertEqual(0, len(acl.acl_users))


class WhenCreatingNewContainerACL(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewContainerACL, self).setUp()
        self.container_id = 'container123456'
        self.user_ids = ['user12345', 'user67890']
        self.operation = 'read'
        self.project_access = True

    def test_new_containeracl_for_given_all_input(self):
        acl = models.ContainerACL(self.container_id, self.operation,
                                  self.project_access, self.user_ids)
        self.assertEqual(self.container_id, acl.container_id)
        self.assertEqual(self.operation, acl.operation)
        self.assertEqual(self.project_access, acl.project_access)
        self.assertTrue(all(acl_user.user_id in self.user_ids for acl_user
                            in acl.acl_users))

    def test_new_containeracl_check_to_dict_fields(self):
        acl = models.ContainerACL(self.container_id, self.operation,
                                  self.project_access, self.user_ids)
        self.assertEqual(self.container_id,
                         acl.to_dict_fields()['container_id'])
        self.assertEqual(self.operation, acl.to_dict_fields()['operation'])
        self.assertEqual(self.project_access,
                         acl.to_dict_fields()['project_access'])
        self.assertTrue(all(user_id in self.user_ids for user_id
                            in acl.to_dict_fields()['users']))
        self.assertIsNone(acl.to_dict_fields()['acl_id'])

    def test_new_containeracl_for_bare_minimum_input(self):
        acl = models.ContainerACL(self.container_id, self.operation,
                                  None, None)
        self.assertEqual(self.container_id, acl.container_id)
        self.assertEqual(0, len(acl.acl_users))
        self.assertEqual(self.operation, acl.operation)
        self.assertIsNone(acl.project_access)

    def test_new_containeracl_with_duplicate_userids_input(self):
        user_ids = list(self.user_ids)
        user_ids = user_ids * 2  # duplicate ids
        acl = models.ContainerACL(self.container_id, self.operation,
                                  True, user_ids=user_ids)
        self.assertEqual(self.container_id, acl.container_id)
        self.assertEqual(self.operation, acl.operation)
        self.assertTrue(acl.project_access)
        self.assertEqual(2, len(acl.acl_users))

    def test_should_throw_exception_missing_container_id(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.ContainerACL, None, 'read',
                          None, ['user246'])

    def test_should_throw_exception_missing_operation(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.ContainerACL, self.container_id, None,
                          None, ['user246'])

    def test_new_containeracl_expect_user_ids_as_list(self):
        acl = models.ContainerACL(self.container_id, self.operation,
                                  None, {'aUser': '12345'})
        self.assertEqual(0, len(acl.acl_users))


class WhenCreatingNewSecretACLUser(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewSecretACLUser, self).setUp()
        self.secret_acl_id = 'secret_acl_123456'
        self.user_ids = ['user12345', 'user67890']

    def test_new_secretacl_user_for_given_all_input(self):
        acl_user = models.SecretACLUser(self.secret_acl_id, self.user_ids[0])

        self.assertEqual(self.secret_acl_id, acl_user.acl_id)
        self.assertEqual(self.user_ids[0], acl_user.user_id)
        self.assertEqual(models.States.ACTIVE, acl_user.status)

    def test_new_secretacl_user_check_to_dict_fields(self):
        acl_user = models.SecretACLUser(self.secret_acl_id, self.user_ids[1])

        self.assertEqual(self.secret_acl_id,
                         acl_user.to_dict_fields()['acl_id'])
        self.assertEqual(self.user_ids[1],
                         acl_user.to_dict_fields()['user_id'])
        self.assertEqual(models.States.ACTIVE,
                         acl_user.to_dict_fields()['status'])

    def test_should_throw_exception_missing_user_id(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.SecretACLUser, self.secret_acl_id,
                          None)


class WhenCreatingNewContainerACLUser(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewContainerACLUser, self).setUp()
        self.container_acl_id = 'container_acl_123456'
        self.user_ids = ['user12345', 'user67890']

    def test_new_secretacl_user_for_given_all_input(self):
        acl_user = models.ContainerACLUser(self.container_acl_id,
                                           self.user_ids[0])

        self.assertEqual(self.container_acl_id, acl_user.acl_id)
        self.assertEqual(self.user_ids[0], acl_user.user_id)
        self.assertEqual(models.States.ACTIVE, acl_user.status)

    def test_new_secretacl_user_check_to_dict_fields(self):
        acl_user = models.ContainerACLUser(self.container_acl_id,
                                           self.user_ids[1])

        self.assertEqual(self.container_acl_id,
                         acl_user.to_dict_fields()['acl_id'])
        self.assertEqual(self.user_ids[1],
                         acl_user.to_dict_fields()['user_id'])
        self.assertEqual(models.States.ACTIVE,
                         acl_user.to_dict_fields()['status'])

    def test_should_throw_exception_missing_user_id(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.ContainerACLUser, self.container_acl_id,
                          None)


class WhenCreatingNewProjectQuotas(utils.BaseTestCase):
    def setUp(self):
        super(WhenCreatingNewProjectQuotas, self).setUp()

    def test_create_new_project_quotas(self):
        project = models.Project()
        project.id = '12345'
        project.external_id = '67890'
        parsed_project_quotas = {
            'secrets': 101,
            'orders': 102,
            'containers': 103,
            'consumers': 105,
            'cas': 106}
        project_quotas = models.ProjectQuotas(project.id,
                                              parsed_project_quotas)

        self.assertEqual('12345', project_quotas.project_id)
        self.assertEqual(101, project_quotas.secrets)
        self.assertEqual(102, project_quotas.orders)
        self.assertEqual(103, project_quotas.containers)
        self.assertEqual(105, project_quotas.consumers)
        self.assertEqual(106, project_quotas.cas)

    def test_create_new_project_quotas_with_all_default_quotas(self):
        project = models.Project()
        project.id = '12345'
        project.external_id = '67890'
        project_quotas = models.ProjectQuotas(project.id,
                                              None)

        self.assertEqual('12345', project_quotas.project_id)
        self.assertIsNone(project_quotas.secrets)
        self.assertIsNone(project_quotas.orders)
        self.assertIsNone(project_quotas.containers)
        self.assertIsNone(project_quotas.consumers)
        self.assertIsNone(project_quotas.cas)

    def test_create_new_project_quotas_with_some_default_quotas(self):
        project = models.Project()
        project.id = '12345'
        project.external_id = '67890'
        parsed_project_quotas = {
            'secrets': 101,
            'containers': 103,
            'consumers': 105}
        project_quotas = models.ProjectQuotas(project.id,
                                              parsed_project_quotas)

        self.assertEqual('12345', project_quotas.project_id)
        self.assertEqual(101, project_quotas.secrets)
        self.assertIsNone(project_quotas.orders)
        self.assertEqual(103, project_quotas.containers)
        self.assertEqual(105, project_quotas.consumers)
        self.assertIsNone(project_quotas.cas)

    def test_should_throw_exception_missing_project_id(self):
        self.assertRaises(exception.MissingArgumentError,
                          models.ProjectQuotas, None, None)

    def test_project_quotas_check_to_dict_fields(self):
        project = models.Project()
        project.id = '12345'
        project.external_id = '67890'
        parsed_project_quotas = {
            'secrets': 101,
            'orders': 102,
            'containers': 103,
            'consumers': 105,
            'cas': 106}
        project_quotas = models.ProjectQuotas(project.id,
                                              parsed_project_quotas)
        self.assertEqual(project.id,
                         project_quotas.to_dict_fields()['project_id'])
        self.assertEqual(101,
                         project_quotas.to_dict_fields()['secrets'])
        self.assertEqual(102,
                         project_quotas.to_dict_fields()['orders'])
        self.assertEqual(103,
                         project_quotas.to_dict_fields()['containers'])
        self.assertEqual(105,
                         project_quotas.to_dict_fields()['consumers'])
        self.assertEqual(106,
                         project_quotas.to_dict_fields()['cas'])

if __name__ == '__main__':
    unittest.main()
