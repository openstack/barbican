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

import testtools

from barbican.model import models


class WhenCreatingNewSecret(testtools.TestCase):
    def setUp(self):
        super(WhenCreatingNewSecret, self).setUp()
        self.parsed_secret = {'name': 'name',
                              'algorithm': 'algorithm',
                              'bit_length': 512,
                              'mode': 'mode',
                              'plain_text': 'not-encrypted'}

        self.parsed_order = {'secret': self.parsed_secret}

    def test_new_secret_is_created_from_dict(self):
        secret = models.Secret(self.parsed_secret)
        self.assertEqual(secret.name, self.parsed_secret['name'])
        self.assertEqual(secret.algorithm, self.parsed_secret['algorithm'])
        self.assertEqual(secret.bit_length, self.parsed_secret['bit_length'])
        self.assertEqual(secret.mode, self.parsed_secret['mode'])


class WhenCreatingNewContainer(testtools.TestCase):
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

    def test_parse_secret_ref_uri(self):
        self.parsed_container['secret_refs'][0]['secret_ref'] =\
            'http://localhost:9110/123/secrets/123456'
        container = models.Container(self.parsed_container)
        self.assertEqual(container.container_secrets[0].secret_id, '123456')

        self.parsed_container['secret_refs'][0]['secret_ref'] =\
            'http://localhost:9110/123/secrets/123456/'
        container = models.Container(self.parsed_container)
        self.assertEqual(container.container_secrets[0].secret_id, '123456')
