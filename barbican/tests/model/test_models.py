# Copyright (c) 2013 Rackspace, Inc.
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

import unittest

from barbican.model.models import Secret


class WhenCreatingNewSecret(unittest.TestCase):
    def setUp(self):
        self.parsed_body = {'name': 'name',
                            'mime_type': 'text/plain',
                            'algorithm': 'algorithm',
                            'bit_length': 512,
                            'cypher_type': 'cypher_type',
                            'plain_text': 'not-encrypted'}

    def test_new_secret_is_created_from_dict(self):
        secret = Secret(self.parsed_body)
        self.assertEqual(secret.name, self.parsed_body['name'])
        self.assertEqual(secret.mime_type, self.parsed_body['mime_type'])
        self.assertEqual(secret.algorithm, self.parsed_body['algorithm'])
        self.assertEqual(secret.bit_length, self.parsed_body['bit_length'])
        self.assertEqual(secret.cypher_type, self.parsed_body['cypher_type'])
