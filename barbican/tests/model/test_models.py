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

import unittest

from barbican.model import models


class WhenCreatingNewSecret(unittest.TestCase):
    def setUp(self):
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
