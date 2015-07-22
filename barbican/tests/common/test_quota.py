# Copyright (c) 2015 Cisco Systems
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

from barbican.common import quota
from barbican.tests import utils


class WhenTestingQuotaFunctions(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingQuotaFunctions, self).setUp()
        self.quota_driver = quota.QuotaDriver()

    def test_get_defaults(self):
        quotas = self.quota_driver.get_defaults()
        self.assertEqual(500, quotas['secrets'])
        self.assertEqual(100, quotas['orders'])
        self.assertEqual(-1, quotas['containers'])
        self.assertEqual(100, quotas['transport_keys'])
        self.assertEqual(100, quotas['consumers'])

    def test_is_unlimited_true(self):
        self.assertTrue(self.quota_driver._is_unlimited_value(-1))

    def test_is_unlimited_false(self):
        self.assertFalse(self.quota_driver._is_unlimited_value(1))


if __name__ == '__main__':
    unittest.main()
