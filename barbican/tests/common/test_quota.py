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

from barbican.common import exception as excep
from barbican.common import quota
from barbican.model import models
from barbican.tests import database_utils


class WhenTestingQuotaDriverFunctions(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingQuotaDriverFunctions, self).setUp()
        self.quota_driver = quota.QuotaDriver()

    def test_get_defaults(self):
        quotas = self.quota_driver._get_defaults()
        self.assertEqual(-1, quotas['secrets'])
        self.assertEqual(-1, quotas['orders'])
        self.assertEqual(-1, quotas['containers'])
        self.assertEqual(-1, quotas['consumers'])
        self.assertEqual(-1, quotas['cas'])

    def test_compute_effective_quotas_using_some_defaults(self):
        configured_quotas = {'consumers': None, 'containers': 66,
                             'orders': None, 'secrets': 55,
                             'cas': None}
        quotas = self.quota_driver._compute_effective_quotas(configured_quotas)
        expected_quotas = {'consumers': -1, 'containers': 66,
                           'orders': -1, 'secrets': 55,
                           'cas': -1}
        self.assertEqual(expected_quotas, quotas)

    def test_compute_effective_quotas_using_all_defaults(self):
        configured_quotas = {'consumers': None, 'containers': None,
                             'orders': None, 'secrets': None,
                             'cas': None}
        quotas = self.quota_driver._compute_effective_quotas(configured_quotas)
        expected_quotas = {'consumers': -1, 'containers': -1,
                           'orders': -1, 'secrets': -1,
                           'cas': -1}
        self.assertEqual(expected_quotas, quotas)

    def test_is_unlimited_true(self):
        self.assertTrue(self.quota_driver.is_unlimited_value(-1))

    def test_is_unlimited_false(self):
        self.assertFalse(self.quota_driver.is_unlimited_value(1))

    def test_is_disabled_true(self):
        self.assertTrue(self.quota_driver.is_disabled_value(0))

    def test_is_disabled_false(self):
        self.assertFalse(self.quota_driver.is_disabled_value(1))

    def test_should_get_project_quotas(self):
        self.create_a_test_project_quotas()
        project_quotas = self.quota_driver.get_project_quotas(
            self.get_test_project_id())
        self.assertEqual({'project_quotas':
                          self.get_test_parsed_project_quotas()},
                         project_quotas)

    def test_should_return_not_found_get_project_quotas(self):
        project_quotas = self.quota_driver.get_project_quotas('dummy')
        self.assertIsNone(project_quotas)

    def test_should_get_project_quotas_list(self):
        self.create_a_test_project_quotas()
        project_quotas = self.quota_driver.get_project_quotas_list()
        self.assertEqual({'project_quotas': [{
            'project_id': u'project1',
            'project_quotas': {'consumers': 105,
                               'containers': 103,
                               'orders': 102,
                               'secrets': 101,
                               'cas': 106}}], 'total': 1},
                         project_quotas)

    def test_should_get_empty_project_quotas_list(self):
        project_quotas = self.quota_driver.get_project_quotas_list()
        self.assertEqual({'total': 0, 'project_quotas': []}, project_quotas)

    def test_should_delete_project_quotas(self):
        self.create_a_test_project_quotas()
        self.quota_driver.delete_project_quotas(
            self.get_test_project_id())

    def test_should_raise_not_found_delete_project_quotas(self):
        self.assertRaises(
            excep.NotFound,
            self.quota_driver.delete_project_quotas,
            'dummy')

    def test_get_project_quotas_with_partial_definition(self):
        self.create_a_test_project_quotas('partial')
        project_quotas = self.quota_driver.get_project_quotas(
            self.get_test_project_id('partial'))
        self.assertEqual({'project_quotas':
                          self.get_test_response_project_quotas('partial')},
                         project_quotas)

    def test_get_project_quotas_using_empty_definition(self):
        self.create_a_test_project_quotas('none')
        project_quotas = self.quota_driver.get_project_quotas(
            self.get_test_project_id('none'))
        self.assertEqual({'project_quotas':
                          self.get_test_response_project_quotas('none')},
                         project_quotas)

    def test_get_quotas_using_some_defaults(self):
        self.create_a_test_project_quotas('partial')
        quotas = self.quota_driver.get_quotas(
            self.get_test_project_id('partial'))
        expected_quotas = {'quotas': {'consumers': -1, 'containers': 66,
                                      'orders': -1, 'secrets': 55,
                                      'cas': -1}}
        self.assertEqual(expected_quotas, quotas)

    def test_get_quotas_using_all_defaults(self):
        quotas = self.quota_driver.get_quotas('not_configured')
        expected_quotas = {'quotas': {'consumers': -1, 'containers': -1,
                                      'orders': -1, 'secrets': -1,
                                      'cas': -1}}
        self.assertEqual(expected_quotas, quotas)

    # ----------------------- Helper Functions ---------------------------
    def get_test_project_id(self, index=1):
        if index == 'partial':
            return 'project_partial'
        elif index == 'none':
            return 'project_none'
        else:
            return 'project' + str(index)

    def get_test_parsed_project_quotas(self, index=1):
        if index == 'partial':
            parsed_project_quotas = {
                'secrets': 55,
                'containers': 66}
        elif index == 'none':
            parsed_project_quotas = {}
        else:
            parsed_project_quotas = {
                'secrets': index * 100 + 1,
                'orders': index * 100 + 2,
                'containers': index * 100 + 3,
                'consumers': index * 100 + 5,
                'cas': index * 100 + 6}
        return parsed_project_quotas

    def get_test_response_project_quotas(self, index=1):
        if index == 'partial':
            response_project_quotas = {
                'secrets': 55,
                'orders': None,
                'containers': 66,
                'consumers': None,
                'cas': None}
        elif index == 'none':
            response_project_quotas = {
                'secrets': None,
                'orders': None,
                'containers': None,
                'consumers': None,
                'cas': None}
        else:
            response_project_quotas = {
                'secrets': index * 100 + 1,
                'orders': index * 100 + 2,
                'containers': index * 100 + 3,
                'consumers': index * 100 + 5,
                'cas': index * 100 + 6}
        return response_project_quotas

    def create_a_test_project_quotas(self, index=1):
        project_id = self.get_test_project_id(index)
        parsed_project_quotas = self.get_test_parsed_project_quotas(index)
        self.quota_driver.set_project_quotas(project_id, parsed_project_quotas)

    def create_project_quotas(self):
        for index in [1, 2, 3]:
            self.create_a_test_project_quotas(index)


class DummyRepoForTestingQuotaEnforcement(object):

    def __init__(self, get_count_return_value):
        self.get_count_return_value = get_count_return_value

    def get_count(self, internal_project_id):
        return self.get_count_return_value


class WhenTestingQuotaEnforcingFunctions(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingQuotaEnforcingFunctions, self).setUp()
        self.quota_driver = quota.QuotaDriver()
        self.project = models.Project()
        self.project.id = 'my_internal_id'
        self.project.external_id = 'my_keystone_id'

    def test_should_pass_default_unlimited(self):
        test_repo = DummyRepoForTestingQuotaEnforcement(0)
        quota_enforcer = quota.QuotaEnforcer('secrets', test_repo)
        quota_enforcer.enforce(self.project)

    def test_should_raise_disabled_value(self):
        test_repo = DummyRepoForTestingQuotaEnforcement(0)
        quota_enforcer = quota.QuotaEnforcer('secrets', test_repo)
        disabled_project_quotas = {'consumers': 0, 'containers': 0,
                                   'orders': 0, 'secrets': 0,
                                   'cas': 0}
        self.quota_driver.set_project_quotas(self.project.external_id,
                                             disabled_project_quotas)
        exception = self.assertRaises(
            excep.QuotaReached,
            quota_enforcer.enforce,
            self.project
        )
        self.assertIn('Quota reached for project', exception.message)
        self.assertIn('my_keystone_id', exception.message)
        self.assertIn('secrets', exception.message)
        self.assertIn(str(0), exception.message)

    def test_should_pass_below_limit(self):
        test_repo = DummyRepoForTestingQuotaEnforcement(4)
        quota_enforcer = quota.QuotaEnforcer('secrets', test_repo)
        five_project_quotas = {'consumers': 5, 'containers': 5,
                               'orders': 5, 'secrets': 5,
                               'cas': 5}
        self.quota_driver.set_project_quotas(self.project.external_id,
                                             five_project_quotas)
        quota_enforcer.enforce(self.project)

    def test_should_raise_equal_limit(self):
        test_repo = DummyRepoForTestingQuotaEnforcement(5)
        quota_enforcer = quota.QuotaEnforcer('secrets', test_repo)
        five_project_quotas = {'consumers': 5, 'containers': 5,
                               'orders': 5, 'secrets': 5,
                               'cas': 5}
        self.quota_driver.set_project_quotas(self.project.external_id,
                                             five_project_quotas)
        exception = self.assertRaises(
            excep.QuotaReached,
            quota_enforcer.enforce,
            self.project
        )
        self.assertIn('Quota reached for project', exception.message)
        self.assertIn('my_keystone_id', exception.message)
        self.assertIn('secrets', exception.message)
        self.assertIn(str(5), exception.message)

    def test_should_raise_above_limit(self):
        test_repo = DummyRepoForTestingQuotaEnforcement(6)
        quota_enforcer = quota.QuotaEnforcer('secrets', test_repo)
        five_project_quotas = {'consumers': 5, 'containers': 5,
                               'orders': 5, 'secrets': 5,
                               'cas': 5}
        self.quota_driver.set_project_quotas(self.project.external_id,
                                             five_project_quotas)
        exception = self.assertRaises(
            excep.QuotaReached,
            quota_enforcer.enforce,
            self.project
        )
        self.assertIn('Quota reached for project', exception.message)
        self.assertIn('my_keystone_id', exception.message)
        self.assertIn('secrets', exception.message)
        self.assertIn(str(5), exception.message)


if __name__ == '__main__':
    unittest.main()
