# Copyright (c) 2015 Cisco Systems
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import unittest

from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


class WhenTestingProjectQuotasRepo(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingProjectQuotasRepo, self).setUp()
        self.project_quotas_repo = repositories.ProjectQuotasRepo()

        self.session = self.project_quotas_repo.get_session()

        self.project_1 = models.Project()
        self.project_1.id = '11111'
        self.project_1.external_id = '44444'
        self.project_1.save(session=self.session)
        self.project_2 = models.Project()
        self.project_2.id = '22222'
        self.project_2.external_id = '55555'
        self.project_2.save(session=self.session)
        self.project_3 = models.Project()
        self.project_3.id = '33333'
        self.project_3.external_id = '66666'
        self.project_3.save(session=self.session)

        self.parsed_project_quotas_1 = {
            'secrets': 101,
            'orders': 102,
            'containers': 103,
            'consumers': 105,
            'cas': 106}
        self.parsed_project_quotas_2 = {
            'secrets': 201,
            'orders': 202,
            'containers': 203,
            'consumers': 205,
            'cas': 206}
        self.parsed_project_quotas_3 = {
            'secrets': 301,
            'containers': 303,
            'consumers': 305}

    def test_get_list_of_one_project_quotas(self):
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_1.id,
            self.parsed_project_quotas_1,
            session=self.session)
        self.session.commit()
        retrieved_project_quotas, offset, limit, total =\
            self.project_quotas_repo.get_by_create_date(session=self.session)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)
        self.assertEqual([self.project_1.id],
                         [s.project_id for s in retrieved_project_quotas])
        self.assertEqual([self.project_1.external_id],
                         [s.project.external_id for s
                          in retrieved_project_quotas])
        self.assertEqual([101],
                         [s.secrets for s in retrieved_project_quotas])
        self.assertEqual([102],
                         [s.orders for s in retrieved_project_quotas])
        self.assertEqual([103],
                         [s.containers for s in retrieved_project_quotas])
        self.assertEqual([105],
                         [s.consumers for s in retrieved_project_quotas])
        self.assertEqual([106],
                         [s.cas for s in retrieved_project_quotas])

    def test_get_list_of_two_project_quotas(self):
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_1.id,
            self.parsed_project_quotas_1,
            session=self.session)
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_2.id,
            self.parsed_project_quotas_2,
            session=self.session)
        self.session.commit()
        retrieved_project_quotas, offset, limit, total =\
            self.project_quotas_repo.get_by_create_date(session=self.session)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(2, total)
        self.assertCountEqual([self.project_1.id, self.project_2.id],
                              [s.project_id for s in retrieved_project_quotas])
        self.assertCountEqual([self.project_1.external_id,
                               self.project_2.external_id],
                              [s.project.external_id for s
                               in retrieved_project_quotas])
        self.assertCountEqual([101, 201],
                              [s.secrets for s in retrieved_project_quotas])
        self.assertCountEqual([102, 202],
                              [s.orders for s in retrieved_project_quotas])
        self.assertCountEqual([103, 203],
                              [s.containers for s in retrieved_project_quotas])
        self.assertCountEqual([105, 205],
                              [s.consumers for s in retrieved_project_quotas])
        self.assertCountEqual([106, 206],
                              [s.cas for s in retrieved_project_quotas])

    def test_should_raise_get_list_of_zero_project_quotas(self):
        self.assertRaises(
            exception.NotFound,
            self.project_quotas_repo.get_by_create_date,
            session=self.session,
            suppress_exception=False)

    def test_should_suppress_get_list_of_zero_project_quotas(self):
        retrieved_project_quotas, offset, limit, total =\
            self.project_quotas_repo.get_by_create_date(
                session=self.session, suppress_exception=True)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_get_specific_project_quotas(self):
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_1.id,
            self.parsed_project_quotas_1,
            session=self.session)
        self.session.commit()
        retrieved_project_quotas =\
            self.project_quotas_repo.get_by_external_project_id(
                self.project_1.external_id, session=self.session)
        self.assertEqual(self.project_1.id,
                         retrieved_project_quotas.project_id)
        self.assertEqual(self.project_1.external_id,
                         retrieved_project_quotas.project.external_id)
        self.assertEqual(101, retrieved_project_quotas.secrets)
        self.assertEqual(102, retrieved_project_quotas.orders)
        self.assertEqual(103, retrieved_project_quotas.containers)
        self.assertEqual(105, retrieved_project_quotas.consumers)
        self.assertEqual(106, retrieved_project_quotas.cas)

    def test_project_quotas_with_some_defaults(self):
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_3.id,
            self.parsed_project_quotas_3,
            session=self.session)
        self.session.commit()
        retrieved_project_quotas =\
            self.project_quotas_repo.get_by_external_project_id(
                self.project_3.external_id, session=self.session)
        self.assertEqual(self.project_3.id,
                         retrieved_project_quotas.project_id)
        self.assertEqual(self.project_3.external_id,
                         retrieved_project_quotas.project.external_id)
        self.assertEqual(301, retrieved_project_quotas.secrets)
        self.assertIsNone(retrieved_project_quotas.orders)
        self.assertEqual(303, retrieved_project_quotas.containers)
        self.assertEqual(305, retrieved_project_quotas.consumers)
        self.assertIsNone(retrieved_project_quotas.cas)

    def test_update_specific_project_quotas(self):
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_1.id,
            self.parsed_project_quotas_1,
            session=self.session)
        self.session.commit()
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_1.id,
            self.parsed_project_quotas_2,
            session=self.session)
        self.session.commit()
        retrieved_project_quotas =\
            self.project_quotas_repo.get_by_external_project_id(
                self.project_1.external_id, session=self.session)
        self.assertEqual(self.project_1.id,
                         retrieved_project_quotas.project_id)
        self.assertEqual(self.project_1.external_id,
                         retrieved_project_quotas.project.external_id)
        self.assertEqual(201, retrieved_project_quotas.secrets)
        self.assertEqual(202, retrieved_project_quotas.orders)
        self.assertEqual(203, retrieved_project_quotas.containers)
        self.assertEqual(205, retrieved_project_quotas.consumers)
        self.assertEqual(206, retrieved_project_quotas.cas)

    def test_should_raise_get_missing_specific_project_quotas(self):
        self.assertRaises(
            exception.NotFound,
            self.project_quotas_repo.get_by_external_project_id,
            'dummy',
            suppress_exception=False,
            session=self.session)

    def test_should_suppress_get_missing_specific_project_quotas(self):
        retrieved_project_quotas =\
            self.project_quotas_repo.get_by_external_project_id(
                'dummy', suppress_exception=True, session=self.session)
        self.assertIsNone(retrieved_project_quotas)

    def test_get_by_create_date_nothing(self):
        retrieved_project_quotas, offset, limit, total =\
            self.project_quotas_repo.get_by_create_date(
                session=self.session, suppress_exception=True)
        self.assertEqual([], retrieved_project_quotas)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_should_delete(self):
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_1.id,
            self.parsed_project_quotas_1,
            session=self.session)
        self.session.commit()
        self.project_quotas_repo.delete_by_external_project_id(
            self.project_1.external_id, session=self.session)

    def test_should_raise_delete_not_found(self):
        self.assertRaises(
            exception.NotFound,
            self.project_quotas_repo.delete_by_external_project_id,
            'dummy',
            session=self.session)

    def test_should_suppress_delete_not_found(self):
        self.project_quotas_repo.delete_by_external_project_id(
            'dummy', suppress_exception=True, session=self.session)

    def test_do_entity_name(self):
        self.assertEqual("ProjectQuotas",
                         self.project_quotas_repo._do_entity_name())

    def test_should_raise_not_found_get_by_entity_id(self):
        self.assertRaises(
            exception.NotFound,
            self.project_quotas_repo.get,
            'dummy',
            session=self.session)


if __name__ == '__main__':
    unittest.main()
