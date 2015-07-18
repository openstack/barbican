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

        self.project_id_1 = '11111'
        self.project_id_2 = '22222'
        self.project_id_3 = '33333'
        self.parsed_project_quotas_1 = {
            'secrets': 101,
            'orders': 102,
            'containers': 103,
            'transport_keys': 104,
            'consumers': 105}
        self.parsed_project_quotas_2 = {
            'secrets': 201,
            'orders': 202,
            'containers': 203,
            'transport_keys': 204,
            'consumers': 205}
        self.parsed_project_quotas_3 = {
            'secrets': 301,
            'containers': 303,
            'consumers': 305}

    def test_get_list_of_one_project_quotas(self):
        session = self.project_quotas_repo.get_session()
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_1,
            self.parsed_project_quotas_1,
            session)
        session.commit()
        retrieved_project_quotas, offset, limit, total =\
            self.project_quotas_repo.get_by_create_date(session=session)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)
        self.assertEqual([self.project_id_1],
                         [s.project_id for s in retrieved_project_quotas])
        self.assertEqual([101],
                         [s.secrets for s in retrieved_project_quotas])
        self.assertEqual([102],
                         [s.orders for s in retrieved_project_quotas])
        self.assertEqual([103],
                         [s.containers for s in retrieved_project_quotas])
        self.assertEqual([104],
                         [s.transport_keys for s in retrieved_project_quotas])
        self.assertEqual([105],
                         [s.consumers for s in retrieved_project_quotas])

    def test_get_list_of_two_project_quotas(self):
        session = self.project_quotas_repo.get_session()
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_1,
            self.parsed_project_quotas_1,
            session)
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_2,
            self.parsed_project_quotas_2,
            session)
        session.commit()
        retrieved_project_quotas, offset, limit, total =\
            self.project_quotas_repo.get_by_create_date(session=session)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(2, total)
        self.assertItemsEqual([self.project_id_1, self.project_id_2],
                              [s.project_id for s in retrieved_project_quotas])
        self.assertItemsEqual([101, 201],
                              [s.secrets for s in retrieved_project_quotas])
        self.assertItemsEqual([102, 202],
                              [s.orders for s in retrieved_project_quotas])
        self.assertItemsEqual([103, 203],
                              [s.containers for s in retrieved_project_quotas])
        self.assertItemsEqual([104, 204],
                              [s.transport_keys for s in
                               retrieved_project_quotas])
        self.assertItemsEqual([105, 205],
                              [s.consumers for s in retrieved_project_quotas])

    def test_should_raise_get_list_of_zero_project_quotas(self):
        session = self.project_quotas_repo.get_session()
        self.assertRaises(
            exception.NotFound,
            self.project_quotas_repo.get_by_create_date,
            session=session,
            suppress_exception=False)

    def test_should_suppress_get_list_of_zero_project_quotas(self):
        session = self.project_quotas_repo.get_session()
        retrieved_project_quotas, offset, limit, total =\
            self.project_quotas_repo.get_by_create_date(
                session=session, suppress_exception=True)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_get_specific_project_quotas(self):
        session = self.project_quotas_repo.get_session()
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_1, self.parsed_project_quotas_1, session)
        session.commit()
        retrieved_project_quotas =\
            self.project_quotas_repo.get_by_project_id(self.project_id_1,
                                                       session=session)
        self.assertEqual(self.project_id_1,
                         retrieved_project_quotas.project_id)
        self.assertEqual(101, retrieved_project_quotas.secrets)
        self.assertEqual(102, retrieved_project_quotas.orders)
        self.assertEqual(103, retrieved_project_quotas.containers)
        self.assertEqual(104, retrieved_project_quotas.transport_keys)
        self.assertEqual(105, retrieved_project_quotas.consumers)

    def test_project_quotas_with_some_defaults(self):
        session = self.project_quotas_repo.get_session()
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_3, self.parsed_project_quotas_3, session)
        session.commit()
        retrieved_project_quotas =\
            self.project_quotas_repo.get_by_project_id(self.project_id_3,
                                                       session=session)
        self.assertEqual(self.project_id_3,
                         retrieved_project_quotas.project_id)
        self.assertEqual(301, retrieved_project_quotas.secrets)
        self.assertIsNone(retrieved_project_quotas.orders)
        self.assertEqual(303, retrieved_project_quotas.containers)
        self.assertIsNone(retrieved_project_quotas.transport_keys)
        self.assertEqual(305, retrieved_project_quotas.consumers)

    def test_update_specific_project_quotas(self):
        session = self.project_quotas_repo.get_session()

        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_1, self.parsed_project_quotas_1, session)
        session.commit()
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_1, self.parsed_project_quotas_2, session)
        session.commit()
        retrieved_project_quotas =\
            self.project_quotas_repo.get_by_project_id(self.project_id_1,
                                                       session=session)
        self.assertEqual(self.project_id_1,
                         retrieved_project_quotas.project_id)
        self.assertEqual(201, retrieved_project_quotas.secrets)
        self.assertEqual(202, retrieved_project_quotas.orders)
        self.assertEqual(203, retrieved_project_quotas.containers)
        self.assertEqual(204, retrieved_project_quotas.transport_keys)
        self.assertEqual(205, retrieved_project_quotas.consumers)

    def test_should_raise_get_missing_specific_project_quotas(self):
        session = self.project_quotas_repo.get_session()
        self.assertRaises(
            exception.NotFound,
            self.project_quotas_repo.get_by_project_id,
            "dummy",
            suppress_exception=False,
            session=session)

    def test_should_suppress_get_missing_specific_project_quotas(self):
        session = self.project_quotas_repo.get_session()
        retrieved_project_quotas =\
            self.project_quotas_repo.get_by_project_id(self.project_id_1,
                                                       suppress_exception=True,
                                                       session=session)
        self.assertIsNone(retrieved_project_quotas)

    def test_get_by_create_date_nothing(self):
        session = self.project_quotas_repo.get_session()
        retrieved_project_quotas, offset, limit, total =\
            self.project_quotas_repo.get_by_create_date(
                session=session, suppress_exception=True)
        self.assertEqual([], retrieved_project_quotas)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_should_raise_add_duplicate_project_id(self):
        session = self.project_quotas_repo.get_session()
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_1, self.parsed_project_quotas_1, session)
        session.commit()
        project_quotas = models.ProjectQuotas(
            self.project_id_1, self.parsed_project_quotas_2)
        self.assertRaises(
            exception.Duplicate,
            self.project_quotas_repo.create_from,
            project_quotas,
            session)

    def test_should_delete(self):
        session = self.project_quotas_repo.get_session()
        self.project_quotas_repo.create_or_update_by_project_id(
            self.project_id_1, self.parsed_project_quotas_1, session)
        session.commit()
        self.project_quotas_repo.delete_by_project_id(self.project_id_1,
                                                      session=session)

    def test_should_raise_delete_not_found(self):
        session = self.project_quotas_repo.get_session()
        self.assertRaises(
            exception.NotFound,
            self.project_quotas_repo.delete_by_project_id,
            "dummy",
            session=session)

    def test_should_suppress_delete_not_found(self):
        session = self.project_quotas_repo.get_session()
        self.project_quotas_repo.delete_by_project_id('dummy',
                                                      suppress_exception=True,
                                                      session=session)

    def test_do_entity_name(self):
        self.assertEqual("ProjectQuotas",
                         self.project_quotas_repo._do_entity_name())

    def test_should_raise_not_found_get_by_entity_id(self):
        session = self.project_quotas_repo.get_session()
        self.assertRaises(
            exception.NotFound,
            self.project_quotas_repo.get,
            "dummy",
            session=session)


if __name__ == '__main__':
    unittest.main()
