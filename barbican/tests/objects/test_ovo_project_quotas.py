#    Copyright 2018 Fujitsu.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from barbican.common import exception
from barbican import objects
from barbican.tests.objects import test_ovo_base


class TestProjectQuotas(test_ovo_base.OVOTestCase):
    def setUp(self):
        super(TestProjectQuotas, self).setUp()
        self.init()

    def init(self):
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

        project1 = objects.Project(external_id='11111')
        project1.create(session=self.session)
        self.project_id1 = project1.id
        self.external_id1 = project1.external_id

        project2 = objects.Project(external_id='2222')
        project2.create(session=self.session)
        self.project_id2 = project2.id
        self.external_id2 = project2.external_id

        project3 = objects.Project(external_id='3333')
        project3.create(session=self.session)
        self.project_id3 = project3.id
        self.external_id3 = project3.external_id

    def test_ovo_get_list_of_one_project_quotas(self):
        objects.ProjectQuotas.create_or_update_by_project_id(
            project_id=self.project_id1,
            parsed_project_quotas=self.parsed_project_quotas_1,
            session=self.session
        )
        retrieved_project_quotas, offset, limit, total = \
            objects.ProjectQuotas.get_by_create_date(session=self.session)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)
        self.assertEqual([self.project_id1],
                         [s.project_id for s in retrieved_project_quotas])
        self.assertEqual([self.external_id1],
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

    def test_ovo_get_list_of_two_project_quotas(self):
        objects.ProjectQuotas.create_or_update_by_project_id(
            project_id=self.project_id1,
            parsed_project_quotas=self.parsed_project_quotas_1,
            session=self.session
        )
        objects.ProjectQuotas.create_or_update_by_project_id(
            project_id=self.project_id2,
            parsed_project_quotas=self.parsed_project_quotas_2,
            session=self.session
        )
        retrieved_project_quotas, offset, limit, total = \
            objects.ProjectQuotas.get_by_create_date(session=self.session)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(2, total)
        self.assertCountEqual([self.project_id1, self.project_id2],
                              [s.project_id for s in retrieved_project_quotas])
        self.assertCountEqual([self.external_id1,
                               self.external_id2],
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

    def test_ovo_should_raise_get_list_of_zero_project_quotas(self):
        self.assertRaises(
            exception.NotFound,
            objects.ProjectQuotas.get_by_create_date,
            session=self.session,
            suppress_exception=False)

    def test_ovo_get_specific_project_quotas(self):
        objects.ProjectQuotas.create_or_update_by_project_id(
            self.project_id1,
            self.parsed_project_quotas_1,
            session=self.session)
        retrieved_project_quotas = \
            objects.ProjectQuotas.get_by_external_project_id(
                self.external_id1, session=self.session)
        self.assertEqual(self.project_id1,
                         retrieved_project_quotas.project_id)
        self.assertEqual(self.external_id1,
                         retrieved_project_quotas.project.external_id)
        self.assertEqual(101, retrieved_project_quotas.secrets)
        self.assertEqual(102, retrieved_project_quotas.orders)
        self.assertEqual(103, retrieved_project_quotas.containers)
        self.assertEqual(105, retrieved_project_quotas.consumers)
        self.assertEqual(106, retrieved_project_quotas.cas)

    def test_ovo_project_quotas_with_some_defaults(self):
        objects.ProjectQuotas.create_or_update_by_project_id(
            self.project_id3,
            self.parsed_project_quotas_3,
            session=self.session)
        retrieved_project_quotas = \
            objects.ProjectQuotas.get_by_external_project_id(
                self.external_id3, session=self.session)
        self.assertEqual(self.project_id3,
                         retrieved_project_quotas.project_id)
        self.assertEqual(self.external_id3,
                         retrieved_project_quotas.project.external_id)
        self.assertEqual(301, retrieved_project_quotas.secrets)
        self.assertIsNone(retrieved_project_quotas.orders)
        self.assertEqual(303, retrieved_project_quotas.containers)
        self.assertEqual(305, retrieved_project_quotas.consumers)
        self.assertIsNone(retrieved_project_quotas.cas)

    def test_ovo_update_specific_project_quotas(self):
        objects.ProjectQuotas.create_or_update_by_project_id(
            self.project_id1,
            self.parsed_project_quotas_1,
            session=self.session)
        self.session.commit()
        objects.ProjectQuotas.create_or_update_by_project_id(
            self.project_id1,
            self.parsed_project_quotas_2,
            session=self.session)
        self.session.commit()
        retrieved_project_quotas = \
            objects.ProjectQuotas.get_by_external_project_id(
                self.external_id1, session=self.session)
        self.assertEqual(self.project_id1,
                         retrieved_project_quotas.project_id)
        self.assertEqual(self.external_id1,
                         retrieved_project_quotas.project.external_id)
        self.assertEqual(201, retrieved_project_quotas.secrets)
        self.assertEqual(202, retrieved_project_quotas.orders)
        self.assertEqual(203, retrieved_project_quotas.containers)
        self.assertEqual(205, retrieved_project_quotas.consumers)
        self.assertEqual(206, retrieved_project_quotas.cas)

    def test_ovo_should_raise_get_missing_specific_project_quotas(self):
        self.assertRaises(
            exception.NotFound,
            objects.ProjectQuotas.get_by_external_project_id,
            'trollo',
            suppress_exception=False,
            session=self.session)

    def test_ovo_should_suppress_get_missing_specific_project_quotas(self):
        retrieved_project_quotas = \
            objects.ProjectQuotas.get_by_external_project_id(
                'trollo', suppress_exception=True, session=self.session)
        self.assertIsNone(retrieved_project_quotas)

    def test_ovo_get_by_create_date_nothing(self):
        retrieved_project_quotas, offset, limit, total = \
            objects.ProjectQuotas.get_by_create_date(
                session=self.session, suppress_exception=True)
        self.assertEqual([], retrieved_project_quotas)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_ovo_should_delete(self):
        objects.ProjectQuotas.create_or_update_by_project_id(
            self.project_id1,
            self.parsed_project_quotas_1,
            session=self.session)
        self.session.commit()
        objects.ProjectQuotas.delete_by_external_project_id(
            self.external_id1, session=self.session)

    def test_ovo_should_raise_delete_not_found(self):
        self.assertRaises(
            exception.NotFound,
            objects.ProjectQuotas.delete_by_external_project_id,
            'trollo',
            session=self.session)

    def test_ovo_should_suppress_delete_not_found(self):
        objects.ProjectQuotas.delete_by_external_project_id(
            'trollo', suppress_exception=True, session=self.session)

    def test_ovo_should_raise_not_found_get_by_entity_id(self):
        self.assertRaises(
            exception.NotFound,
            objects.ProjectQuotas.get,
            'trollo',
            session=self.session)

    def test_ovo_should_throw_exception_missing_project_id(self):
        project_quotas = objects.ProjectQuotas()
        self.assertRaises(exception.MissingArgumentError,
                          project_quotas.create,
                          session=self.session)
