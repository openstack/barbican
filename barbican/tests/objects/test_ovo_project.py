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


class TestProject(test_ovo_base.OVOTestCase):
    def setUp(self):
        super(TestProject, self).setUp()
        self.session = objects.Project.get_session()

    def test_ovo_should_create_retrieve_deleted_project(self):
        # Create project
        create_project_ovo = objects.Project(external_id='fake_external_id',
                                             status='ACTIVE')
        create_project_ovo.create(session=self.session)
        project_id = create_project_ovo.id
        self.assertFalse(create_project_ovo.deleted)
        self.assertEqual('ACTIVE', create_project_ovo.status)
        self.assertIsNone(create_project_ovo.deleted_at)
        self.assertIsNotNone(create_project_ovo.id)
        # Get project
        get1_project_ovo = objects.Project.get(entity_id=project_id)
        self.assertEqual('ACTIVE', get1_project_ovo.status)
        # Update project
        update_project_ovo = objects.Project(id=project_id,
                                             status='ERROR')
        update_project_ovo.save(session=self.session)
        # Get project
        get2_project_ovo = objects.Project.get(entity_id=project_id)
        self.assertEqual('ERROR', get2_project_ovo.status)
        # Delete project
        objects.Project.delete_entity_by_id(entity_id=project_id,
                                            external_project_id=None,
                                            session=self.session)
        self.assertRaises(exception.NotFound, objects.Project.get,
                          entity_id=project_id, session=self.session)

    def test_ovo_should_raise_no_result_found(self):
        self.assertRaises(exception.NotFound, objects.Project.get,
                          entity_id="key project id")

    def test_ovo_find_by_external_project_id(self):
        external_id = 'fake2_external_id'
        project_ovo = objects.Project(external_id=external_id,
                                      status='ACTIVE')
        project_ovo.create(session=self.session)

        project = objects.Project.find_by_external_project_id(
            external_project_id=external_id, session=self.session)
        self.assertEqual(external_id, project.external_id)
