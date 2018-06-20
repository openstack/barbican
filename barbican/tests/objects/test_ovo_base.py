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
from barbican.model import repositories as repos
from barbican import objects
from barbican.tests import database_utils


class OVOTestCase(database_utils.RepositoryTestCase):
    """Base test case class for in-memory database unit tests."""
    def setUp(self):
        super(OVOTestCase, self).setUp()
        self.session = repos.get_session()


class TestBarbicanObject(OVOTestCase):
    def test_ovo_get_session(self):
        session = objects.BarbicanObject.get_session()
        self.assertEqual(self.session, session)
