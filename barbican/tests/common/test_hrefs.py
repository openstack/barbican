# Copyright (c) 2015, Cisco Systems
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

from barbican.common import hrefs
from barbican.tests import utils as test_utils


class WhenTestingGetContainerID(test_utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingGetContainerID, self).setUp()

    def test_get_container_id_passes(self):
        test_ref = 'https://localhost/v1/containers/good_container_ref'
        result = hrefs.get_container_id_from_ref(test_ref)
        self.assertEqual('good_container_ref', result)

    def test_get_container_id_raises(self):
        test_ref = 'bad_container_ref'
        self.assertRaises(IndexError,
                          hrefs.get_container_id_from_ref,
                          test_ref)
