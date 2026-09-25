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
from barbican.common import utils
from barbican.tests import utils as test_utils


class WhenTestingGetContainerID(test_utils.BaseTestCase):

    def test_get_container_id_passes(self):
        test_ref = 'https://localhost/v1/containers/good_container_ref'
        result = hrefs.get_container_id_from_ref(test_ref)
        self.assertEqual('good_container_ref', result)

    def test_get_container_id_raises(self):
        test_ref = 'bad_container_ref'
        self.assertRaises(IndexError,
                          hrefs.get_container_id_from_ref,
                          test_ref)


class WhenTestingPaginationHrefs(test_utils.BaseTestCase):

    def setUp(self):
        super().setUp()
        utils.CONF.set_override('host_href', 'http://localhost:9311')

    def tearDown(self):
        super().tearDown()
        utils.CONF.clear_override('host_href')

    def test_convert_list_to_href_no_filters(self):
        result = hrefs.convert_list_to_href('secrets', 0, 10)
        self.assertIn('limit=10', result)
        self.assertIn('offset=0', result)
        self.assertNotIn('secret_type', result)

    def test_convert_list_to_href_preserves_filters(self):
        result = hrefs.convert_list_to_href(
            'secrets', 10, 10, query_string='secret_type=passphrase')
        self.assertIn('limit=10', result)
        self.assertIn('offset=10', result)
        self.assertIn('secret_type=passphrase', result)

    def test_next_href_preserves_filters(self):
        result = hrefs.next_href(
            'secrets', 0, 10, query_string='secret_type=passphrase')
        self.assertIn('offset=10', result)
        self.assertIn('secret_type=passphrase', result)

    def test_previous_href_preserves_filters(self):
        result = hrefs.previous_href(
            'secrets', 10, 10, query_string='secret_type=passphrase')
        self.assertIn('offset=0', result)
        self.assertIn('secret_type=passphrase', result)

    def test_add_nav_hrefs_preserves_filters_in_next(self):
        data = {}
        result = hrefs.add_nav_hrefs(
            'secrets', 0, 10, 25, data,
            query_string='secret_type=passphrase')
        self.assertIn('next', result)
        self.assertIn('secret_type=passphrase', result['next'])
        self.assertNotIn('previous', result)

    def test_add_nav_hrefs_preserves_filters_in_previous(self):
        data = {}
        result = hrefs.add_nav_hrefs(
            'secrets', 10, 10, 25, data,
            query_string='secret_type=passphrase')
        self.assertIn('previous', result)
        self.assertIn('secret_type=passphrase', result['previous'])
        self.assertIn('next', result)
        self.assertIn('secret_type=passphrase', result['next'])

    def test_add_nav_hrefs_no_filters_omits_extra_params(self):
        data = {}
        result = hrefs.add_nav_hrefs('secrets', 0, 10, 25, data)
        self.assertIn('next', result)
        self.assertNotIn('secret_type', result['next'])
