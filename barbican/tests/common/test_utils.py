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

import mock

from barbican.common import utils


class WhenTestingAcceptEncodingGetter(unittest.TestCase):

    def setUp(self):
        self.req = mock.Mock()

    def test_parses_accept_encoding_header(self):
        self.req.get_header.return_value = '*'
        ae = utils.get_accepted_encodings(self.req)
        self.req.get_header.assert_called_once_with('Accept-Encoding')
        self.assertEqual(ae, ['*'])

    def test_returns_none_for_empty_encoding(self):
        self.req.get_header.return_value = None
        ae = utils.get_accepted_encodings(self.req)
        self.assertIsNone(ae)

    def test_parses_single_accept_with_quality_value(self):
        self.req.get_header.return_value = 'base64;q=0.7'
        ae = utils.get_accepted_encodings(self.req)
        self.assertEqual(ae, ['base64'])

    def test_parses_more_than_one_encoding(self):
        self.req.get_header.return_value = 'base64, gzip'
        ae = utils.get_accepted_encodings(self.req)
        self.assertEqual(ae, ['base64', 'gzip'])

    def test_can_sort_by_quality_value(self):
        self.req.get_header.return_value = 'base64;q=0.5, gzip;q=0.6, compress'
        ae = utils.get_accepted_encodings(self.req)
        self.assertEqual(ae, ['compress', 'gzip', 'base64'])
