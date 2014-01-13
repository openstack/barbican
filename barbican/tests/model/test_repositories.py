"""
Copyright 2013-2014 Rackspace, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import unittest

from oslo.config import cfg
from barbican.model.repositories import clean_paging_values


class WhenCleaningRepositoryPagingParameters(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.CONF = cfg.CONF

    def test_parameters_not_assigned(self):
        """ The cleaner should use defaults when params are not specified"""
        clean_offset, clean_limit = clean_paging_values()

        self.assertEqual(clean_offset, 0)
        self.assertEqual(clean_limit, self.CONF.default_limit_paging)

    def test_limit_as_none(self):
        """ When Limit is set to None it should use the default limit"""
        offset = 0
        clean_offset, clean_limit = clean_paging_values(offset_arg=offset,
                                                        limit_arg=None)

        self.assertEqual(clean_offset, offset)
        self.assertIsNotNone(clean_limit)

    def test_offset_as_none(self):
        """ When Offset is set to None it should use an offset of 0 """
        limit = self.CONF.default_limit_paging
        clean_offset, clean_limit = clean_paging_values(offset_arg=None,
                                                        limit_arg=limit)

        self.assertIsNotNone(clean_offset)
        self.assertEqual(clean_limit, limit)

    def test_limit_as_uncastable_str(self):
        """ When Limit cannot be cast to an int, expect the default """
        clean_offset, clean_limit = clean_paging_values(offset_arg=0,
                                                        limit_arg='boom')
        self.assertEqual(clean_offset, 0)
        self.assertEqual(clean_limit, self.CONF.default_limit_paging)

    def test_offset_as_uncastable_str(self):
        """ When Offset cannot be cast to an int, it should be zero """
        limit = self.CONF.default_limit_paging
        clean_offset, clean_limit = clean_paging_values(offset_arg='boom',
                                                        limit_arg=limit)
        self.assertEqual(clean_offset, 0)
        self.assertEqual(clean_limit, limit)

    def test_limit_is_less_than_one(self):
        """Offset should default to 1"""
        limit = -1
        clean_offset, clean_limit = clean_paging_values(offset_arg=1,
                                                        limit_arg=limit)
        self.assertEqual(clean_offset, 1)
        self.assertEqual(clean_limit, 1)

    def test_limit_ist_too_big(self):
        """Limit should max out at configured value"""
        limit = self.CONF.max_limit_paging + 10
        clean_offset, clean_limit = clean_paging_values(offset_arg=1,
                                                        limit_arg=limit)
        self.assertEqual(clean_limit, self.CONF.max_limit_paging)
