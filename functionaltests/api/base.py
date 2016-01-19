"""
Copyright 2014 Rackspace

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
import abc
import fixtures
import logging
import os
import uuid

import oslotest.base as oslotest
import six
from testtools import testcase

from barbican.tests import utils
from functionaltests.common import client
from functionaltests.common import config


CONF = config.get_config()


class TestCase(oslotest.BaseTestCase):
    max_payload_size = 10000
    max_sized_payload = 'a' * max_payload_size
    oversized_payload = 'a' * (max_payload_size + 1)
    max_field_size = 255
    max_sized_field = 'a' * max_field_size
    oversized_field = 'a' * (max_field_size + 1)

    log_format = ('%(asctime)s %(process)d %(levelname)-8s '
                  '[%(name)s] %(message)s')

    @classmethod
    def setUpClass(cls):
        cls.LOG = logging.getLogger(cls._get_full_case_name())
        super(TestCase, cls).setUpClass()

    def setUp(self):
        self.LOG.info('Starting: %s', self._testMethodName)
        super(TestCase, self).setUp()

        self.client = client.BarbicanClient()

        stdout_capture = os.environ.get('OS_STDOUT_CAPTURE')
        stderr_capture = os.environ.get('OS_STDERR_CAPTURE')
        log_capture = os.environ.get('OS_LOG_CAPTURE')

        if ((stdout_capture and stdout_capture.lower() == 'true') or
                stdout_capture == '1'):
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if ((stderr_capture and stderr_capture.lower() == 'true') or
                stderr_capture == '1'):
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))
        if ((log_capture and log_capture.lower() == 'true') or
                log_capture == '1'):
            self.useFixture(fixtures.LoggerFixture(nuke_handlers=False,
                                                   format=self.log_format,
                                                   level=logging.DEBUG))

    def tearDown(self):
        super(TestCase, self).tearDown()
        self.LOG.info('Finished: %s\n', self._testMethodName)

    @classmethod
    def _get_full_case_name(cls):
        name = '{module}:{case_name}'.format(
            module=cls.__module__,
            case_name=cls.__name__
        )
        return name


@six.add_metaclass(abc.ABCMeta)
class PagingTestCase(TestCase):

    def setUp(self):
        super(PagingTestCase, self).setUp()
        self._all_fetched_resources = []

    def tearDown(self):
        super(PagingTestCase, self).tearDown()

    def _set_filter_field(self, model):
        filter = str(uuid.uuid4())
        self.set_filter_field(filter, model)
        return filter

    def _validate_resource_group(self, resources=[], next_ref=None,
                                 prev_ref=None,
                                 expected_size=0,
                                 next_ref_should_be_none=True,
                                 prev_ref_should_be_none=True):
        """Validate the returned group of resources.

        Will check for:
            1. there is a returned group (ie not None)
            2. size of the returned group
            3. no duplicates within the returned group
            4. no duplicates across multiple calls
            5. valid next resource ref
            6. valid previous resource ref

        :param resources: the list of resources
        :param expected_size: the expected size of the list
        :param next_ref: next href
        :param prev_ref: previous href
        :param next_ref_should_be_none: should next href be none?
        :param next_ref_should_be_none: should prev href be none?
        :param all_fetched_resources: running list of all resources (used to
        detect duplicates across multiple calls)
        """
        self.assertIsNotNone(resources)
        self.assertEqual(len(resources), expected_size)
        self.assertEqual(next_ref_should_be_none, next_ref is None)
        self.assertEqual(prev_ref_should_be_none, prev_ref is None)

        # check for duplicates within this group
        self.assertEqual(len(resources), len(set(resources)))

        # check for duplicates across calls
        if len(self._all_fetched_resources):
            duplicates = [entity for entity in resources if entity in
                          self._all_fetched_resources]
            self.assertEqual(len(duplicates), 0)

        # add to our running list of resource refs
        self._all_fetched_resources.extend(resources)

    @abc.abstractmethod
    def create_model(self):
        pass

    @abc.abstractmethod
    def create_resources(self, count=0, model=None):
        pass

    @abc.abstractmethod
    def get_resources(self, limit=10, offset=0, filter=""):
        pass

    @abc.abstractmethod
    def set_filter_field(self, filter, model):
        pass

    @testcase.attr('positive')
    def test_paging_with_limits_and_offsets(self):
        """Covers resource paging limit and offset attributes."""
        test_model = self.create_model()

        number_of_resource_groups = 5
        resources_per_group = 10

        filter = self._set_filter_field(test_model)

        # create a number of resources
        self.create_resources(
            count=number_of_resource_groups * resources_per_group,
            model=test_model)

        # validate all groups of resources
        for i in range(1, number_of_resource_groups + 1):
            resp, resources, next_ref, prev_ref = self.get_resources(
                limit=resources_per_group,
                offset=(i - 1) * resources_per_group,
                filter=filter)

            self.assertEqual(200, resp.status_code)

            check_next = i == number_of_resource_groups
            check_prev = i == 1
            self._validate_resource_group(resources=resources,
                                          next_ref=next_ref, prev_ref=prev_ref,
                                          expected_size=resources_per_group,
                                          next_ref_should_be_none=check_next,
                                          prev_ref_should_be_none=check_prev)

    @testcase.attr('positive')
    def test_paging_with_offset_zero_and_varying_limits(self):
        """Covers listing resources with limit attribute.

        Use limits from 1 to twice the number of resources we expect.  Always
        use offset=0 so we start from the beginning.
        """

        res_count = 25

        test_model = self.create_model()
        filter = self._set_filter_field(test_model)
        self.create_resources(count=res_count, model=test_model)

        minimum_limit = 1
        maximum_limit = res_count * 2
        offset = 0

        for limit in range(minimum_limit, maximum_limit):
            resp, resources, next_ref, prev_ref = self.get_resources(
                limit=limit, offset=offset, filter=filter)

            self.assertEqual(200, resp.status_code)

            check_next = limit >= res_count
            check_prev = offset == 0

            self._validate_resource_group(resources=resources,
                                          next_ref=next_ref, prev_ref=prev_ref,
                                          expected_size=min(limit, res_count),
                                          next_ref_should_be_none=check_next,
                                          prev_ref_should_be_none=check_prev)

    @testcase.attr('positive')
    def test_paging_exceeding_paging_max_limit(self):
        """Covers case of listing resources with a limit that exceeds max.

        Create a number of resources over the max paging limit, then try
        to get them all in one call.  It should only return the max, with
        a next link to get the rest.
        """
        max_allowable_limit = 100
        number_of_resources = max_allowable_limit + 10

        test_model = self.create_model()
        filter = self._set_filter_field(test_model)
        self.create_resources(count=number_of_resources, model=test_model)

        resp, resources, next_ref, prev_ref = self.get_resources(
            limit=number_of_resources, offset=0, filter=filter)
        self.assertEqual(200, resp.status_code)

        self._validate_resource_group(resources=resources, next_ref=next_ref,
                                      prev_ref=prev_ref,
                                      expected_size=max_allowable_limit,
                                      next_ref_should_be_none=False,
                                      prev_ref_should_be_none=True)
        limit, offset = utils.get_limit_and_offset_from_ref(next_ref)

        # new offset and limit should both be the same as the max limit
        self.assertEqual(str(max_allowable_limit), limit)
        self.assertEqual(str(max_allowable_limit), offset)

        # now get the rest
        resp, resources, next_ref, prev_ref = self.get_resources(
            limit=limit, offset=offset, filter=filter)
        self.assertEqual(200, resp.status_code)

        expected_size = number_of_resources - max_allowable_limit
        self._validate_resource_group(resources=resources, next_ref=next_ref,
                                      prev_ref=prev_ref,
                                      expected_size=expected_size,
                                      next_ref_should_be_none=True,
                                      prev_ref_should_be_none=False)

    @testcase.attr('positive')
    def test_paging_next_option_start_in_middle(self):
        """Covers getting a list of resources and using the next reference."""

        number_of_resources = 150

        test_model = self.create_model()
        filter = self._set_filter_field(test_model)
        self.create_resources(count=number_of_resources, model=test_model)

        # First set of resources
        limit = number_of_resources // 10
        offset = number_of_resources // 2

        resp, resources, next_ref, prev_ref = self.get_resources(
            limit=limit, offset=offset, filter=filter)
        self.assertEqual(200, resp.status_code)

        self._validate_resource_group(resources=resources, next_ref=next_ref,
                                      prev_ref=prev_ref,
                                      expected_size=limit,
                                      next_ref_should_be_none=False,
                                      prev_ref_should_be_none=False)

        limit, offset = utils.get_limit_and_offset_from_ref(next_ref)

        # Next set of resources
        resp, resources, next_ref, prev_ref = self.get_resources(
            limit=limit, offset=offset, filter=filter)

        self._validate_resource_group(resources=resources, next_ref=next_ref,
                                      prev_ref=prev_ref,
                                      expected_size=int(limit),
                                      next_ref_should_be_none=False,
                                      prev_ref_should_be_none=False)

    @testcase.attr('positive')
    def test_paging_with_default_limit_and_varying_offsets(self):
        """Covers listing resources with various offsets.

        Use offsets from 0 to the number of resources we expect.  Always
        use default limit.
        """

        number_of_resources = 15

        test_model = self.create_model()
        filter = self._set_filter_field(test_model)
        self.create_resources(count=number_of_resources, model=test_model)

        minimum_offset = 0
        maximum_offset = number_of_resources
        limit = 10

        for offset in range(minimum_offset, maximum_offset):
            resp, resources, next_ref, prev_ref = self.get_resources(
                limit=limit, offset=offset, filter=filter)
            self.assertEqual(200, resp.status_code)

            check_next = offset + limit >= number_of_resources
            check_prev = offset == 0
            expected_size = min(limit, number_of_resources - offset)

            self._validate_resource_group(resources=resources,
                                          next_ref=next_ref,
                                          prev_ref=prev_ref,
                                          expected_size=expected_size,
                                          next_ref_should_be_none=check_next,
                                          prev_ref_should_be_none=check_prev)

    @testcase.attr('positive')
    def test_resources_get_paging_prev_option_start_in_middle(self):
        """Covers getting a list of resources and using the next reference."""

        number_of_resources = 150

        test_model = self.create_model()
        filter = self._set_filter_field(test_model)
        self.create_resources(count=number_of_resources, model=test_model)

        # First set of resources
        limit = number_of_resources // 10
        offset = number_of_resources // 2
        resp, resources, next_ref, prev_ref = self.get_resources(
            limit=limit, offset=offset, filter=filter)
        self.assertEqual(200, resp.status_code)

        self._validate_resource_group(resources=resources, next_ref=next_ref,
                                      prev_ref=prev_ref,
                                      expected_size=limit,
                                      next_ref_should_be_none=False,
                                      prev_ref_should_be_none=False)

        limit, offset = utils.get_limit_and_offset_from_ref(prev_ref)

        # Previous set of resources
        resp, resources, next_ref, prev_ref = self.get_resources(
            limit=limit, offset=offset, filter=filter)

        self._validate_resource_group(resources=resources, next_ref=next_ref,
                                      prev_ref=prev_ref,
                                      expected_size=int(limit),
                                      next_ref_should_be_none=False,
                                      prev_ref_should_be_none=False)

    @testcase.attr('positive')
    def test_paging_with_non_integer_limits_and_offsets(self):
        """Covers resource paging limit and offset attributes."""
        test_model = self.create_model()

        number_of_resources = 25

        # create a number of resources
        filter = self._set_filter_field(test_model)
        self.create_resources(count=number_of_resources, model=test_model)

        # pass in non-integer values for limit and offset
        resp, resources, next_ref, prev_ref = self.get_resources(
            limit='not-an-int-limit',
            offset='not-an-int-offset', filter=filter)

        self.assertEqual(200, resp.status_code)
        self._validate_resource_group(resources=resources, next_ref=next_ref,
                                      prev_ref=prev_ref, expected_size=10,
                                      next_ref_should_be_none=False,
                                      prev_ref_should_be_none=True)

    @testcase.attr('positive')
    def test_paging_with_default_limit_and_large_offsets(self):
        """Covers resource paging limit and offset attributes."""
        test_model = self.create_model()

        number_of_resources = 25

        # create a number of resources
        filter = self._set_filter_field(test_model)
        self.create_resources(count=number_of_resources, model=test_model)

        large_offset = 265613988875874769338781322035779626829233452653394495
        limit = 10

        # pass in non-integer values for limit and offset
        resp, resources, next_ref, prev_ref = self.get_resources(
            limit=limit,
            offset=large_offset, filter=filter)

        self.assertEqual(200, resp.status_code)
        self._validate_resource_group(resources=resources, next_ref=next_ref,
                                      prev_ref=prev_ref, expected_size=10,
                                      next_ref_should_be_none=False,
                                      prev_ref_should_be_none=True)
