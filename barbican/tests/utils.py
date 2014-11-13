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
import datetime
import functools
from os import path
import time
import types
import urlparse

import oslotest.base as oslotest
import six


class BaseTestCase(oslotest.BaseTestCase):
    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.order_id = 'order1234'
        self.keystone_id = 'keystone1234'

    def tearDown(self):
        super(BaseTestCase, self).tearDown()


def construct_new_test_function(original_func, name, build_params):
    """Builds a new test function based on parameterized data.

    :param original_func: The original test function that is used as a template
    :param name: The fullname of the new test function
    :param build_params: A dictionary or list containing args or kwargs
        for the new test
    :return: A new function object
    """
    new_func = types.FunctionType(
        six.get_function_code(original_func),
        six.get_function_globals(original_func),
        name=name,
        argdefs=six.get_function_defaults(original_func)
    )

    # Support either an arg list or kwarg dict for our data
    build_args = build_params if isinstance(build_params, list) else []
    build_kwargs = build_params if isinstance(build_params, dict) else {}

    # Build a test wrapper to execute with our kwargs
    def test_wrapper(func, test_args, test_kwargs):
        @functools.wraps(func)
        def wrapper(self):
            return func(self, *test_args, **test_kwargs)
        return wrapper

    return test_wrapper(new_func, build_args, build_kwargs)


def process_parameterized_function(name, func_obj, build_data):
    """Build lists of functions to add and remove to a test case."""
    to_remove = []
    to_add = []

    for subtest_name, params in six.iteritems(build_data):
        # Build new test function
        func_name = '{0}_{1}'.format(name, subtest_name)
        new_func = construct_new_test_function(func_obj, func_name, params)

        # Mark the new function as needed to be added to the class
        to_add.append((func_name, new_func))

        # Mark key for removal
        to_remove.append(name)

    return to_remove, to_add


def parameterized_test_case(cls):
    """Class decorator to process parameterized tests

    This allows for parameterization to be used for potentially any
    unittest compatible runner; including testr and py.test.
    """
    tests_to_remove = []
    tests_to_add = []
    for key, val in six.iteritems(vars(cls)):
        # Only process tests with build data on them
        if key.startswith('test_') and val.__dict__.get('build_data'):
            to_remove, to_add = process_parameterized_function(
                name=key,
                func_obj=val,
                build_data=val.__dict__.get('build_data')
            )
            tests_to_remove.extend(to_remove)
            tests_to_add.extend(to_add)

    # Add all new test functions
    [setattr(cls, name, func) for name, func in tests_to_add]

    # Remove all old test function templates (if they still exist)
    [delattr(cls, key) for key in tests_to_remove if hasattr(cls, key)]
    return cls


def parameterized_dataset(build_data):
    """Simple decorator to mark a test method for processing."""
    def decorator(func):
        func.__dict__['build_data'] = build_data
        return func
    return decorator


def create_timestamp_w_tz_and_offset(timezone=None, days=0, hours=0, minutes=0,
                                     seconds=0):
    """Creates a timestamp with a timezone and offset in days

    :param timezone: Timezone used in creation of timestamp
    :param days: The offset in days
    :param hours: The offset in hours
    :param minutes: The offset in minutes

    :return a timestamp
    """
    if timezone is None:
        timezone = time.strftime("%z")

    timestamp = '{time}{timezone}'.format(
        time=(datetime.datetime.today() + datetime.timedelta(days=days,
                                                             hours=hours,
                                                             minutes=minutes,
                                                             seconds=seconds)),
        timezone=timezone)

    return timestamp


def get_limit_and_offset_from_ref(ref):
    matches = dict(urlparse.parse_qsl(urlparse.urlparse(ref).query))
    ref_limit = matches['limit']
    ref_offset = matches['offset']

    return ref_limit, ref_offset


def get_tomorrow_timestamp():
    tomorrow = (datetime.today() + datetime.timedelta(days=1))
    return tomorrow.isoformat()


def string_to_datetime(datetimestring, date_formats=None):
    date_formats = date_formats or [
        '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%S.%f', "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"]

    for dateformat in date_formats:
        try:
            return datetime.datetime.strptime(datetimestring, dateformat)
        except ValueError:
            continue
    else:
        raise


def get_id_from_ref(ref):
    """Returns id from reference."""
    ref_id = None
    if ref is not None and len(ref) > 0:
        ref_id = path.split(ref)[1]
    return ref_id
