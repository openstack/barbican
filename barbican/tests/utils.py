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
import uuid

import mock
import oslotest.base as oslotest
import six
from six.moves.urllib import parse
import webtest

from OpenSSL import crypto

from barbican.api import app
import barbican.context
from barbican.tests import database_utils


class BarbicanAPIBaseTestCase(oslotest.BaseTestCase):
    """Base TestCase for all tests needing to interact with a Barbican app."""
    root_controller = None

    def _build_context(self, project_id, roles=None, user=None, is_admin=True,
                       policy_enforcer=None):
        context = barbican.context.RequestContext(
            roles=roles,
            user=user,
            project=project_id,
            is_admin=is_admin
        )
        context.policy_enforcer = policy_enforcer
        return context

    def setUp(self):
        super(BarbicanAPIBaseTestCase, self).setUp()
        # Make sure we have a test db and session to work with
        database_utils.setup_in_memory_db()

        # Generic project id to perform actions under
        self.project_id = str(uuid.uuid4())

        # Build the test app
        wsgi_app = app.build_wsgi_app(
            controller=self.root_controller,
            transactional=True
        )

        self.app = webtest.TestApp(wsgi_app)
        self.app.extra_environ = {
            'barbican.context': self._build_context(self.project_id)
        }

    def tearDown(self):
        database_utils.in_memory_cleanup()
        super(BarbicanAPIBaseTestCase, self).tearDown()


class BaseTestCase(oslotest.BaseTestCase):
    """DEPRECATED - Will remove in future refactoring."""
    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.order_id = 'order1234'
        self.external_project_id = 'keystone1234'
        self.request_id = 'request1234'

    def tearDown(self):
        super(BaseTestCase, self).tearDown()


class MockModelRepositoryMixin(object):
    """Class for setting up the repo factory mocks

    This class has the purpose of setting up the mocks for the model repository
    factory functions. This is because they are intended to be singletons, and
    thus called inside the code-base, and not really passed around as
    arguments. Thus, this kind of approach is needed.

    The functions assume that the class that inherits from this is a test case
    fixture class. This is because as a side-effect patcher objects will be
    added to the class, and also the cleanup of these patcher objects will be
    added to the tear-down of the respective classes.
    """

    def setup_container_consumer_repository_mock(
            self, mock_container_consumer_repo=mock.MagicMock()):
        """Mocks the container consumer repository factory function

        :param mock_container_consumer_repo: The pre-configured mock
                                             container consumer repo to be
                                             returned.
        """
        self.mock_container_consumer_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_container_consumer_repository',
            mock_repo_obj=mock_container_consumer_repo,
            patcher_obj=self.mock_container_consumer_repo_patcher)

    def setup_container_repository_mock(self,
                                        mock_container_repo=mock.MagicMock()):
        """Mocks the container repository factory function

        :param mock_container_repo: The pre-configured mock
                                    container repo to be returned.
        """
        self.mock_container_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_container_repository',
            mock_repo_obj=mock_container_repo,
            patcher_obj=self.mock_container_repo_patcher)

    def setup_container_secret_repository_mock(
            self, mock_container_secret_repo=mock.MagicMock()):
        """Mocks the container-secret repository factory function

        :param mock_container_secret_repo: The pre-configured mock
                                           container-secret repo to be
                                           returned.
        """
        self.mock_container_secret_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_container_secret_repository',
            mock_repo_obj=mock_container_secret_repo,
            patcher_obj=self.mock_container_secret_repo_patcher)

    def setup_encrypted_datum_repository_mock(
            self, mock_encrypted_datum_repo=mock.MagicMock()):
        """Mocks the encrypted datum repository factory function

        :param mock_encrypted_datum_repo: The pre-configured mock
                                          encrypted datum repo to be returned.
        """
        self.mock_encrypted_datum_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_encrypted_datum_repository',
            mock_repo_obj=mock_encrypted_datum_repo,
            patcher_obj=self.mock_encrypted_datum_repo_patcher)

    def setup_kek_datum_repository_mock(self,
                                        mock_kek_datum_repo=mock.MagicMock()):
        """Mocks the kek datum repository factory function

        :param mock_kek_datum_repo: The pre-configured mock kek-datum repo to
                                    be returned.
        """
        self.mock_kek_datum_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_kek_datum_repository',
            mock_repo_obj=mock_kek_datum_repo,
            patcher_obj=self.mock_kek_datum_repo_patcher)

    def setup_order_barbican_meta_repository_mock(
            self, mock_order_barbican_meta_repo=mock.MagicMock()):
        """Mocks the order-barbican-meta repository factory function

        :param mock_order_barbican_meta_repo: The pre-configured mock order
                                              barbican-meta repo to be
                                              returned.
        """
        self.mock_order_barbican_meta_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_order_barbican_meta_repository',
            mock_repo_obj=mock_order_barbican_meta_repo,
            patcher_obj=self.mock_order_barbican_meta_repo_patcher)

    def setup_order_plugin_meta_repository_mock(
            self, mock_order_plugin_meta_repo=mock.MagicMock()):
        """Mocks the order-plugin-meta repository factory function

        :param mock_order_plugin_meta_repo: The pre-configured mock order
                                            plugin-meta repo to be returned.
        """
        self.mock_order_plugin_meta_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_order_plugin_meta_repository',
            mock_repo_obj=mock_order_plugin_meta_repo,
            patcher_obj=self.mock_order_plugin_meta_repo_patcher)

    def setup_order_repository_mock(self, mock_order_repo=mock.MagicMock()):
        """Mocks the order repository factory function

        :param mock_order_repo: The pre-configured mock order repo to be
                                returned.
        """
        self.mock_order_repo_patcher = None
        self._setup_repository_mock(repo_factory='get_order_repository',
                                    mock_repo_obj=mock_order_repo,
                                    patcher_obj=self.mock_order_repo_patcher)

    def setup_project_repository_mock(self,
                                      mock_project_repo=mock.MagicMock()):
        """Mocks the project repository factory function

        :param mock_project_repo: The pre-configured mock project repo to be
                                  returned.
        """
        self.mock_project_repo_patcher = None
        self._setup_repository_mock(repo_factory='get_project_repository',
                                    mock_repo_obj=mock_project_repo,
                                    patcher_obj=self.mock_project_repo_patcher)

    def setup_secret_meta_repository_mock(
            self, mock_secret_meta_repo=mock.MagicMock()):
        """Mocks the secret-meta repository factory function

        :param mock_secret_meta_repo: The pre-configured mock secret-meta repo
                                      to be returned.
        """
        self.mock_secret_meta_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_secret_meta_repository',
            mock_repo_obj=mock_secret_meta_repo,
            patcher_obj=self.mock_secret_meta_repo_patcher)

    def setup_secret_repository_mock(self, mock_secret_repo=mock.MagicMock()):
        """Mocks the secret repository factory function

        :param mock_secret_repo: The pre-configured mock secret repo to be
                                 returned.
        """
        self.mock_secret_repo_patcher = None
        self._setup_repository_mock(repo_factory='get_secret_repository',
                                    mock_repo_obj=mock_secret_repo,
                                    patcher_obj=self.mock_secret_repo_patcher)

    def setup_transport_key_repository_mock(
            self, mock_transport_key_repo=mock.MagicMock()):
        """Mocks the transport-key repository factory function

        :param mock_transport_key_repo: The pre-configured mock transport_key
                                        repo to be returned.
        """
        self.mock_transport_key_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_transport_key_repository',
            mock_repo_obj=mock_transport_key_repo,
            patcher_obj=self.mock_transport_key_repo_patcher)

    def setup_ca_repository_mock(self, mock_ca_repo=mock.MagicMock()):
        """Mocks the project repository factory function

        :param mock_ca_repo: The pre-configured mock ca repo to be returned.
        """
        self.mock_ca_repo_patcher = None
        self._setup_repository_mock(repo_factory='get_ca_repository',
                                    mock_repo_obj=mock_ca_repo,
                                    patcher_obj=self.mock_ca_repo_patcher)

    def setup_preferred_ca_repository_mock(
            self, mock_preferred_ca_repo=mock.MagicMock()):
        """Mocks the project repository factory function

        :param mock_preferred_ca_repo: The pre-configured mock project ca repo
                                     to be returned.
        """
        self.mock_preferred_ca_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_preferred_ca_repository',
            mock_repo_obj=mock_preferred_ca_repo,
            patcher_obj=self.mock_preferred_ca_repo_patcher)

    def setup_project_ca_repository_mock(
            self, mock_project_ca_repo=mock.MagicMock()):
        """Mocks the project repository factory function

        :param mock_project_ca_repo: The pre-configured mock project ca repo
                                     to be returned.
        """
        self.mock_project_ca_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_project_ca_repository',
            mock_repo_obj=mock_project_ca_repo,
            patcher_obj=self.mock_project_ca_repo_patcher)

    def _setup_repository_mock(self, repo_factory, mock_repo_obj, patcher_obj):
        patcher_obj = mock.patch(
            'barbican.model.repositories.' + repo_factory,
            return_value=mock_repo_obj
        )
        patcher_obj.start()
        self.addCleanup(patcher_obj.stop)


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

    for key, val in original_func.__dict__.items():
        if key != 'build_data':
            new_func.__dict__[key] = val

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

    for subtest_name, params in build_data.items():
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
    for key, val in vars(cls).items():
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
    matches = dict(parse.parse_qsl(parse.urlparse(ref).query))
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


def generate_test_uuid(tail_value=0):
    """Returns a blank uuid with the given value added to the end segment."""
    return '00000000-0000-0000-0000-{value:0>{pad}}'.format(value=tail_value,
                                                            pad=12)


def get_symmetric_key():
    s = "MIICdgIBADANBgkqhkiG9w=="
    return s


def get_triple_des_key():
    s = "AQIDBAUGBwgBAgMEBQYHCAECAwQFBgcI"
    return s


def is_cert_valid(expected, observed):
    c1 = crypto.load_certificate(crypto.FILETYPE_PEM, expected)
    c2 = crypto.load_certificate(crypto.FILETYPE_PEM, observed)
    return (crypto.dump_certificate(crypto.FILETYPE_PEM, c1) ==
            crypto.dump_certificate(crypto.FILETYPE_PEM, c2))


def is_private_key_valid(expected, observed):
    k1 = crypto.load_privatekey(crypto.FILETYPE_PEM, expected)
    k2 = crypto.load_privatekey(crypto.FILETYPE_PEM, observed)
    return (crypto.dump_privatekey(crypto.FILETYPE_PEM, k1) ==
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k2))


def is_public_key_valid(expected, observed):
    # TODO(alee) fill in the relevant test here
    return True


class DummyClassForTesting(object):
    pass
