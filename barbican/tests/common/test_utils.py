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
import mock
from oslo_config import cfg
import six

from barbican.common import config
from barbican.common import utils
from barbican.tests import utils as test_utils


class WhenTestingHostnameForRefsGetter(test_utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingHostnameForRefsGetter, self).setUp()

        self.host = 'host'
        self.version = 'version'
        self.external_project_id = 'external_project_id'
        self.resource = 'resource'

        self._old_host = utils.CONF.host_href
        self._old_version = utils.API_VERSION
        utils.CONF.set_override('host_href', self.host, enforce_type=True)
        utils.API_VERSION = self.version

    def tearDown(self):
        super(WhenTestingHostnameForRefsGetter, self).tearDown()
        utils.CONF.clear_override('host_href')
        utils.API_VERSION = self._old_version

    def test_hostname_for_refs(self):
        uri = utils.hostname_for_refs(resource=self.resource)
        self.assertEqual("{0}/{1}/{2}".format(self.host, self.version,
                                              self.resource), uri)

    def test_hostname_for_refs_no_resource(self):
        uri = utils.hostname_for_refs()
        self.assertEqual("{0}/{1}".format(self.host, self.version), uri)


class WhenTestingAcceptEncodingGetter(test_utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingAcceptEncodingGetter, self).setUp()

        self.req = mock.Mock()

    def test_parses_accept_encoding_header(self):
        self.req.get_header.return_value = '*'
        ae = utils.get_accepted_encodings(self.req)
        self.req.get_header.assert_called_once_with('Accept-Encoding')
        self.assertEqual(['*'], ae)

    def test_returns_none_for_empty_encoding(self):
        self.req.get_header.return_value = None
        ae = utils.get_accepted_encodings(self.req)
        self.assertIsNone(ae)

    def test_parses_single_accept_with_quality_value(self):
        self.req.get_header.return_value = 'base64;q=0.7'
        ae = utils.get_accepted_encodings(self.req)
        self.assertEqual(['base64'], ae)

    def test_parses_more_than_one_encoding(self):
        self.req.get_header.return_value = 'base64, gzip'
        ae = utils.get_accepted_encodings(self.req)
        self.assertEqual(['base64', 'gzip'], ae)

    def test_can_sort_by_quality_value(self):
        self.req.get_header.return_value = 'base64;q=0.5, gzip;q=0.6, compress'
        ae = utils.get_accepted_encodings(self.req)
        self.assertEqual(['compress', 'gzip', 'base64'], ae)

    def test_returns_none_on_invalid_quality_type(self):
        self.req.get_header.return_value = 'base64;q=three'
        ae = utils.get_accepted_encodings(self.req)
        self.assertIsNone(ae)

    def test_returns_none_on_quality_too_large(self):
        self.req.get_header.return_value = 'base64;q=1.1'
        ae = utils.get_accepted_encodings(self.req)
        self.assertIsNone(ae)

    def test_returns_none_on_quality_too_small(self):
        self.req.get_header.return_value = 'base64;q=-0.1'
        ae = utils.get_accepted_encodings(self.req)
        self.assertIsNone(ae)

    def test_ignores_encoding_with_zero_quality_value(self):
        self.req.get_header.return_value = 'base64;q=0.5, gzip;q=0.0, compress'
        ae = utils.get_accepted_encodings(self.req)
        self.assertEqual(['compress', 'base64'], ae)


class WhenTestingGenerateFullClassnameForInstance(test_utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingGenerateFullClassnameForInstance, self).setUp()

        self.instance = test_utils.DummyClassForTesting()

    def test_get_fullname_for_null_instance_raises_exception(self):
        self.assertRaises(ValueError, utils.generate_fullname_for, None)

    def test_get_fullname_for_string_doesnt_include_module(self):
        test_string = "foo"
        fullname = utils.generate_fullname_for(test_string)
        self.assertEqual(0, fullname.count("."))
        self.assertNotIn(six.moves.builtins.__name__, fullname)

    def test_returns_class_name_on_null_module(self):
        self.instance.__class__.__module__ = None
        name = utils.generate_fullname_for(self.instance)
        self.assertEqual('DummyClassForTesting', name)

    def test_returns_qualified_name(self):
        self.instance.__class__.__module__ = 'dummy'
        name = utils.generate_fullname_for(self.instance)
        self.assertEqual('dummy.DummyClassForTesting', name)


class TestConfigValues(test_utils.BaseTestCase):

    def setUp(self):
        super(TestConfigValues, self).setUp()
        self.barbican_config = config.CONF
        self.oslo_config = cfg.CONF

    def test_barbican_conf_values_made_visible_to_oslo_conf(self):
        """In this, checking oslo CONF values are same as barbican config

        This tests shows that after the change values referenced via
        oslo_config.cfg.CONF value are same as
        barbican.common.config.CONF.
        """

        # Checking that 'admin_role' value referred via
        # barbican.common.config.CONF is same as oslo_config.cfg.CONF
        self.assertEqual('admin', self.barbican_config._get('admin_role'))
        self.assertEqual('admin', self.barbican_config.admin_role)

        self.assertEqual('admin', self.oslo_config._get('admin_role'))
        self.assertEqual('admin', self.oslo_config.admin_role)

        # No error in getting 'project' value from both config reading
        # mechanism
        self.assertEqual('barbican', self.barbican_config.project)
        self.assertEqual('barbican', self.oslo_config.project)
