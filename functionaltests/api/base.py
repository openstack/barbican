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
import os

import oslotest.base as oslotest
from tempest import auth
from tempest import clients as tempest_clients
from tempest import config
from tempest.openstack.common import log as logging

from functionaltests.common import client

CONF = config.CONF

# Use local tempest conf if one is available.
# This usually means we're running tests outside of devstack
if os.path.exists('./etc/dev_tempest.conf'):
    CONF.set_config_path('./etc/dev_tempest.conf')


class TestCase(oslotest.BaseTestCase):
    max_payload_size = 10000
    max_sized_payload = 'a' * max_payload_size
    oversized_payload = 'a' * (max_payload_size + 1)
    max_field_size = 255
    max_sized_field = 'a' * max_field_size
    oversized_field = 'a' * (max_field_size + 1)

    @classmethod
    def setUpClass(cls):
        cls.LOG = logging.getLogger(cls._get_full_case_name())
        super(TestCase, cls).setUpClass()

    def setUp(self):
        self.LOG.info('Starting: %s', self._testMethodName)
        super(TestCase, self).setUp()
        credentials = BarbicanCredentials()

        mgr = tempest_clients.Manager(credentials=credentials)
        auth_provider = mgr.get_auth_provider(credentials)
        self.client = client.BarbicanClient(auth_provider)

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


class BarbicanCredentials(auth.KeystoneV3Credentials):

    def __init__(self):
        credentials = dict(
            username=CONF.identity.admin_username,
            password=CONF.identity.admin_password,
            project_name=CONF.identity.admin_tenant_name
        )

        super(BarbicanCredentials, self).__init__(**credentials)
