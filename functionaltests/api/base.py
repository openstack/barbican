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
from tempest import auth
from tempest import clients
from tempest.common import rest_client
from tempest import config
import testtools

CONF = config.CONF


class BarbicanClient(rest_client.RestClient):

    def __init__(self, auth_provider):
        super(BarbicanClient, self).__init__(auth_provider)

        # get the project id (aka tenant id) which we need in the API tests
        # to build the correct URI.
        credentials = auth_provider.fill_credentials()
        self.project_id = credentials.tenant_id

        self.service = 'keystore'
        self.endpoint_url = 'publicURL'


class TestCase(testtools.TestCase):

    def setUp(self):
        super(TestCase, self).setUp()

        credentials = BarbicanCredentials()

        mgr = clients.Manager(credentials=credentials)
        auth_provider = mgr.get_auth_provider(credentials)
        self.client = BarbicanClient(auth_provider)


class BarbicanCredentials(auth.KeystoneV2Credentials):

    def __init__(self):
        credentials = dict(
            username=CONF.identity.admin_username,
            password=CONF.identity.admin_password,
            tenant_name=CONF.identity.admin_tenant_name
        )

        super(BarbicanCredentials, self).__init__(**credentials)
