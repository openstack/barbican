"""
Copyright 2015 Rackspace

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
from keystoneclient.v2_0 import client as v2_client
from keystoneclient.v3 import client as v3_client
from requests import auth

STORED_AUTHENTICATION = None


class FunctionalTestAuth(auth.AuthBase):

    def __init__(self, endpoint, version, username, password,
                 project_name, project_domain):
        self.endpoint = endpoint
        self.version = version
        self.username = username
        self.password = password
        self.project_name = project_name
        self.project_domain = project_domain

        self._client = None

    @property
    def service_catalog(self):
        if not self._client:
            self.authenticate()
        return self.stored_auth.get(self.username, {}).get('service_catalog')

    @property
    def auth_client(self):
        if not self._client:
            self.authenticate()
        return self._client

    @property
    def stored_auth(self):
        global STORED_AUTHENTICATION
        if not STORED_AUTHENTICATION:
            STORED_AUTHENTICATION = {}
        return STORED_AUTHENTICATION

    def _auth_with_keystone_client(self):
        if self.version.lower() == 'v2':
            self._client = v2_client.Client(
                username=self.username,
                password=self.password,
                tenant_name=self.project_name,
                auth_url=self.endpoint
            )
            return self._client.auth_token, self._client.tenant_id

        elif self.version.lower() == 'v3':
            self._client = v3_client.Client(
                username=self.username,
                password=self.password,
                user_domain_name=self.project_domain,
                project_name=self.project_name,
                project_domain_name=self.project_domain,
                auth_url=self.endpoint
            )
            return self._client.auth_token, self._client.project_id
        else:
            raise Exception('Unknown authentication version')

    def authenticate(self):
        creds = self.stored_auth.get(self.username)

        if not creds:
            token, project_id = self._auth_with_keystone_client()
            self.stored_auth[self.username] = {
                'token': token,
                'project_id': project_id,
                'service_catalog': self._client.service_catalog,
                'user_id': self._client.auth_user_id
            }

        return self.stored_auth[self.username]

    def get_user_id(self):
        """Return the UID used by keystone to uniquely identify the user"""
        return self.authenticate()['user_id']

    def get_project_id(self):
        """Return the UID used by keystone to identify the user's project"""
        return self.authenticate()['project_id']

    def __call__(self, r):
        creds = self.authenticate()

        # modify and return the request
        r.headers['X-Project-Id'] = creds.get('project_id')
        r.headers['X-Auth-Token'] = creds.get('token')
        return r
