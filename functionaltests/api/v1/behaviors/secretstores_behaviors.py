# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from functionaltests.api.v1.behaviors import base_behaviors


class SecretStoresBehaviors(base_behaviors.BaseBehaviors):

    def get_all_secret_stores(self, extra_headers=None, use_auth=True,
                              user_name=None):
        """Retrieves list of secret stores available in barbican"""
        resp = self.client.get('secret-stores',
                               extra_headers=extra_headers,
                               use_auth=use_auth, user_name=user_name)
        json_data = None
        if resp.status_code == 200:
            json_data = self.get_json(resp)

        return resp, json_data

    def get_global_default(self, extra_headers=None, use_auth=True,
                           user_name=None):
        """Retrieves global default secret store."""

        resp = self.client.get('secret-stores/global-default',
                               extra_headers=extra_headers, use_auth=use_auth,
                               user_name=user_name)
        json_data = None
        if resp.status_code == 200:
            json_data = self.get_json(resp)

        return resp, json_data

    def get_project_preferred_store(self, extra_headers=None, use_auth=True,
                                    user_name=None):
        """Retrieve global default secret store."""

        resp = self.client.get('secret-stores/preferred',
                               extra_headers=extra_headers, use_auth=use_auth,
                               user_name=user_name)
        json_data = None
        if resp.status_code == 200:
            json_data = self.get_json(resp)

        return resp, json_data

    def get_a_secret_store(self, secret_store_ref, extra_headers=None,
                           use_auth=True, user_name=None):
        """Retrieve a specific secret store."""

        resp = self.client.get(secret_store_ref, extra_headers=extra_headers,
                               use_auth=use_auth, user_name=user_name)
        json_data = None
        if resp.status_code == 200:
            json_data = self.get_json(resp)

        return resp, json_data

    def set_preferred_secret_store(self, secret_store_ref,
                                   extra_headers=None, use_auth=True,
                                   user_name=None):
        """Set a preferred secret store."""
        project_id = None
        try:
            if user_name:
                project_id = self.client.get_project_id_from_name(user_name)
        except Exception:
            pass

        resp = self.client.post(secret_store_ref + '/preferred',
                                extra_headers=extra_headers,
                                use_auth=use_auth, user_name=user_name)
        if resp.status_code == 204 and project_id:
            # add tuple of store ref, user_name to cleanup later
            self.created_entities.append((secret_store_ref, user_name))

        return resp

    def unset_preferred_secret_store(self, secret_store_ref,
                                     extra_headers=None, use_auth=True,
                                     user_name=None):
        """Unset a preferred secret store."""

        return self.client.delete(secret_store_ref + '/preferred',
                                  extra_headers=extra_headers,
                                  use_auth=use_auth, user_name=user_name)

    def cleanup_preferred_secret_store_entities(self):
        for (store_ref, user_name) in self.created_entities:
            self.unset_preferred_secret_store(store_ref, user_name=user_name)
