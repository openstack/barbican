"""
Copyright 2015 Red Hat, Inc.

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
from functionaltests.api.v1.behaviors import base_behaviors
from functionaltests.api.v1.models import ca_models


class CABehaviors(base_behaviors.BaseBehaviors):

    def get_ca(self, ca_ref, extra_headers=None,
               use_auth=True, user_name=None):
        """Handles getting a CA

        :param ca_ref: href for a CA
        :param extra_headers: extra HTTP headers for the GET request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used for request
        :return: a request Response object
        """
        return self.client.get(ca_ref,
                               response_model_type=ca_models.CAModel,
                               extra_headers=extra_headers,
                               use_auth=use_auth, user_name=user_name)

    def get_cacert(self, ca_ref, payload_content_encoding=None,
                   extra_headers=None,
                   use_auth=True, user_name=None):
        """Retrieve the CA signing certificate. """
        headers = {'Accept': 'application/octet-stream',
                   'Accept-Encoding': payload_content_encoding}
        if extra_headers:
            headers.update(extra_headers)

        return self.client.get(ca_ref + '/cacert',
                               extra_headers=headers, use_auth=use_auth,
                               user_name=user_name)

    def get_cas(self, limit=10, offset=0, user_name=None):
        """Handles getting a list of CAs.

        :param limit: limits number of returned CAs
        :param offset: represents how many records to skip before retrieving
                       the list
        :return: the response, a list of cas, total number of cas, next and
                 prev references
        """
        resp = self.client.get('cas', user_name=user_name,
                               params={'limit': limit, 'offset': offset})

        # TODO(alee) refactor to use he client's get_list_of_models()

        resp_json = self.get_json(resp)
        cas, total, next_ref, prev_ref = [], 0, None, None

        for item in resp_json:
            if 'next' == item:
                next_ref = resp_json.get('next')
            elif 'previous' == item:
                prev_ref = resp_json.get('previous')
            elif 'cas' == item:
                cas = resp_json.get('cas')
            elif 'total' == item:
                total = resp_json.get('total')

        return resp, cas, total, next_ref, prev_ref

    def create_ca(self, model, headers=None, use_auth=True,
                  user_name=None, admin=None):
        """Create a subordinate CA from the data in the model.

        :param model: The metadata used to create the subCA
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to create the subCA
        :param admin: The user with permissions to delete the subCA
        :return: A tuple containing the response from the create
        and the href to the newly created subCA
        """

        resp = self.client.post('cas', request_model=model,
                                extra_headers=headers, use_auth=use_auth,
                                user_name=user_name)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None

        returned_data = self.get_json(resp)
        ca_ref = returned_data.get('ca_ref')
        if ca_ref:
            if admin is None:
                admin = user_name
            self.created_entities.append((ca_ref, admin))
        return resp, ca_ref

    def delete_ca(self, ca_ref, extra_headers=None,
                  expected_fail=False, use_auth=True, user_name=None):
        """Delete a secret.

        :param ca_ref: HATEOAS ref of the secret to be deleted
        :param extra_headers: Optional HTTP headers to add to the request
        :param expected_fail: If test is expected to fail the deletion
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to delete the entity
        :return A request response object
        """
        resp = self.client.delete(ca_ref, extra_headers=extra_headers,
                                  use_auth=use_auth, user_name=user_name)

        if not expected_fail:
            for item in self.created_entities:
                if item[0] == ca_ref:
                    self.created_entities.remove(item)

        return resp

    def delete_all_created_cas(self):
        """Delete all of the cas that we have created."""
        entities = list(self.created_entities)
        for (ca_ref, admin) in entities:
            self.delete_ca(ca_ref, user_name=admin)

    def add_ca_to_project(self, ca_ref, headers=None, use_auth=True,
                          user_name=None):
        resp = self.client.post(ca_ref + '/add-to-project',
                                extra_headers=headers, use_auth=use_auth,
                                user_name=user_name)
        return resp

    def remove_ca_from_project(self, ca_ref, headers=None, use_auth=True,
                               user_name=None):
        resp = self.client.post(ca_ref + '/remove-from-project',
                                extra_headers=headers, use_auth=use_auth,
                                user_name=user_name)
        return resp

    def set_preferred(self, ca_ref, headers=None, use_auth=True,
                      user_name=None):
        resp = self.client.post(ca_ref + '/set-preferred',
                                extra_headers=headers, use_auth=use_auth,
                                user_name=user_name)
        return resp

    def get_preferred(self, extra_headers=None, use_auth=True,
                      user_name=None):
        resp = self.client.get('cas/preferred',
                               response_model_type=ca_models.CAModel,
                               extra_headers=extra_headers, use_auth=use_auth,
                               user_name=user_name)
        return resp

    def set_global_preferred(self, ca_ref, headers=None,
                             use_auth=True, user_name=None):
        resp = self.client.post(ca_ref + '/set-global-preferred',
                                extra_headers=headers, use_auth=use_auth,
                                user_name=user_name)
        return resp

    def unset_global_preferred(self, headers=None,
                               use_auth=True, user_name=None):
        resp = self.client.post('cas/unset-global-preferred',
                                extra_headers=headers,
                                use_auth=use_auth, user_name=user_name)
        return resp

    def get_global_preferred(self, extra_headers=None,
                             use_auth=True, user_name=None):
        resp = self.client.get('cas/global-preferred',
                               response_model_type=ca_models.CAModel,
                               extra_headers=extra_headers,
                               use_auth=use_auth, user_name=user_name)
        return resp
