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

    def get_ca(self, ca_ref, extra_headers=None):
        """Handles getting a CA

        :param ca_ref: href for a CA
        :param extra_headers: extra HTTP headers for the GET request
        :return: a request Response object
        """
        return self.client.get(ca_ref,
                               response_model_type=ca_models.CAModel,
                               extra_headers=extra_headers)

    def get_cacert(self, ca_ref, payload_content_type,
                   payload_content_encoding=None, extra_headers=None,
                   use_auth=True, user_name=None):
        headers = {'Accept': payload_content_type,
                   'Accept-Encoding': payload_content_encoding}
        if extra_headers:
            headers.update(extra_headers)

        return self.client.get(ca_ref + '/cacert',
                               extra_headers=headers, use_auth=use_auth,
                               user_name=user_name)

    def get_cas(self, limit=10, offset=0):
        """Handles getting a list of CAs.

        :param limit: limits number of returned CAs
        :param offset: represents how many records to skip before retrieving
                       the list
        :return: the response, a list of cas, total number of cas, next and
                 prev references
        """
        resp = self.client.get('cas', params={'limit': limit,
                                              'offset': offset})

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
