"""
Copyright 2015 Cisco Systems

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
from functionaltests.api.v1.models import quota_models


class QuotaBehaviors(base_behaviors.BaseBehaviors):

    def get_quotas(self, extra_headers=None,
                   use_auth=True, user_name=None):
        """Handles getting quotas

        :param extra_headers: extra HTTP headers for the REST request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used for REST command
        :return: a request Response object
        """
        resp = self.client.get(
            'quotas', response_model_type=quota_models.QuotasResponseModel,
            extra_headers=extra_headers,
            use_auth=use_auth, user_name=user_name)
        return resp

    def get_project_quotas_list(self, limit=10, offset=0, extra_headers=None,
                                use_auth=True, user_name=None):
        """Handles getting project quotas

        :param limit: limits number of returned orders (default 10)
        :param offset: represents how many records to skip before retrieving
                       the list (default 0)
        :param extra_headers: extra HTTP headers for the REST request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used for REST command
        :return: the response, a list of project quotas and the next/prev refs
        """
        params = {'limit': limit, 'offset': offset}
        resp = self.client.get(
            'project-quotas',
            response_model_type=quota_models.ProjectQuotaListModel,
            params=params,
            extra_headers=extra_headers,
            use_auth=use_auth, user_name=user_name)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None, None, None

        project_quotas_list = self.get_json(resp)
        project_quotas, next_ref, prev_ref = self.client.get_list_of_models(
            project_quotas_list, quota_models.ProjectQuotaListItemModel)

        return resp, project_quotas, next_ref, prev_ref

    def get_project_quotas(self, project_id, extra_headers=None,
                           use_auth=True, user_name=None):
        """Handles getting project quotas

        :param extra_headers: extra HTTP headers for the REST request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used for REST command
        :return: a request Response object
        """
        resp = self.client.get(
            'project-quotas/' + project_id,
            response_model_type=quota_models.ProjectQuotaOneModel,
            extra_headers=extra_headers,
            use_auth=use_auth, user_name=user_name)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None, None, None

        return resp

    def set_project_quotas(self, project_id, request_model, extra_headers=None,
                           use_auth=True, user_name=None):
        """Handles setting project quotas

        :param project_id: id of project whose quotas are to be set
        :param extra_headers: extra HTTP headers for the REST request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used for REST command
        :return: a request Response object
        """
        resp = self.client.put(
            'project-quotas/' + project_id,
            request_model=request_model,
            extra_headers=extra_headers,
            use_auth=use_auth, user_name=user_name)

        if resp.status_code == 204:
            self.created_entities.append((project_id, user_name))

        return resp

    def delete_project_quotas(self, project_id, extra_headers=None,
                              expected_fail=False,
                              use_auth=True, user_name=None):
        """Handles deleting project quotas

        :param project_id: id of project whose quotas are to be deleted
        :param extra_headers: extra HTTP headers for the REST request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used for REST command
        :return: a request Response object
        """
        resp = self.client.delete('project-quotas/' + project_id,
                                  extra_headers=extra_headers,
                                  use_auth=use_auth, user_name=user_name)

        if resp.status_code == 204:
            for item in self.created_entities:
                if item[0] == project_id:
                    self.created_entities.remove(item)

        return resp

    def delete_all_created_quotas(self):
        """Delete all of the project_quotas that we have created."""
        entities = list(self.created_entities)
        for (acl_ref, user_name) in entities:
            self.delete_project_quotas(acl_ref, user_name=user_name)
