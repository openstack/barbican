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
from functionaltests.api.v1.models import acl_models


class AclBehaviors(base_behaviors.BaseBehaviors):

    def create_acl(self, entity_ref, model, extra_headers=None,
                   use_auth=True, user_name=None):
        """Create an acl from the data in the model.

        :param entity_ref: ref of secret or container for acl
        :param model: The metadata used to create the acl
        :param extra_headers: Headers used to create the acl
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to create the acl

        :return: the response from the PUT request
        """

        acl_ref = '{0}/acl'.format(entity_ref)
        resp = self.client.put(acl_ref, request_model=model,
                               extra_headers=extra_headers, use_auth=use_auth,
                               user_name=user_name)

        self.created_entities.append((acl_ref, user_name))
        return resp

    def get_acl(self, acl_ref, extra_headers=None, use_auth=True,
                user_name=None):
        """Handles getting a single acl

        :param acl_ref: Reference to the acl to be retrieved
        :param extra_headers: Headers used to get the acl
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to get the acl

        :return: The response of the GET.
        """
        resp = self.client.get(
            acl_ref, response_model_type=acl_models.AclModel,
            use_auth=use_auth, user_name=user_name)
        return resp

    def update_acl(self, acl_ref, model, extra_headers=None,
                   use_auth=True, user_name=None):
        """Update an acl from the data in the model.

        :param acl_ref: Reference of the acl to be updated
        :param model: The metadata used to update the acl
        :param extra_headers: Headers used to update the acl
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to update the acl

        :return: the response from the PATCH request
        """
        resp = self.client.patch(
            acl_ref, request_model=model, extra_headers=extra_headers,
            response_model_type=acl_models.AclModel,
            use_auth=use_auth, user_name=user_name)

        return resp

    def delete_acl(self, acl_ref, extra_headers=None,
                   expected_fail=False, use_auth=True, user_name=None):
        """Handles deleting an acl.

        :param acl_ref: Reference of the acl to be deleted
        :param extra_headers: Any additional headers needed.
        :param expected_fail: If there is a negative test, this should be
            marked true if you are trying to delete an acl that does
            not exist.
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to delete the acl

        :return: Response of the delete.
        """
        resp = self.client.delete(acl_ref, extra_headers, use_auth=use_auth,
                                  user_name=user_name)

        if not expected_fail:
            for item in self.created_entities:
                if item[0] == acl_ref:
                    self.created_entities.remove(item)

        return resp

    def delete_all_created_acls(self):
        """Delete all of the acls that we have created."""
        entities = list(self.created_entities)
        for (acl_ref, user_name) in entities:
            self.delete_acl(acl_ref, user_name=user_name)
