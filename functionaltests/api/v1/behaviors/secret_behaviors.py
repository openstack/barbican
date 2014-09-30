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
from functionaltests.api.v1.behaviors.base_behaviors import BaseBehaviors
from functionaltests.api.v1.models import secret_models


class SecretBehaviors(BaseBehaviors):

    def create_secret(self, model):
        """Create a secret from the data in the model.

        :param model: The metadata used to create the secret
        :return: A tuple containing the response from the create
        and the href to the newly created secret
        """
        resp = self.client.post('secrets', request_model=model)

        returned_data = resp.json()
        secret_ref = returned_data.get('secret_ref')
        if secret_ref:
            self.created_entities.append(secret_ref)
        return resp, secret_ref

    def update_secret_payload(self, secret_ref, payload, content_type):
        """Updates a secret's payload data

        :param secret_ref: HATEOS ref of the secret to be deleted
        :return: A request response object
        """
        headers = {'Content-Type': content_type}
        return self.client.put(secret_ref, data=payload, extra_headers=headers)

    def get_secret_metadata(self, secret_ref):
        """Retrieves a secret's metadata

        :param secret_ref: HATEOS ref of the secret to be deleted
        :return: A request response object
        """
        return self.client.get(
            secret_ref, response_model_type=secret_models.SecretModel)

    def delete_secret(self, secret_ref, extra_headers=None):
        """Delete a secret.

        :param secret_ref: HATEOS ref of the secret to be deleted
        :param extra_headers: Optional HTTP headers to add to the request
        :return: A request response object
        """
        resp = self.client.delete(secret_ref, extra_headers=extra_headers)
        self.created_entities.remove(secret_ref)
        return resp

    def delete_all_created_secrets(self):
        """Delete all of the secrets that we have created."""
        for secret_ref in self.created_entities:
            self.delete_secret(secret_ref)
