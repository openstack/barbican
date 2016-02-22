"""
Copyright 2014-2015 Rackspace

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
from functionaltests.api.v1.models import secret_models


class SecretBehaviors(base_behaviors.BaseBehaviors):

    def create_secret(self, model, extra_headers=None, omit_headers=None,
                      use_auth=True, user_name=None, admin=None):
        """Create a secret from the data in the model.

        :param model: The metadata used to create the secret
        :param extra_headers: Optional HTTP headers to add to the request
        :param omit_headers: headers to delete before making the request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to create the secret
        :param admin: The user with permissions to delete the secrets
        :return: A tuple containing the response from the create
        and the href to the newly created secret
        """

        resp = self.client.post('secrets', request_model=model,
                                extra_headers=extra_headers,
                                omit_headers=omit_headers, use_auth=use_auth,
                                user_name=user_name)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None

        returned_data = self.get_json(resp)
        secret_ref = returned_data.get('secret_ref')
        if secret_ref:
            if admin is None:
                admin = user_name
            self.created_entities.append((secret_ref, admin))
        return resp, secret_ref

    def update_secret_payload(self, secret_ref, payload, payload_content_type,
                              payload_content_encoding=None,
                              extra_headers=None, omit_headers=None,
                              use_auth=True, user_name=None):
        """Updates a secret's payload data.

        :param secret_ref: HATEOAS ref of the secret to be updated
        :param payload: new payload to be sent to server
        :param payload_content_type: value for the Content-Type header
        :param payload_content_encoding: value for the Content-Encoding header
        :param extra_headers: Optional HTTP headers to add to the request
        :param omit_headers: headers to delete before making the request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to update the secret
        :return: the response from the PUT update
        """

        if payload_content_encoding is None:
            headers = {'Content-Type': payload_content_type}
        else:
            headers = {'Content-Type': payload_content_type,
                       'Content-Encoding': payload_content_encoding}

        if extra_headers:
            headers.update(extra_headers)

        return self.client.put(secret_ref, data=payload, extra_headers=headers,
                               omit_headers=omit_headers,
                               use_auth=use_auth, user_name=user_name)

    def get_secret(self, secret_ref, payload_content_type,
                   payload_content_encoding=None, extra_headers=None,
                   omit_headers=None, use_auth=True, user_name=None):

        headers = {'Accept': payload_content_type,
                   'Accept-Encoding': payload_content_encoding}

        if extra_headers:
            headers.update(extra_headers)

        return self.client.get(secret_ref + '/payload',
                               extra_headers=headers,
                               omit_headers=omit_headers, use_auth=use_auth,
                               user_name=user_name)

    def get_secret_based_on_content_type(self, secret_ref,
                                         payload_content_type,
                                         payload_content_encoding=None,
                                         extra_headers=None,
                                         omit_headers=None,
                                         user_name=None):
        """Retrieves a secret's payload based on the content type

        NOTE: This way will be deprecated in subsequent versions of the API.
        """

        headers = {'Accept': payload_content_type,
                   'Accept-Encoding': payload_content_encoding}

        if extra_headers:
            headers.update(extra_headers)

        return self.client.get(secret_ref, extra_headers=headers,
                               omit_headers=omit_headers, user_name=user_name)

    def get_secret_metadata(self, secret_ref, extra_headers=None,
                            omit_headers=None, use_auth=True, user_name=None):
        """Retrieves a secret's metadata.

        :param secret_ref: HATEOAS ref of the secret to be retrieved
        :param extra_headers: Optional HTTP headers to add to the request
        :param omit_headers: headers to delete before making the request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to get the metadata
        :return: A request response object
        """
        return self.client.get(
            secret_ref, extra_headers=extra_headers, omit_headers=omit_headers,
            response_model_type=secret_models.SecretModel,
            use_auth=use_auth, user_name=user_name)

    def get_secrets(self, limit=10, offset=0, filter=None,
                    extra_headers=None, omit_headers=None, use_auth=True,
                    user_name=None):
        """Handles getting a list of secrets.

        :param limit: limits number of returned secrets
        :param offset: represents how many records to skip before retrieving
                       the list
        :param filter: optional filter to limit the returned secrets to
                        those whose name matches the filter.
        :param extra_headers: Optional HTTP headers to add to the request
        :param omit_headers: headers to delete before making the request
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to list the secrets
        """
        params = {'limit': limit, 'offset': offset}
        if filter:
            params['name'] = filter
        resp = self.client.get('secrets', params=params,
                               extra_headers=extra_headers,
                               omit_headers=omit_headers,
                               use_auth=use_auth, user_name=user_name)

        # handle expected JSON parsing errors for unauthenticated requests
        if resp.status_code == 401 and not use_auth:
            return resp, None, None, None

        secrets_list = self.get_json(resp)

        secrets, next_ref, prev_ref = self.client.get_list_of_models(
            secrets_list, secret_models.SecretModel)

        return resp, secrets, next_ref, prev_ref

    def delete_secret(self, secret_ref, extra_headers=None, omit_headers=None,
                      expected_fail=False, use_auth=True, user_name=None):
        """Delete a secret.

        :param secret_ref: HATEOAS ref of the secret to be deleted
        :param extra_headers: Optional HTTP headers to add to the request
        :param omit_headers: headers to delete before making the request
        :param expected_fail: If test is expected to fail the deletion
        :param use_auth: Boolean for whether to send authentication headers
        :param user_name: The user name used to delete the secret
        :return A request response object
        """
        resp = self.client.delete(secret_ref, extra_headers=extra_headers,
                                  omit_headers=omit_headers,
                                  use_auth=use_auth, user_name=user_name)

        if not expected_fail:
            for item in self.created_entities:
                if item[0] == secret_ref:
                    self.created_entities.remove(item)

        return resp

    def delete_all_created_secrets(self):
        """Delete all of the secrets that we have created."""
        entities = list(self.created_entities)
        for (secret_ref, admin) in entities:
            self.delete_secret(secret_ref, user_name=admin)
