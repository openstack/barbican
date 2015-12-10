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
from functionaltests.api.v1.models import consumer_model


class ConsumerBehaviors(base_behaviors.BaseBehaviors):

    def create_consumer(self, model, container_ref, extra_headers=None,
                        user_name=None, admin=None, use_auth=True):
        """Register a consumer to a container.

        :param model: The metadata for the consumer
        :param container_ref: Full reference to a container
        :param extra_headers: Any additional headers to pass to the request
        :param user_name: The user name used to create the consumer
        :param admin: The user with permission to delete the consumer
        :param use_auth: Boolean for whether to send authentication headers

        :return: A tuple containing the response from the create
        and the href to the newly registered consumer
        """

        url = '{0}/consumers'.format(container_ref)

        resp = self.client.post(url, request_model=model,
                                extra_headers=extra_headers,
                                user_name=user_name, use_auth=use_auth)

        if resp.status_code == 401 and not use_auth:
            return resp, None

        if resp.status_code == 200:
            if admin is None:
                admin = user_name
            self.created_entities.append((container_ref, model, admin))

        returned_data = self.get_json(resp)
        consumer_data = returned_data.get('consumers')

        return resp, consumer_data

    def get_consumers(self, container_ref, limit=10, offset=0,
                      extra_headers=None,
                      user_name=None, use_auth=True):
        """Gets a list of consumers on a container.

        :param container_ref: Full reference to a container
        :param limit: limits number of returned consumers
        :param offset: represents how many records to skip before retrieving
            the list
        :param extra_headers: Any additional headers to pass to the request
        :param user_name: The user name used to get the consumer
        :param use_auth: Boolean for whether to send authentication headers

        :return: The response from the get and refs to the next/previous list
            of consumers
        """

        url = '{0}/consumers'.format(container_ref)

        params = {'limit': limit, 'offset': offset}
        resp = self.client.get(url, params=params, extra_headers=extra_headers,
                               user_name=user_name, use_auth=use_auth)

        if resp.status_code == 401 and not use_auth:
            return resp, None, None, None

        consumer_list = self.get_json(resp)

        consumers, next_ref, prev_ref = self.client.get_list_of_models(
            consumer_list, consumer_model.ConsumerModel)

        return resp, consumers, next_ref, prev_ref

    def delete_consumer(self, model, container_ref, extra_headers=None,
                        user_name=None, use_auth=True):
        """Deletes a consumer from a container.

        :param model: The metadata for the consumer
        :param container_ref: Full reference to a container
        :param extra_headers: Any additional headers to pass to the request
        :param user_name: The user name used to delete the consumer
        :param use_auth: Boolean for whether to send authentication headers

        :return: The response from the delete
        """
        url = '{0}/consumers'.format(container_ref)

        resp = self.client.delete(url, request_model=model,
                                  extra_headers=extra_headers,
                                  user_name=user_name,
                                  use_auth=use_auth)

        if resp.status_code == 401 and not use_auth:
            return resp, None

        if resp.status_code != 200:
            return resp, None

        returned_data = self.get_json(resp)
        consumer_data = returned_data['consumers']

        return resp, consumer_data

    def delete_all_created_consumers(self):
        """Delete all of the consumers that we have created."""
        entities = list(self.created_entities)
        for (container_ref, model, admin) in entities:
            self.delete_consumer(model, container_ref, user_name=admin)
