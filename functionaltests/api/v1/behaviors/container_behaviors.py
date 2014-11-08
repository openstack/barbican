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

from functionaltests.api.v1.behaviors import base_behaviors
from functionaltests.api.v1.models import container_models


class ContainerBehaviors(base_behaviors.BaseBehaviors):

    def create_container(self, model, extra_headers=None):
        """Create a container from the data in the model.

        :param model: The metadata used to create the container
        :param extra_headers: Headers used to create the container

        :return: A tuple containing the response from the create
        and the href to the newly created container
        """

        resp = self.client.post('containers', request_model=model,
                                extra_headers=extra_headers)

        returned_data = resp.json()
        container_ref = returned_data.get('container_ref')
        if container_ref:
            self.created_entities.append(container_ref)
        return resp, container_ref

    def get_container(self, container_ref, extra_headers=None):
        """Handles getting a single container

        :param container_ref: Reference to the container to be retrieved
        :param extra_headers: Headers used to get the container

        :return: The response of the GET.
        """
        resp = self.client.get(
            container_ref, response_model_type=container_models.ContainerModel)

        return resp

    def get_containers(self, limit=10, offset=0, extra_headers=None):
        """Handles getting a list of containers.

        :param limit: limits number of returned containers
        :param offset: represents how many records to skip before retrieving
            the list
        :param extra_headers: Extra headers used to retrieve a list of
            containers

        :return: Returns the response, a list of container models, and
            references to the next and previous list of containers.
        """
        params = {'limit': limit, 'offset': offset}
        resp = self.client.get('containers', params=params)

        container_list = resp.json()

        containers, next_ref, prev_ref = self.client.get_list_of_models(
            container_list, container_models.ContainerModel)

        return resp, containers, next_ref, prev_ref

    def delete_container(self, container_ref, extra_headers=None,
                         expected_fail=False):
        """Handles deleting a containers.

        :param container_ref: Reference of the container to be deleted
        :param extra_headers: Any additional headers needed.
        :param expected_fail: If there is a negative test, this should be
            marked true if you are trying to delete a container that does
            not exist.
        :return: Response of the delete.
        """
        resp = self.client.delete(container_ref, extra_headers)

        if not expected_fail:
            self.created_entities.remove(container_ref)

        return resp

    def delete_all_created_containers(self):
        """Delete all of the containers that we have created."""
        containers_to_delete = [container for container
                                in self.created_entities]

        for container_ref in containers_to_delete:
            self.delete_container(container_ref)
