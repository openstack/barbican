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
from barbican.tests import utils
from functionaltests.api.v1.behaviors import base_behaviors
from functionaltests.api.v1.models import container_models


class ContainerBehaviors(base_behaviors.BaseBehaviors):

    def create_container(self, model, extra_headers=None,
                         user_name=None, admin=None):
        """Create a container from the data in the model.

        :param model: The metadata used to create the container
        :param extra_headers: Headers used to create the container
        :param user_name: The user name used to create the container
        :param admin: The user with permissions to delete the container
        :return: A tuple containing the response from the create
        and the href to the newly created container
        """

        resp = self.client.post('containers', request_model=model,
                                extra_headers=extra_headers,
                                user_name=user_name)

        returned_data = self.get_json(resp)
        container_ref = returned_data.get('container_ref')
        if container_ref:
            if admin is None:
                admin = user_name
            self.created_entities.append((container_ref, admin))
        return resp, container_ref

    def get_container(self, container_ref, extra_headers=None, user_name=None):
        """Handles getting a single container

        :param container_ref: Reference to the container to be retrieved
        :param extra_headers: Headers used to get the container
        :param user_name: The user name used to get the container

        :return: The response of the GET.
        """
        resp = self.client.get(
            container_ref, response_model_type=container_models.ContainerModel,
            user_name=user_name, extra_headers=extra_headers)

        return resp

    def get_containers(self, limit=10, offset=0, filter=None,
                       extra_headers=None, user_name=None):
        """Handles getting a list of containers.

        :param limit: limits number of returned containers
        :param offset: represents how many records to skip before retrieving
            the list
        :param filter: allows you to filter results based on name
        :param extra_headers: Extra headers used to retrieve a list of
            containers
        :param user_name: The user name used to get the list

        :return: Returns the response, a list of container models, and
            references to the next and previous list of containers.
        """
        params = {'limit': limit, 'offset': offset}

        if filter:
            params['name'] = filter

        resp = self.client.get('containers', params=params,
                               extra_headers=extra_headers,
                               user_name=user_name)

        container_list = self.get_json(resp)

        containers, next_ref, prev_ref = self.client.get_list_of_models(
            container_list, container_models.ContainerModel)

        return resp, containers, next_ref, prev_ref

    def delete_container(self, container_ref, extra_headers=None,
                         expected_fail=False, user_name=None):
        """Handles deleting a containers.

        :param container_ref: Reference of the container to be deleted
        :param extra_headers: Any additional headers needed.
        :param expected_fail: If there is a negative test, this should be
            marked true if you are trying to delete a container that does
            not exist.
        :param user_name: The user name used to delete the container
        :return: Response of the delete.
        """
        resp = self.client.delete(container_ref, extra_headers,
                                  user_name=user_name)

        if not expected_fail:
            for item in self.created_entities:
                if item[0] == container_ref:
                    self.created_entities.remove(item)

        return resp

    def delete_all_created_containers(self):
        """Delete all of the containers that we have created."""
        entities = list(self.created_entities)
        for (container_ref, admin) in entities:
            self.delete_container(container_ref, user_name=admin)

    def update_container(self, container_ref, user_name=None):
        """Attempt to update a container (which is an invalid operation)

        Update (HTTP PUT) is not supported against a container resource, so
        issuing this call should fail.

        :param container_ref: Reference of the container to be updated
        :param user_name: The user name used to update the container
        :return: Response of the update.
        """

        resp = self.client.put(container_ref, user_name=user_name)

        return resp

    def delete_all_containers_for_user(self, user_name):
        '''Delete all of the containers for the specified user'''
        response, containers, next_ref, prev_ref = self.get_containers(
            user_name=user_name)
        container_refs_to_delete = []
        while len(containers) > 0:
            for container in containers:
                container_refs_to_delete.append(container.container_ref)
            if next_ref:
                limit, offset = utils.get_limit_and_offset_from_ref(next_ref)
                response, containers, next_ref, prev = self.get_containers(
                    limit=limit, offset=offset, user_name=user_name)
            else:
                break

        for container_ref in container_refs_to_delete:
            self.delete_container(container_ref=container_ref,
                                  user_name=user_name)
