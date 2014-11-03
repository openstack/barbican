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

    def create_container(self, model, headers=None):
        resp = self.client.post('containers', request_model=model,
                                extra_headers=headers)

        returned_data = resp.json()
        container_ref = returned_data.get('container_ref')
        if container_ref:
            self.created_entities.append(container_ref)
        return resp, container_ref

    def get_container(self, container_ref, extra_headers=None):
        return self.client.get(
            container_ref,
            extra_headers=extra_headers,
            response_model_type=container_models.ContainerModel
        )

    def get_containers(self, limit=10, offset=0):
        params = {'limit': limit, 'offset': offset}
        resp = self.client.get('containers', params=params)

        container_list = resp.json()

        containers, next_ref, prev_ref = self.client.get_list_of_models(
            container_list, container_models.ContainerModel)

        return resp, containers, next_ref, prev_ref

    def delete_container(self, container_ref, extra_headers=None,
                         expected_fail=False):
        resp = self.client.get(container_ref, extra_headers=extra_headers)

        if not expected_fail:
            self.created_entities.remove(container_ref)

        return resp
