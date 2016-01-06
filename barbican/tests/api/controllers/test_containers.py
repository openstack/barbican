# Copyright (c) 2015 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import uuid

from barbican.common import config
from barbican.common import exception
from barbican.model import repositories
from barbican.tests.api.controllers import test_secrets as secret_helper
from barbican.tests import utils

containers_repo = repositories.get_container_repository()


class SuccessfulContainerCreateMixin(object):
    def _assert_successful_container_create(self, resp, container_uuid):
        self.assertEqual(201, resp.status_int)
        # this will raise if the container uuid is not proper
        uuid.UUID(container_uuid)


class WhenCreatingContainersUsingContainersResource(
        utils.BarbicanAPIBaseTestCase,
        SuccessfulContainerCreateMixin):

    def test_should_add_new_empty_container(self):
        container_name = 'test container name'
        container_type = 'generic'
        resp, container_uuid = create_container(
            self.app,
            name=container_name,
            container_type=container_type
        )
        self._assert_successful_container_create(resp, container_uuid)

        container = containers_repo.get(container_uuid, self.project_id)
        self.assertEqual(container_name, container.name)
        self.assertEqual(container_type, container.type)

    def test_should_add_new_populated_container(self):
        secret_name = 'test secret 1'
        resp, _ = secret_helper.create_secret(
            self.app,
            name=secret_name
        )
        self.assertEqual(201, resp.status_int)
        secret_ref = resp.json.get('secret_ref')

        container_name = 'test container name'
        container_type = 'generic'
        secret_refs = [
            {
                'name': secret_name,
                'secret_ref': secret_ref
            }
        ]
        resp, container_uuid = create_container(
            self.app,
            name=container_name,
            container_type=container_type,
            secret_refs=secret_refs
        )
        self._assert_successful_container_create(resp, container_uuid)

        container = containers_repo.get(container_uuid, self.project_id)
        self.assertEqual(container_name, container.name)
        self.assertEqual(container_type, container.type)

    def test_should_create_container_w_empty_name(self):
        # Name key missing
        container_type = 'generic'
        resp, container_uuid = create_container(
            self.app,
            container_type=container_type
        )
        self._assert_successful_container_create(resp, container_uuid)

        # Name key is null
        request = {
            'name': None,
            'type': container_type,
        }
        resp = self.app.post_json(
            '/containers/',
            request,
        )
        container_ref = resp.json.get('container_ref', '')
        _, container_uuid = os.path.split(container_ref)
        self._assert_successful_container_create(resp, container_uuid)

    def test_should_raise_container_bad_json(self):
        resp, container_uuid = create_container(
            self.app,
            expect_errors=True
        )
        self.assertEqual(400, resp.status_int)

    def test_should_raise_container_bad_content_type_header(self):
        resp, container_uuid = create_container(
            self.app,
            name='test container name',
            container_type='generic',
            expect_errors=True,
            headers={'Content-Type': 'bad_content_type'}
        )
        self.assertEqual(415, resp.status_int)

    def test_should_sanitize_location_from_response_header(self):
        resp, container_uuid = create_container(
            self.app,
            name='test container name',
            container_type='generic'
        )
        self._assert_successful_container_create(resp, container_uuid)
        self.assertNotIn(self.project_id, resp.headers['Location'])

    def test_should_throw_exception_when_secret_ref_doesnt_exist(self):
        config.CONF.set_override("host_href", "http://localhost:9311",
                                 enforce_type=True)
        secret_refs = [
            {
                'name': 'bad secret',
                'secret_ref': 'http://localhost:9311/secrets/does_not_exist'
            }
        ]
        resp, container_uuid = create_container(
            self.app,
            name='test container name',
            container_type='generic',
            secret_refs=secret_refs,
            expect_errors=True,
        )
        self.assertEqual(404, resp.status_int)
        config.CONF.clear_override('host_href')


class WhenGettingContainersListUsingContainersResource(
        utils.BarbicanAPIBaseTestCase,
        SuccessfulContainerCreateMixin):

    def setUp(self):
        super(WhenGettingContainersListUsingContainersResource, self).setUp()

        self.num_containers = 10
        self.offset = 2
        self.limit = 2
        self.params = {
            'offset': self.offset,
            'limit': self.limit
        }

    def _create_containers(self):
        for i in range(self.num_containers):
            resp, container_uuid = create_container(
                self.app,
                name='test container name {num}'.format(num=i),
                container_type='generic'
            )
            self._assert_successful_container_create(resp, container_uuid)

    def _create_url(self, offset_arg=None, limit_arg=None):
        if limit_arg:
            offset = int(offset_arg)
            limit = int(limit_arg)
            return '/containers?limit={limit}&offset={offset}'.format(
                limit=limit, offset=offset)
        else:
            return '/containers'

    def test_should_get_list_containers(self):
        self._create_containers()

        resp = self.app.get(
            '/containers/',
            self.params
        )
        self.assertEqual(200, resp.status_int)
        self.assertIn('previous', resp.namespace)
        self.assertIn('next', resp.namespace)

        url_nav_next = self._create_url(self.offset + self.limit, self.limit)
        self.assertEqual(1, resp.body.decode('utf-8').count(url_nav_next))

        url_nav_prev = self._create_url(0, self.limit)
        self.assertEqual(1, resp.body.decode('utf-8').count(url_nav_prev))

        url_hrefs = self._create_url()
        self.assertEqual((self.limit + 2),
                         resp.body.decode('utf-8').count(url_hrefs))

    def test_response_should_include_total(self):
        self._create_containers()

        resp = self.app.get(
            '/containers/',
            self.params
        )
        self.assertIn('total', resp.namespace)
        self.assertEqual(self.num_containers, resp.namespace['total'])

    def test_should_handle_no_containers(self):
        resp = self.app.get(
            '/containers/',
            self.params
        )
        self.assertEqual(0, resp.namespace['total'])
        self.assertNotIn('previous', resp.namespace)
        self.assertNotIn('next', resp.namespace)


class WhenGettingOrDeletingContainerUsingContainerResource(
        utils.BarbicanAPIBaseTestCase,
        SuccessfulContainerCreateMixin):

    def test_should_get_container(self):
        container_name = 'test container name'
        container_type = 'generic'
        resp, container_uuid = create_container(
            self.app,
            name=container_name,
            container_type=container_type
        )
        self._assert_successful_container_create(resp, container_uuid)

        resp = self.app.get('/containers/{container_id}/'.format(
            container_id=container_uuid
        ))

        self.assertEqual(200, resp.status_int)
        self.assertEqual(container_name, resp.json.get('name', ''))
        self.assertEqual(container_type, resp.json.get('type', ''))

    def test_should_delete_container(self):
        resp, container_uuid = create_container(
            self.app,
            name='test container name',
            container_type='generic'
        )
        self._assert_successful_container_create(resp, container_uuid)

        resp = self.app.delete('/containers/{container_id}/'.format(
            container_id=container_uuid
        ))

        self.assertEqual(204, resp.status_int)
        self.assertRaises(exception.NotFound, containers_repo.get,
                          container_uuid, self.project_id)

    def test_should_throw_exception_for_get_when_container_not_found(self):
        resp = self.app.get('/containers/bad_id/', expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_should_throw_exception_for_delete_when_container_not_found(self):
        resp = self.app.delete('/containers/bad_id/', expect_errors=True)
        self.assertEqual(404, resp.status_int)
        # Error response should have json content type
        self.assertEqual("application/json", resp.content_type)


class WhenPerformingUnallowedOperationsOnContainers(
        utils.BarbicanAPIBaseTestCase,
        SuccessfulContainerCreateMixin):

    container_req = [
        {
            'name': 'test container name',
            'type': 'generic',
            'secret_refs': []
        }
    ]

    def test_should_not_allow_put_on_containers(self):
        resp = self.app.put_json(
            '/containers/',
            self.container_req,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_post_on_container_by_id(self):
        resp, container_uuid = create_container(
            self.app,
            name='test container name',
            container_type='generic'
        )
        self._assert_successful_container_create(resp, container_uuid)

        resp = self.app.post_json(
            '/containers/{container_id}/'.format(container_id=container_uuid),
            self.container_req,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)

    def test_should_not_allow_put_on_container_by_id(self):
        resp, container_uuid = create_container(
            self.app,
            name='test container name',
            container_type='generic'
        )
        self._assert_successful_container_create(resp, container_uuid)

        resp = self.app.put_json(
            '/containers/{container_id}/'.format(container_id=container_uuid),
            self.container_req,
            expect_errors=True
        )
        self.assertEqual(405, resp.status_int)


# ----------------------- Helper Functions ---------------------------
def create_container(app, name=None, container_type=None, secret_refs=None,
                     expect_errors=False, headers=None):
    request = {
        'name': name,
        'type': container_type,
        'secret_refs': secret_refs if secret_refs else []
    }
    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    resp = app.post_json(
        '/containers/',
        cleaned_request,
        expect_errors=expect_errors,
        headers=headers
    )

    created_uuid = None
    if resp.status_int == 201:
        container_ref = resp.json.get('container_ref', '')
        _, created_uuid = os.path.split(container_ref)

    return (resp, created_uuid)
