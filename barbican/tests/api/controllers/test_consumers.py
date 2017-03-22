# Copyright (c) 2017 IBM
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

from barbican.tests import utils


class WhenTestingConsumersResource(utils.BarbicanAPIBaseTestCase):

    def setUp(self):
        super(WhenTestingConsumersResource, self).setUp()

        self.container_name = "Im_a_container"
        self.container_type = "generic"

        self.consumer_a = {
            "URL": "http://test_a",
            "name": "consumer_a"
        }

        self.consumer_b = {
            "URL": "http://test_b",
            "name": "consumer_b"
        }

        self.consumer_c = {
            "URL": "http://test_c",
            "name": "consumer_c"
        }

    def test_can_create_new_consumer(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_a["name"],
            url=self.consumer_a["URL"]
        )

        self.assertEqual(200, consumer_resp.status_int)
        self.assertEqual([self.consumer_a], consumer)

    def test_can_get_consumers(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumers = create_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_a["name"],
            url=self.consumer_a["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_b["name"],
            url=self.consumer_b["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_c["name"],
            url=self.consumer_c["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_get_resp = self.app.get(
            '/containers/{container_id}/consumers/'.format(
                container_id=container_uuid))

        self.assertEqual(200, consumer_get_resp.status_int)
        self.assertIn(consumers[0]["name"],
                      consumer_get_resp.json["consumers"][0]["name"])
        self.assertIn(consumers[0]["URL"],
                      consumer_get_resp.json["consumers"][0]["URL"])
        self.assertIn(consumers[1]["name"],
                      consumer_get_resp.json["consumers"][1]["name"])
        self.assertIn(consumers[1]["URL"],
                      consumer_get_resp.json["consumers"][1]["URL"])
        self.assertIn(consumers[2]["name"],
                      consumer_get_resp.json["consumers"][2]["name"])
        self.assertIn(consumers[2]["URL"],
                      consumer_get_resp.json["consumers"][2]["URL"])

    def test_can_get_consumers_with_limit_and_offset(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumers = create_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_a["name"],
            url=self.consumer_a["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_b["name"],
            url=self.consumer_b["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_c["name"],
            url=self.consumer_c["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_get_resp = self.app.get(
            '/containers/{container_id}/consumers/?limit=1&offset=1'.format(
                container_id=container_uuid))
        self.assertEqual(200, consumer_get_resp.status_int)

        container_url = resp.json["container_ref"]

        prev_cons = u"{container_url}/consumers?limit=1&offset=0".format(
            container_url=container_url)
        self.assertEqual(prev_cons, consumer_get_resp.json["previous"])

        next_cons = u"{container_url}/consumers?limit=1&offset=2".format(
            container_url=container_url)
        self.assertEqual(next_cons, consumer_get_resp.json["next"])

        self.assertEqual(self.consumer_b["name"],
                         consumer_get_resp.json["consumers"][0]["name"])
        self.assertEqual(self.consumer_b["URL"],
                         consumer_get_resp.json["consumers"][0]["URL"])

        self.assertEqual(3, consumer_get_resp.json["total"])

    def test_can_delete_consumer(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumers = create_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_a["name"],
            url=self.consumer_a["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        request = {
            'name': self.consumer_a["name"],
            'URL': self.consumer_a["URL"]
        }
        cleaned_request = {key: val for key, val in request.items()
                           if val is not None}

        consumer_del_resp = self.app.delete_json(
            '/containers/{container_id}/consumers/'.format(
                container_id=container_uuid
            ), cleaned_request, headers={'Content-Type': 'application/json'})

        self.assertEqual(200, consumer_del_resp.status_int)

    def test_can_get_no_consumers(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_get_resp = self.app.get(
            '/containers/{container_id}/consumers/'.format(
                container_id=container_uuid))

        self.assertEqual(200, consumer_get_resp.status_int)
        self.assertEqual([], consumer_get_resp.json["consumers"])

    def test_fail_create_container_not_found(self):
        consumer_resp, consumers = create_consumer(
            self.app,
            container_id="bad_container_id",
            name=self.consumer_a["name"],
            url=self.consumer_a["URL"],
            expect_errors=True
        )
        self.assertEqual(404, consumer_resp.status_int)

    def test_fail_get_container_not_found(self):
        consumer_get_resp = self.app.get(
            '/containers/{container_id}/consumers/'.format(
                container_id="bad_container_id"), expect_errors=True)

        self.assertEqual(404, consumer_get_resp.status_int)

    def test_fail_delete_container_not_found(self):
        request = {
            'name': self.consumer_a["name"],
            'URL': self.consumer_a["URL"]
        }
        cleaned_request = {key: val for key, val in request.items()
                           if val is not None}

        consumer_del_resp = self.app.delete_json(
            '/containers/{container_id}/consumers/'.format(
                container_id="bad_container_id"
            ), cleaned_request, headers={'Content-Type': 'application/json'},
            expect_errors=True)

        self.assertEqual(404, consumer_del_resp.status_int)

    def test_fail_delete_consumer_not_found(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        request = {
            'name': self.consumer_a["name"],
            'URL': self.consumer_a["URL"]
        }
        cleaned_request = {key: val for key, val in request.items()
                           if val is not None}

        consumer_del_resp = self.app.delete_json(
            '/containers/{container_id}/consumers/'.format(
                container_id=container_uuid
            ), cleaned_request, headers={'Content-Type': 'application/json'},
            expect_errors=True)

        self.assertEqual(404, consumer_del_resp.status_int)

    def test_fail_create_no_name(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_consumer(
            self.app,
            container_id=container_uuid,
            url="http://theurl",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)

    def test_fail_create_no_url(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_consumer(
            self.app,
            container_id=container_uuid,
            name="thename",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)

    def test_fail_create_empty_name(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_consumer(
            self.app,
            container_id=container_uuid,
            name="",
            url="http://theurl",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)

    def test_fail_create_empty_url(self):
        resp, container_uuid = create_container(
            self.app,
            name=self.container_name,
            container_type=self.container_type
        )
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_consumer(
            self.app,
            container_id=container_uuid,
            name="thename",
            url="",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)


# ----------------------- Helper Functions ---------------------------
def create_container(app, name=None, container_type=None, expect_errors=False,
                     headers=None):
    request = {
        'name': name,
        'type': container_type
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

    return resp, created_uuid


def create_consumer(app, container_id=None, name=None, url=None,
                    expect_errors=False, headers=None):
    request = {
        'name': name,
        'URL': url
    }
    cleaned_request = {key: val for key, val in request.items()
                       if val is not None}

    resp = app.post_json(
        '/containers/{container_id}/consumers/'.format(
            container_id=container_id),
        cleaned_request,
        expect_errors=expect_errors,
        headers=headers
    )

    consumers = None
    if resp.status_int == 200:
        consumers = resp.json.get('consumers', '')

    return resp, consumers
