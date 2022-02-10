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


class WhenTestingContainerConsumersResource(utils.BarbicanAPIBaseTestCase):

    def setUp(self):
        super(WhenTestingContainerConsumersResource, self).setUp()

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

        consumer_resp, consumer = create_container_consumer(
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

        consumer_resp, consumers = create_container_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_a["name"],
            url=self.consumer_a["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_container_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_b["name"],
            url=self.consumer_b["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_container_consumer(
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

        consumer_resp, consumers = create_container_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_a["name"],
            url=self.consumer_a["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_container_consumer(
            self.app,
            container_id=container_uuid,
            name=self.consumer_b["name"],
            url=self.consumer_b["URL"]
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_container_consumer(
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

        consumer_resp, consumers = create_container_consumer(
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
        consumer_resp, consumers = create_container_consumer(
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

        consumer_resp, consumer = create_container_consumer(
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

        consumer_resp, consumer = create_container_consumer(
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

        consumer_resp, consumer = create_container_consumer(
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

        consumer_resp, consumer = create_container_consumer(
            self.app,
            container_id=container_uuid,
            name="thename",
            url="",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)


class WhenTestingSecretConsumersResource(utils.BarbicanAPIBaseTestCase):

    def setUp(self):
        super(WhenTestingSecretConsumersResource, self).setUp()

        self.consumer_a = {
            "service": "service_a",
            "resource_type": "resource_type_a",
            "resource_id": "resource_id_a",
        }

        self.consumer_b = {
            "service": "service_b",
            "resource_type": "resource_type_b",
            "resource_id": "resource_id_b",
        }

        self.consumer_c = {
            "service": "service_c",
            "resource_type": "resource_type_c",
            "resource_id": "resource_id_c",
        }

    def test_can_create_new_consumer(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service=self.consumer_a["service"],
            resource_type=self.consumer_a["resource_type"],
            resource_id=self.consumer_a["resource_id"],
        )

        self.assertEqual(200, consumer_resp.status_int)
        self.assertEqual([self.consumer_a], consumer)

    def test_can_get_consumers(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumers = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service=self.consumer_a["service"],
            resource_type=self.consumer_a["resource_type"],
            resource_id=self.consumer_a["resource_id"],
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service=self.consumer_b["service"],
            resource_type=self.consumer_b["resource_type"],
            resource_id=self.consumer_b["resource_id"],
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service=self.consumer_c["service"],
            resource_type=self.consumer_c["resource_type"],
            resource_id=self.consumer_c["resource_id"],
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_get_resp = self.app.get(
            '/secrets/{secret_id}/consumers/'.format(
                secret_id=secret_id))

        self.assertEqual(200, consumer_get_resp.status_int)
        self.assertIn(consumers[0]["service"],
                      consumer_get_resp.json["consumers"][0]["service"])
        self.assertIn(consumers[0]["resource_type"],
                      consumer_get_resp.json["consumers"][0]["resource_type"])
        self.assertIn(consumers[0]["resource_id"],
                      consumer_get_resp.json["consumers"][0]["resource_id"])
        self.assertIn(consumers[1]["service"],
                      consumer_get_resp.json["consumers"][1]["service"])
        self.assertIn(consumers[1]["resource_type"],
                      consumer_get_resp.json["consumers"][1]["resource_type"])
        self.assertIn(consumers[1]["resource_id"],
                      consumer_get_resp.json["consumers"][1]["resource_id"])
        self.assertIn(consumers[2]["service"],
                      consumer_get_resp.json["consumers"][2]["service"])
        self.assertIn(consumers[2]["resource_type"],
                      consumer_get_resp.json["consumers"][2]["resource_type"])
        self.assertIn(consumers[2]["resource_id"],
                      consumer_get_resp.json["consumers"][2]["resource_id"])

    def test_can_get_consumers_with_limit_and_offset(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumers = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service=self.consumer_a["service"],
            resource_type=self.consumer_a["resource_type"],
            resource_id=self.consumer_a["resource_id"],
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service=self.consumer_b["service"],
            resource_type=self.consumer_b["resource_type"],
            resource_id=self.consumer_b["resource_id"],
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_resp, consumers = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service=self.consumer_c["service"],
            resource_type=self.consumer_c["resource_type"],
            resource_id=self.consumer_c["resource_id"],
        )
        self.assertEqual(200, consumer_resp.status_int)

        consumer_get_resp = self.app.get(
            '/secrets/{secret_id}/consumers/?limit=1&offset=1'.format(
                secret_id=secret_id))
        self.assertEqual(200, consumer_get_resp.status_int)

        secret_url = resp.json["secret_ref"]

        prev_cons = u"{secret_url}/consumers?limit=1&offset=0".format(
            secret_url=secret_url)
        self.assertEqual(prev_cons, consumer_get_resp.json["previous"])

        next_cons = u"{secret_url}/consumers?limit=1&offset=2".format(
            secret_url=secret_url)
        self.assertEqual(next_cons, consumer_get_resp.json["next"])

        self.assertEqual(
            self.consumer_b["service"],
            consumer_get_resp.json["consumers"][0]["service"]
        )
        self.assertEqual(
            self.consumer_b["resource_type"],
            consumer_get_resp.json["consumers"][0]["resource_type"]
        )
        self.assertEqual(
            self.consumer_b["resource_id"],
            consumer_get_resp.json["consumers"][0]["resource_id"]
        )

        self.assertEqual(3, consumer_get_resp.json["total"])

    def test_can_delete_consumer(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumers = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service=self.consumer_a["service"],
            resource_type=self.consumer_a["resource_type"],
            resource_id=self.consumer_a["resource_id"],
        )
        self.assertEqual(200, consumer_resp.status_int)

        request = {
            "service": self.consumer_a["service"],
            "resource_type": self.consumer_a["resource_type"],
            "resource_id": self.consumer_a["resource_id"],
        }
        cleaned_request = {key: val for key, val in request.items()
                           if val is not None}

        consumer_del_resp = self.app.delete_json(
            '/secrets/{secret_id}/consumers/'.format(
                secret_id=secret_id
            ), cleaned_request, headers={'Content-Type': 'application/json'})

        self.assertEqual(200, consumer_del_resp.status_int)

    def test_can_get_no_consumers(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_get_resp = self.app.get(
            '/secrets/{secret_id}/consumers/'.format(
                secret_id=secret_id))

        self.assertEqual(200, consumer_get_resp.status_int)
        self.assertEqual([], consumer_get_resp.json["consumers"])

    def test_fail_create_secret_not_found(self):
        consumer_resp, consumers = create_secret_consumer(
            self.app,
            secret_id="bad_secret_id",
            service=self.consumer_a["service"],
            resource_type=self.consumer_a["resource_type"],
            resource_id=self.consumer_a["resource_id"],
            expect_errors=True
        )
        self.assertEqual(404, consumer_resp.status_int)

    def test_fail_get_secret_not_found(self):
        consumer_get_resp = self.app.get(
            '/secrets/{secret_id}/consumers/'.format(
                secret_id="bad_secret_id"), expect_errors=True)

        self.assertEqual(404, consumer_get_resp.status_int)

    def test_fail_delete_secret_not_found(self):
        request = {
            "service": self.consumer_a["service"],
            "resource_type": self.consumer_a["resource_type"],
            "resource_id": self.consumer_a["resource_id"],
        }
        cleaned_request = {key: val for key, val in request.items()
                           if val is not None}

        consumer_del_resp = self.app.delete_json(
            '/secrets/{secret_id}/consumers/'.format(
                secret_id="bad_secret_id"
            ), cleaned_request, headers={'Content-Type': 'application/json'},
            expect_errors=True)

        self.assertEqual(404, consumer_del_resp.status_int)

    def test_fail_delete_consumer_not_found(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        request = {
            "service": self.consumer_a["service"],
            "resource_type": self.consumer_a["resource_type"],
            "resource_id": self.consumer_a["resource_id"],
        }
        cleaned_request = {key: val for key, val in request.items()
                           if val is not None}

        consumer_del_resp = self.app.delete_json(
            '/secrets/{secret_id}/consumers/'.format(
                secret_id=secret_id
            ), cleaned_request, headers={'Content-Type': 'application/json'},
            expect_errors=True)

        self.assertEqual(404, consumer_del_resp.status_int)

    def test_fail_create_no_service(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            resource_type="resource_type",
            resource_id="resource_id",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)

    def test_fail_create_no_resource_type(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service="service",
            resource_id="resource_id",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)

    def test_fail_create_no_resource_id(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service="service",
            resource_type="resource_type",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)

    def test_fail_create_empty_service(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service="",
            resource_type="resource_type",
            resource_id="resource_id",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)

    def test_fail_create_empty_resource_type(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service="service",
            resource_type="",
            resource_id="resource_id",
            expect_errors=True
        )
        self.assertEqual(400, consumer_resp.status_int)

    def test_fail_create_empty_resource_id(self):
        resp, secret_id = create_secret(self.app)
        self.assertEqual(201, resp.status_int)

        consumer_resp, consumer = create_secret_consumer(
            self.app,
            secret_id=secret_id,
            service="service",
            resource_type="resource_type",
            resource_id="",
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


def create_container_consumer(app, container_id=None, name=None, url=None,
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


def create_secret(app, expect_errors=False):
    resp = app.post_json('/secrets/', {}, expect_errors=expect_errors)

    secret_id = None
    if resp.status_int == 201:
        secret_ref = resp.json.get('secret_ref', '')
        _, secret_id = os.path.split(secret_ref)

    return resp, secret_id


def create_secret_consumer(app, secret_id=None, service=None,
                           resource_type=None, resource_id=None,
                           expect_errors=False, headers=None):
    request = {
        "service": service,
        "resource_type": resource_type,
        "resource_id": resource_id,
    }
    request = {k: v for k, v in request.items() if v is not None}

    resp = app.post_json(
        "/secrets/{}/consumers/".format(secret_id),
        request,
        expect_errors=expect_errors,
        headers=headers
    )

    consumers = None
    if resp.status_int == 200:
        consumers = resp.json.get('consumers', '')

    return resp, consumers
