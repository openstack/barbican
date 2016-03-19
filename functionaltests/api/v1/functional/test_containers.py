# Copyright (c) 2014 Rackspace, Inc.
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
import copy

from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models


def get_default_container_create_data(secret):
    return {
        "type": "generic",
        "name": "generic name",
        "secret_refs": [
            {
                "name": "a secret",
                "secret_ref": secret
            }
        ]
    }

create_container_data = {
    "name": "containername",
    "type": "generic",
    "secret_refs": [
        {
            "name": "secret1",
        },
        {
            "name": "secret2",
        },
        {
            "name": "secret3"
        }
    ]
}

create_container_rsa_data = {
    "name": "rsacontainer",
    "type": "rsa",
    "secret_refs": [
        {
            "name": "public_key",
        },
        {
            "name": "private_key",
        },
        {
            "name": "private_key_passphrase"
        }
    ]
}

accepted_str_values = {
    'alphanumeric': ['a2j3j6ll9'],
    'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
    'len_255': [str(bytearray().zfill(255))],
    'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
    'empty': ['']
}


class BaseContainerTestCase(base.TestCase):
    default_data_template = create_container_data

    def setUp(self):
        super(BaseContainerTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.behaviors = container_behaviors.ContainerBehaviors(self.client)

        # Setting up three secrets for building containers
        self.secret_ref_1 = self._create_a_secret()
        self.secret_ref_2 = self._create_a_secret()
        self.secret_ref_3 = self._create_a_secret()

        self.default_data = copy.deepcopy(self.default_data_template)

        default_secret_refs = self.default_data['secret_refs']
        default_secret_refs[0]['secret_ref'] = self.secret_ref_1
        default_secret_refs[1]['secret_ref'] = self.secret_ref_2
        default_secret_refs[2]['secret_ref'] = self.secret_ref_3

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        self.behaviors.delete_all_created_containers()
        super(BaseContainerTestCase, self).tearDown()

    def _create_a_secret(self):
        secret_defaults_data = {
            "name": "AES key",
            "expiration": "2018-02-28T19:14:44.180394",
            "algorithm": "aes",
            "bit_length": 256,
            "mode": "cbc",
            "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
            "payload_content_type": "application/octet-stream",
            "payload_content_encoding": "base64",
        }

        secret_model = secret_models.SecretModel(**secret_defaults_data)
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        return secret_ref


@utils.parameterized_test_case
class GenericContainersTestCase(BaseContainerTestCase):

    @testcase.attr('positive')
    def test_create_defaults_none_secret_name(self):
        """Covers creating a container with None as a secret name."""
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.name = None

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)

    @utils.parameterized_dataset({'0': [0], '1': [1], '50': [50]})
    @testcase.attr('positive')
    def test_create_defaults_size(self, num_secrets):
        """Covers creating containers of various sizes."""
        test_model = container_models.ContainerModel(**self.default_data)
        for i in range(0, num_secrets):
            secret_ref = self._create_a_secret()
            test_model.secret_refs.append({
                'name': 'other_secret{0}'.format(i),
                'secret_ref': secret_ref
            })

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_defaults_name(self, name):
        """Covers creating generic containers with various names."""
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.name = name

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_defaults_secret_name(self, name=None):
        """Covers creating containers with various secret ref names."""
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.secret_refs = [{
            'name': name,
            'secret_ref': self.secret_ref_1
        }]

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)

        get_resp = self.behaviors.get_container(container_ref)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.model.secret_refs[0].name, name)

    @testcase.attr('negative')
    def test_create_defaults_invalid_type(self):
        """Container creating should fail with an invalid container type."""
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.type = 'bad_type'

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('negative')
    def test_create_defaults_duplicate_secret_refs(self):
        """Covers creating a container with a duplicated secret ref."""
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.secret_refs[0]['secret_ref'] = self.secret_ref_1
        test_model.secret_refs[1]['secret_ref'] = self.secret_ref_1
        test_model.secret_refs[2]['secret_ref'] = self.secret_ref_1

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('negative')
    def test_get_non_existent_container(self):
        """A get on a container that does not exist should return a 404."""
        resp = self.behaviors.get_container("not_a_ref")
        self.assertEqual(resp.status_code, 404)

    @testcase.attr('negative')
    def test_delete_non_existent_container(self):
        """A delete on a container that does not exist should return a 404."""
        resp = self.behaviors.delete_container("not_a_ref", expected_fail=True)
        self.assertEqual(resp.status_code, 404)

    @testcase.attr('positive')
    def test_create_change_host_header(self, **kwargs):
        """Create a container with a (possibly) malicious host name header."""

        test_model = container_models.ContainerModel(**self.default_data)

        malicious_hostname = 'some.bad.server.com'
        changed_host_header = {'Host': malicious_hostname}

        resp, container_ref = self.behaviors.create_container(
            test_model, extra_headers=changed_host_header)

        self.assertEqual(resp.status_code, 201)

        # get Location field from result and assert that it is NOT the
        # malicious one.
        regex = '.*{0}.*'.format(malicious_hostname)
        self.assertNotRegexpMatches(resp.headers['location'], regex)


@utils.parameterized_test_case
class RSAContainersTestCase(BaseContainerTestCase):
    default_data_template = create_container_rsa_data

    @testcase.attr('positive')
    def test_create_rsa_no_passphrase(self):
        """Covers creating an rsa container without a passphrase."""
        pub_key_ref = {'name': 'public_key', 'secret_ref': self.secret_ref_1}
        priv_key_ref = {'name': 'private_key', 'secret_ref': self.secret_ref_2}

        test_model = container_models.ContainerModel(**self.default_data)
        test_model.secret_refs = [pub_key_ref, priv_key_ref]

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_rsa_name(self, name):
        """Covers creating rsa containers with various names."""
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.name = name

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 201)

    @testcase.attr('negative')
    def test_create_rsa_invalid_key_names(self):
        """Covers creating an RSA container with incorrect names."""
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.secret_refs = [
            {
                "name": "secret1",
                "secret_ref": self.secret_ref_1
            },
            {
                "name": "secret2",
                "secret_ref": self.secret_ref_2
            },
            {
                "name": "secret3",
                "secret_ref": self.secret_ref_3
            }
        ]

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('negative')
    def test_create_rsa_no_public_key(self):
        """Creating an rsa container without a public key should fail.

        RSA containers must have at least a public key and private key.
        """
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.secret_refs[0]['name'] = 'secret_1'

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('negative')
    def test_create_rsa_no_private_key(self):
        """Creating an rsa container without a private key should fail.

        RSA containers must have at least a public key and private key.
        """
        test_model = container_models.ContainerModel(**self.default_data)
        test_model.secret_refs[1]['name'] = 'secret_1'

        resp, container_ref = self.behaviors.create_container(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('positive')
    def test_create_rsa_change_host_header(self, **kwargs):
        """Create a container with a (possibly) malicious host name header."""

        test_model = container_models.ContainerModel(**self.default_data)

        malicious_hostname = 'some.bad.server.com'
        changed_host_header = {'Host': malicious_hostname}

        resp, container_ref = self.behaviors.create_container(
            test_model, extra_headers=changed_host_header)

        self.assertEqual(resp.status_code, 201)

        # get Location field from result and assert that it is NOT the
        # malicious one.
        regex = '.*{0}.*'.format(malicious_hostname)
        self.assertNotRegexpMatches(resp.headers['location'], regex)


class ContainersPagingTestCase(base.PagingTestCase):

    def setUp(self):
        super(ContainersPagingTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.behaviors = container_behaviors.ContainerBehaviors(self.client)

        # make a local mutable copy of the default data to prevent
        # possible data contamination
        secret = self._create_a_secret()
        self.create_default_data = get_default_container_create_data(secret)

    def _create_a_secret(self):
        secret_defaults_data = {
            "name": "AES key",
            "expiration": "2018-02-28T19:14:44.180394",
            "algorithm": "aes",
            "bit_length": 256,
            "mode": "cbc",
            "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
            "payload_content_type": "application/octet-stream",
            "payload_content_encoding": "base64",
        }

        secret_model = secret_models.SecretModel(**secret_defaults_data)
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        return secret_ref

    def tearDown(self):
        self.behaviors.delete_all_created_containers()
        super(ContainersPagingTestCase, self).tearDown()

    def create_model(self):
        return container_models.ContainerModel(**self.create_default_data)

    def create_resources(self, count=0, model=None):
        for x in range(0, count):
            self.behaviors.create_container(model)

    def get_resources(self, limit=10, offset=0, filter=filter):
        return self.behaviors.get_containers(limit=limit, offset=offset,
                                             filter=filter)

    def set_filter_field(self, unique_str, model):
        '''Set the name field which we use in the get_resources '''
        model.name = unique_str


class ContainersUnauthedTestCase(BaseContainerTestCase):

    def setUp(self):
        super(ContainersUnauthedTestCase, self).setUp()

        self.dummy_project_id = 'dummy123'
        self.dummy_container_ref = (
            'containers/dummy123-3416-4b53-8875-e6af3e0af8c3'
        )

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        super(ContainersUnauthedTestCase, self).tearDown()

    @testcase.attr('negative', 'security')
    def test_unauthed_create_huge_dummy_token_no_proj_id(self):
        """Attempt to create a container with a dummy token, and no project id

        Should return 401
        """

        model = container_models.ContainerModel(
            **create_container_data
        )
        headers = {'X-Auth-Token': 'a' * 3500}
        resp = self.client.post(
            'containers', request_model=model, use_auth=False,
            extra_headers=headers
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_unauthed_create_no_proj_id(self):
        """Attempt to create a container without a token or project id

        Should return 401
        """

        model = container_models.ContainerModel(
            **create_container_data
        )
        resp = self.client.post(
            'containers', request_model=model, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_unauthed_get_no_proj_id(self):
        """Attempt to get a container without a token or project id

        Should return 401
        """

        headers = {
            'Accept': '*/*',
            'Accept-Encoding': '*/*'
        }
        resp = self.client.get(
            self.dummy_container_ref, extra_headers=headers, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_unauthed_delete_no_proj_id(self):
        """Attempt to delete a container without a token or project id

        Should return 401
        """

        resp = self.client.delete(self.dummy_container_ref, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_unauthed_huge_dummy_token_with_proj_id(self):
        """Attempt to create a container with a dummy token and project id

        Should return 401
        """

        model = container_models.ContainerModel(
            **create_container_data
        )
        headers = {
            'X-Auth-Token': 'a' * 3500,
            'X-Project-Id': self.dummy_project_id
        }
        resp = self.client.post(
            'containers', request_model=model, use_auth=False,
            extra_headers=headers
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_unauthed_create_with_proj_id(self):
        """Attempt to create a container with a project id, but not a token

        Should return 401
        """

        model = container_models.ContainerModel(
            **create_container_data
        )
        headers = {'X-Project-Id': self.dummy_project_id}
        resp = self.client.post(
            'containers', request_model=model, use_auth=False,
            extra_headers=headers
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_unauthed_get_with_proj_id(self):
        """Attempt to get a container with a project id, but not a token

        Should return 401
        """

        headers = {
            'Accept': '*/*',
            'Accept-Encoding': '*/*',
            'X-Project-Id': self.dummy_project_id
        }
        resp = self.client.get(
            self.dummy_container_ref, extra_headers=headers, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_unauthed_delete_with_proj_id(self):
        """Attempt to delete a container with a project id, but not a token

        Should return 401
        """

        headers = {'X-Project-Id': self.dummy_project_id}
        resp = self.client.delete(
            self.dummy_container_ref, use_auth=False, extra_headers=headers
        )
        self.assertEqual(401, resp.status_code)
