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
