# Copyright (c) 2015 Cisco Systems
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
import base64

from Crypto.PublicKey import RSA
from OpenSSL import crypto
from testtools import testcase

from barbican.tests import keys
from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import order_models
from functionaltests.api.v1.models import secret_models


def get_private_key_req(bits, payload):
    return {'name': 'myprivatekey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': bits,
            'secret_type': 'private',
            'payload': payload}


def get_public_key_req(bits, payload):
    return {'name': 'mypublickey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': bits,
            'secret_type': 'public',
            'payload': payload}


def get_passphrase_req(passphrase):
    return {'name': 'mypassphrase',
            'payload_content_type': 'text/plain',
            'secret_type': 'passphrase',
            'payload': passphrase}


def get_container_req(public_key_ref, private_key_ref, passphrase=None):
    if passphrase is None:
        return {"name": "rsacontainer",
                "type": "rsa",
                "secret_refs": [
                    {'name': 'public_key', 'secret_ref': public_key_ref},
                    {'name': 'private_key', 'secret_ref': private_key_ref}]}
    else:
        return {"name": "rsacontainer",
                "type": "rsa",
                "secret_refs": [
                    {'name': 'public_key', 'secret_ref': public_key_ref},
                    {'name': 'private_key', 'secret_ref': private_key_ref},
                    {'name': 'private_key_passphrase',
                     'secret_ref': passphrase}]}


def get_certificate_req(payload):
    return {'name': 'mycertificate',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'secret_type': 'certificate',
            'payload': payload}


def get_order_create_rsa_container():
    return {'type': 'asymmetric',
            "meta": {"name": "ordered rsacontainer",
                     "algorithm": "rsa",
                     "bit_length": 1024,
                     "mode": "cbc",
                     "payload_content_type": "application/octet-stream"}}


def get_order_create_rsa_container_with_passphrase():
    return {'type': 'asymmetric',
            "meta": {"name": "ordered rsacontainer",
                     "algorithm": "rsa",
                     "bit_length": 1024,
                     "passphrase": "password",
                     "mode": "cbc",
                     "payload_content_type": "application/octet-stream"}}


def get_order_create_certificate(container_ref):
    return {'type': 'certificate',
            'meta': {'request_type': 'stored-key',
                     'container_ref': container_ref,
                     'subject_dn': 'cn=server.example.com,o=example.com',
                     'requestor_name': 'Barbican User',
                     'requestor_email': 'user@example.com',
                     'requestor_phone': '555-1212'}}


def get_order_create_certificate_simple_cmc(csr):
    return {'type': 'certificate',
            'meta': {'request_type': 'simple-cmc',
                     'requestor_name': 'Barbican User',
                     'requestor_email': 'user@example.com',
                     'requestor_phone': '555-1212',
                     'request_data': csr}}


@utils.parameterized_test_case
class RSATestCase(base.TestCase):
    """Positive test cases for all ways of working with RSA keys

    These tests are meant to be 'real'.  All input is created
    using OpenSSL commands and all results verified by OpenSSL.
    """

    def setUp(self):
        super(RSATestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.container_behaviors =\
            container_behaviors.ContainerBehaviors(self.client)
        self.order_behaviors =\
            order_behaviors.OrderBehaviors(self.client)

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        self.container_behaviors.delete_all_created_containers()
        self.order_behaviors.delete_all_created_orders()
        super(RSATestCase, self).tearDown()

    def get_secret_dict(self, secret_refs):
        # get the secrets from the container
        secret_dict = {}
        for secret in secret_refs:
            self.assertIsNotNone(secret.secret_ref)
            secret_resp = self.secret_behaviors.get_secret(
                secret.secret_ref, "application/octet-stream")
            self.assertIsNotNone(secret_resp)
            secret_dict[secret.name] = secret_resp.content
        return secret_dict

    @testcase.attr('positive')
    def test_rsa_check_input_keys(self):
        """Verify the keys input for test cases"""

        # prove pyOpenSSL can parse the original private key
        pem = keys.get_private_key_pkcs8()
        crypto.load_privatekey(crypto.FILETYPE_PEM, pem)

        # prove pyCrypto can parse the original public key
        pem = keys.get_public_key_pem()
        RSA.importKey(pem)

        # prove pyOpenSSL can parse the original encrypted private key
        pem = keys.get_encrypted_private_key_pkcs8()
        passphrase = keys.get_passphrase_txt()
        crypto.load_privatekey(crypto.FILETYPE_PEM,
                               pem,
                               passphrase)

        # prove OpenSSL can parse the original certificate
        pem = keys.get_certificate_pem()
        crypto.load_certificate(crypto.FILETYPE_PEM, pem)

    @testcase.attr('positive')
    def test_rsa_create_and_get_private_key(self):
        """Create a private key secret with one Post, then Get"""

        # make a secret
        bits = 2048
        pem = keys.get_private_key_pkcs8()

        # create with Post to server
        test_model = secret_models.SecretModel(
            **get_private_key_req(bits, base64.b64encode(pem)))
        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # retrieve with Get to server
        content_type = 'application/octet-stream'
        get_resp = self.secret_behaviors.get_secret(secret_ref, content_type)
        self.assertEqual(200, get_resp.status_code)

        # check that returned key is same as original key
        self.assertEqual(pem, get_resp.content)

    @testcase.attr('positive')
    def test_rsa_create_and_get_public_key(self):
        """Create a public key secret with one Post, then Get"""

        # make a secret
        bits = 2048
        pem = keys.get_public_key_pem()

        # create with Post to server
        test_model = secret_models.SecretModel(
            **get_public_key_req(bits, base64.b64encode(pem)))
        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # retrieve with Get to server
        content_type = 'application/octet-stream'
        get_resp = self.secret_behaviors.get_secret(secret_ref, content_type)
        self.assertEqual(200, get_resp.status_code)

        # check that returned pem is same as original pem
        self.assertEqual(pem, get_resp.content)

    @testcase.attr('positive')
    def test_rsa_two_step_create_and_get_public_key(self):
        """Create a public key secret with Post and Put, then Get"""

        # make a secret
        bits = 2048
        pem = keys.get_public_key_pem()

        # create with Post to server
        create_req = get_public_key_req(bits, base64.b64encode(pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(
            **create_req)
        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # update with Put to server
        update_resp = self.secret_behaviors.update_secret_payload(
            secret_ref,
            pem,
            'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

        # retrieve with Get to server
        content_type = 'application/octet-stream'
        get_resp = self.secret_behaviors.get_secret(secret_ref, content_type)
        self.assertEqual(200, get_resp.status_code)

        # check that returned pem is same as original pem
        self.assertEqual(pem, get_resp.content)

    @testcase.attr('positive')
    def test_rsa_two_step_create_and_get_private_key(self):
        """Create a private key secret with Post and Put, then Get"""

        # make a secret
        bits = 2048
        pem = keys.get_private_key_pkcs8()

        # create with Post to server
        create_req = get_private_key_req(bits, base64.b64encode(pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(
            **create_req)
        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # update with Put to server
        update_resp = self.secret_behaviors.update_secret_payload(
            secret_ref,
            pem,
            'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

        # retrieve with Get to server
        content_type = 'application/octet-stream'
        get_resp = self.secret_behaviors.get_secret(secret_ref, content_type)
        self.assertEqual(200, get_resp.status_code)

        # check that returned pem is same as original pem
        self.assertEqual(pem, get_resp.content)

    @testcase.attr('positive')
    def test_rsa_create_and_get_passphrase(self):
        """Create a passphrase secret with one Post, then Get"""

        # make a secret
        passphrase = keys.get_passphrase_txt()

        # create with Post to server
        test_model = secret_models.SecretModel(
            **get_passphrase_req(passphrase))
        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # retrieve with Get to server
        content_type = 'application/octet-stream'
        get_resp = self.secret_behaviors.get_secret(secret_ref, content_type)
        self.assertEqual(200, get_resp.status_code)

        # check that returned phrase is same as original phrase
        self.assertEqual(passphrase, get_resp.content)

    @testcase.attr('positive')
    def test_rsa_create_and_get_certificate_secret(self):
        """Create a certificate secret with one Post, then Get"""

        # make a secret
        pem = keys.get_certificate_pem()

        # create with Post to server
        test_model = secret_models.SecretModel(
            **get_certificate_req(base64.b64encode(pem)))
        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # retrieve with Get to server
        content_type = 'application/octet-stream'
        get_resp = self.secret_behaviors.get_secret(secret_ref, content_type)
        self.assertEqual(200, get_resp.status_code)

        # check that returned certificate is same as original certificate
        self.assertEqual(pem, get_resp.content)

    @testcase.attr('positive')
    def test_rsa_two_step_create_and_get_certificate_secret(self):
        """Create a certificate secret with Post and Put, then Get"""

        # make a secret
        pem = keys.get_certificate_pem()

        # create with Post to server
        create_req = get_certificate_req(base64.b64encode(pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(
            **create_req)
        resp, secret_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # update with Put to server
        update_resp = self.secret_behaviors.update_secret_payload(
            secret_ref,
            pem,
            'application/octet-stream',
            None)
        self.assertEqual(204, update_resp.status_code)

        # retrieve with Get to server
        content_type = 'application/octet-stream'
        get_resp = self.secret_behaviors.get_secret(secret_ref, content_type)
        self.assertEqual(200, get_resp.status_code)

        # check that returned pem is same as original pem
        self.assertEqual(pem, get_resp.content)

    @testcase.attr('positive')
    def test_rsa_create_and_get_container(self):
        """Create an rsa container with one Post, then Get"""

        # make the secrets
        bits = 2048
        private_pem = keys.get_private_key_pkcs8()
        public_pem = keys.get_public_key_pem()

        # create private secret with Post to server
        test_model = secret_models.SecretModel(
            **get_private_key_req(bits, base64.b64encode(private_pem)))
        resp, private_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # create public secret with Post to server
        test_model = secret_models.SecretModel(
            **get_public_key_req(bits, base64.b64encode(public_pem)))
        resp, public_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # create container with Post to server
        test_model = container_models.ContainerModel(
            **get_container_req(public_ref, private_ref))
        resp, container_ref =\
            self.container_behaviors.create_container(test_model)
        self.assertEqual(201, resp.status_code)

        # retrieve container with Get to server
        get_resp = self.container_behaviors.get_container(container_ref)
        self.assertEqual(get_resp.status_code, 200)

        # get the secrets from the container
        secret_dict = self.get_secret_dict(get_resp.model.secret_refs)

        # check that returned secrets are same as original secrets
        self.assertEqual(private_pem, secret_dict['private_key'])
        self.assertEqual(public_pem, secret_dict['public_key'])

    @testcase.attr('positive')
    def test_rsa_create_and_get_container_with_passphrase(self):
        """Create an rsa container with one Post, then Get"""

        # make the secrets
        bits = 2048
        private_pem = keys.get_encrypted_private_key_pkcs8()
        public_pem = keys.get_public_key_pem()
        passphrase = keys.get_passphrase_txt()

        # create private secret with Post to server
        test_model = secret_models.SecretModel(
            **get_private_key_req(bits, base64.b64encode(private_pem)))
        resp, private_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # create public secret with Post to server
        test_model = secret_models.SecretModel(
            **get_public_key_req(bits, base64.b64encode(public_pem)))
        resp, public_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # create passphrase with Post to server
        test_model = secret_models.SecretModel(
            **get_passphrase_req(passphrase))
        resp, passphrase_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # create container with Post to server
        test_model = container_models.ContainerModel(
            **get_container_req(public_ref, private_ref, passphrase_ref))
        resp, container_ref =\
            self.container_behaviors.create_container(test_model)
        self.assertEqual(201, resp.status_code)

        # retrieve container with Get to server
        get_resp = self.container_behaviors.get_container(container_ref)
        self.assertEqual(get_resp.status_code, 200)

        # get the secrets from the container
        secret_dict = self.get_secret_dict(get_resp.model.secret_refs)

        # check that returned secrets are same as original secrets
        self.assertEqual(private_pem, secret_dict['private_key'])
        self.assertEqual(public_pem, secret_dict['public_key'])
        self.assertEqual(passphrase, secret_dict['private_key_passphrase'])

    @testcase.attr('positive')
    def test_rsa_order_container(self):
        """Order an rsa container with asymmetric keys."""

        # order an rsa container
        test_model = order_models.OrderModel(
            **get_order_create_rsa_container())
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)

        # get the order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)

        # get the container
        container_resp = self.container_behaviors.get_container(
            order_resp.model.container_ref)
        self.assertEqual(container_resp.status_code, 200)

        # get the secrets from the container
        secret_dict = self.get_secret_dict(container_resp.model.secret_refs)

        # verify the secrets
        self.assertIsNotNone(secret_dict['private_key'])
        self.assertIsNotNone(secret_dict['public_key'])
        # verify returned keys can be parsed
        crypto.load_privatekey(crypto.FILETYPE_PEM, secret_dict['private_key'])
        RSA.importKey(secret_dict['public_key'])

    @testcase.attr('positive')
    def test_rsa_order_container_with_passphrase(self):
        """Order an rsa container with asymmetric keys and a passphrase."""

        # order an rsa container
        test_model = order_models.OrderModel(
            **get_order_create_rsa_container_with_passphrase())
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)

        # get the order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)

        # get the container
        container_resp = self.container_behaviors.get_container(
            order_resp.model.container_ref)
        self.assertEqual(container_resp.status_code, 200)

        # get the secrets from the container
        secret_dict = self.get_secret_dict(container_resp.model.secret_refs)

        # verify the secrets
        self.assertEqual('password', secret_dict['private_key_passphrase'])
        # verify returned keys can be parsed
        crypto.load_privatekey(crypto.FILETYPE_PEM,
                               secret_dict['private_key'],
                               secret_dict['private_key_passphrase'])
        RSA.importKey(secret_dict['public_key'])

    @testcase.attr('positive')
    def test_rsa_create_container_from_two_step_secrets(self):
        """Order certificate from created rsa container."""

        # store public key
        bits = 2048
        public_pem = keys.get_public_key_pem()
        create_req = get_public_key_req(bits, base64.b64encode(public_pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, public_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)
        # update with Put to server
        update_resp = self.secret_behaviors.update_secret_payload(
            public_ref, public_pem, 'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

        # store private key
        private_pem = keys.get_private_key_pkcs8()
        create_req = get_private_key_req(bits, base64.b64encode(private_pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, private_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)
        update_resp = self.secret_behaviors.update_secret_payload(
            private_ref, private_pem, 'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

        # create container with Post to server
        test_model = container_models.ContainerModel(
            **get_container_req(public_ref, private_ref))
        resp, container_ref =\
            self.container_behaviors.create_container(test_model)
        self.assertEqual(201, resp.status_code)

        # get the container
        container_resp = self.container_behaviors.get_container(container_ref)
        self.assertEqual(container_resp.status_code, 200)

        # get the secrets from the container
        secret_dict = self.get_secret_dict(container_resp.model.secret_refs)

        # check that returned secrets are same as original secrets
        self.assertEqual(private_pem, secret_dict['private_key'])
        self.assertEqual(public_pem, secret_dict['public_key'])

    @testcase.attr('positive')
    def test_rsa_order_certificate_from_generated_container(self):
        """Order a certificate from generated rsa container."""

        # order an rsa container
        test_model = order_models.OrderModel(
            **get_order_create_rsa_container())
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)

        # get the container order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)

        # get the container ref
        container_resp = self.container_behaviors.get_container(
            order_resp.model.container_ref)
        self.assertEqual(container_resp.status_code, 200)
        container_ref = order_resp.model.container_ref

        # order an rsa certificate
        test_model = order_models.OrderModel(
            **get_order_create_certificate(container_ref))
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)

        # get the certificate order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)
        self.assertEqual(order_resp.model.status, "PENDING")
        self.assertEqual(order_resp.model.sub_status, "cert_request_pending")

    @testcase.attr('positive')
    def test_rsa_order_certificate_from_generated_container_with_pass(self):
        """Order certificate from generated rsa container with passphrase."""

        # order an rsa container
        test_model = order_models.OrderModel(
            **get_order_create_rsa_container_with_passphrase())
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(create_resp.status_code, 202)

        # get the container order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)

        # get the container ref
        container_resp = self.container_behaviors.get_container(
            order_resp.model.container_ref)
        self.assertEqual(container_resp.status_code, 200)
        container_ref = order_resp.model.container_ref

        # order an rsa certificate
        test_model = order_models.OrderModel(
            **get_order_create_certificate(container_ref))
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)

        # get the certificate order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)
        self.assertEqual(order_resp.model.status, "PENDING")
        self.assertEqual(order_resp.model.sub_status, "cert_request_pending")

    @testcase.attr('positive')
    def test_rsa_order_certificate_from_created_container(self):
        """Order certificate from created rsa container."""

        # store public key
        bits = 2048
        public_pem = keys.get_public_key_pem()
        create_req = get_public_key_req(bits, base64.b64encode(public_pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, public_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)
        # update with Put to server
        update_resp = self.secret_behaviors.update_secret_payload(
            public_ref, public_pem, 'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

        # store private key
        private_pem = keys.get_private_key_pkcs8()
        create_req = get_private_key_req(bits, base64.b64encode(private_pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, private_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)
        update_resp = self.secret_behaviors.update_secret_payload(
            private_ref, private_pem, 'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

        # create container with Post to server
        test_model = container_models.ContainerModel(
            **get_container_req(public_ref, private_ref))
        resp, container_ref =\
            self.container_behaviors.create_container(test_model)
        self.assertEqual(201, resp.status_code)

        # order an rsa certificate
        test_model = order_models.OrderModel(
            **get_order_create_certificate(container_ref))
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)

        # get the certificate order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)
        self.assertEqual(order_resp.model.status, "PENDING")
        self.assertEqual(order_resp.model.sub_status, "cert_request_pending")

    @testcase.attr('positive')
    def test_rsa_order_certificate_from_created_container_with_pass(self):
        """Order certificate from created rsa container with passphrase."""

        # store public key
        bits = 2048
        public_pem = keys.get_public_key_pem()
        create_req = get_public_key_req(bits, base64.b64encode(public_pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, public_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)
        # update with Put to server
        update_resp = self.secret_behaviors.update_secret_payload(
            public_ref, public_pem, 'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

        # store private key
        private_pem = keys.get_private_key_pkcs8()
        create_req = get_private_key_req(bits, base64.b64encode(private_pem))
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, private_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)
        update_resp = self.secret_behaviors.update_secret_payload(
            private_ref, private_pem, 'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

        # store the passphrase
        passphrase = keys.get_passphrase_txt()
        test_model = secret_models.SecretModel(
            **get_passphrase_req(passphrase))
        resp, passphrase_ref = self.secret_behaviors.create_secret(test_model)
        self.assertEqual(201, resp.status_code)

        # create the container
        test_model = container_models.ContainerModel(
            **get_container_req(public_ref, private_ref, passphrase_ref))
        resp, container_ref =\
            self.container_behaviors.create_container(test_model)
        self.assertEqual(201, resp.status_code)

        # order an rsa certificate
        test_model = order_models.OrderModel(
            **get_order_create_certificate(container_ref))
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)

        # get the certificate order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)
        self.assertEqual(order_resp.model.status, "PENDING")
        self.assertEqual(order_resp.model.sub_status, "cert_request_pending")

    @testcase.attr('positive')
    def test_rsa_order_certificate_from_csr(self):
        """Order certificate from csr"""

        # order an rsa certificate
        csr = keys.get_csr_pem()
        test_model = order_models.OrderModel(
            **get_order_create_certificate_simple_cmc(base64.b64encode(csr)))
        create_resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, create_resp.status_code)

        # get the certificate order
        order_resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(order_resp.status_code, 200)
        self.assertEqual(order_resp.model.status, "PENDING")
        self.assertEqual(order_resp.model.sub_status, "cert_request_pending")
