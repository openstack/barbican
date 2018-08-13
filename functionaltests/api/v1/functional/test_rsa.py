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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto
import testtools
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


def get_private_key_req(payload):
    return {'name': 'myprivatekey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': 'private',
            'payload': payload}


def get_public_key_req(payload):
    return {'name': 'mypublickey',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'algorithm': 'rsa',
            'bit_length': 2048,
            'secret_type': 'public',
            'payload': payload}


def get_passphrase_req(passphrase):
    return {'name': 'mypassphrase',
            'payload_content_type': 'text/plain',
            'secret_type': 'passphrase',
            'payload': passphrase}


def get_container_req(public_key_ref, private_key_ref, passphrase=None):
    request = {"name": "rsacontainer",
               "type": "rsa",
               "secret_refs": [
                   {'name': 'public_key', 'secret_ref': public_key_ref},
                   {'name': 'private_key', 'secret_ref': private_key_ref}]}
    if passphrase:
        request["secret_refs"].append(
            {'name': 'private_key_passphrase', 'secret_ref': passphrase})
    return request


def get_certificate_req(payload):
    return {'name': 'mycertificate',
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64',
            'secret_type': 'certificate',
            'payload': payload}


def get_order_rsa_container():
    return {'type': 'asymmetric',
            "meta": {"name": "ordered rsacontainer",
                     "algorithm": "rsa",
                     "bit_length": 2048,
                     "mode": "cbc"}}


def get_order_rsa_container_with_passphrase():
    return {'type': 'asymmetric',
            "meta": {"name": "ordered rsacontainer",
                     "algorithm": "rsa",
                     "bit_length": 2048,
                     "passphrase": "password",
                     "mode": "cbc"}}


def get_order_certificate(container_ref):
    return {'type': 'certificate',
            'meta': {'request_type': 'stored-key',
                     'container_ref': container_ref,
                     'subject_dn': 'cn=server.example.com,o=example.com',
                     'requestor_name': 'Barbican User',
                     'requestor_email': 'user@example.com',
                     'requestor_phone': '555-1212'}}


def get_order_certificate_simple_cmc(csr):
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
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client)
        self.order_behaviors = order_behaviors.OrderBehaviors(self.client)

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        self.container_behaviors.delete_all_created_containers()
        self.order_behaviors.delete_all_created_orders()
        super(RSATestCase, self).tearDown()

    @testcase.attr('positive')
    def test_rsa_check_input_keys(self):
        """Verify the input keys for test cases"""

        # prove pyOpenSSL can parse the original private key
        pem = keys.get_private_key_pem()
        crypto.load_privatekey(crypto.FILETYPE_PEM, pem)

        # prove cryptography can parse the original public key
        serialization.load_pem_public_key(
            keys.get_public_key_pem(),
            backend=default_backend()
        )

        # prove pyOpenSSL can parse the original encrypted private key
        pem = keys.get_encrypted_private_key_pem()
        passphrase = keys.get_passphrase_txt()
        crypto.load_privatekey(crypto.FILETYPE_PEM,
                               pem,
                               passphrase)

        # prove OpenSSL can parse the original certificate
        pem = keys.get_certificate_pem()
        crypto.load_certificate(crypto.FILETYPE_PEM, pem)

    @testcase.attr('positive')
    def test_rsa_store_and_get_private_key(self):
        """Post and Get for private key"""
        key_ref = self.store_private_key()
        key = self.get_private_key(key_ref)
        self.verify_private_key_equal(key)

    @testcase.attr('positive')
    def test_rsa_store_and_get_public_key(self):
        """Post and Get for public key"""
        key_ref = self.store_public_key()
        key = self.get_public_key(key_ref)
        self.verify_public_key_equal(key)

    @testcase.attr('positive')
    def test_rsa_two_step_store_and_get_private_key(self):
        """Post, Put, and Get for private key"""
        key_ref = self.create_private_key()
        self.update_private_key(key_ref)
        key = self.get_private_key(key_ref)
        self.verify_private_key_equal(key)

    @testcase.attr('positive')
    def test_rsa_two_step_store_and_get_public_key(self):
        """Post, Put, and Get for public key"""
        key_ref = self.create_public_key()
        self.update_public_key(key_ref)
        key = self.get_public_key(key_ref)
        self.verify_public_key_equal(key)

    @testcase.attr('positive')
    def test_rsa_store_and_get_passphrase(self):
        """Post and Get for passphrase"""
        phrase_ref = self.store_passphrase()
        phrase = self.get_passphrase(phrase_ref)
        self.verify_passphrase_equal(phrase)

    @testcase.attr('positive')
    def test_rsa_store_and_get_certificate_secret(self):
        """Post and Get for certificate"""
        cert_ref = self.store_certificate()
        cert = self.get_certificate(cert_ref)
        self.verify_certificate_equal(cert)

    @testcase.attr('positive')
    def test_rsa_two_step_store_and_get_certificate_secret(self):
        """Post, Put, and Get for certificate"""
        cert_ref = self.create_certificate()
        self.update_certificate(cert_ref)
        cert = self.get_certificate(cert_ref)
        self.verify_certificate_equal(cert)

    @testcase.attr('positive')
    def test_rsa_store_and_get_container(self):
        """Post and Get for container"""
        public_ref = self.store_public_key()
        private_ref = self.store_private_key()
        container_ref = self.store_container(public_ref, private_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_equal(secrets)

    @testcase.attr('positive')
    @testtools.skipIf(utils.is_kmip_enabled(),
                      "PyKMIP does not support this operation")
    def test_rsa_store_and_get_container_with_passphrase(self):
        """Post and Get for container with passphrase"""
        public_ref = self.store_public_key()
        private_ref = self.store_encrypted_private_key()
        phrase_ref = self.store_passphrase()
        container_ref = self.store_container(public_ref,
                                             private_ref,
                                             phrase_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_equal(secrets, with_passphrase=True)

    @testcase.attr('positive')
    @testtools.skipIf(utils.is_vault_enabled() or utils.is_pkcs11_enabled(),
                      "Vault does not support this operation")
    def test_rsa_order_container(self):
        """Post an order for a container"""
        order_ref = self.order_container()
        container_ref = self.get_container_order(order_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_valid(secrets)

    @testcase.attr('positive')
    @testtools.skipIf(utils.is_kmip_enabled() or utils.is_vault_enabled()
                      or utils.is_pkcs11_enabled(),
                      "PyKMIP does not support this operation")
    def test_rsa_order_container_with_passphrase(self):
        """Post an order for a container with a passphrase"""
        order_ref = self.order_container(with_passphrase=True)
        container_ref = self.get_container_order(order_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_valid(secrets, with_passphrase=True)

    @testcase.attr('positive')
    def test_rsa_store_container_from_two_step_secrets(self):
        """Post an order for a certificate"""
        public_ref = self.create_public_key()
        self.update_public_key(public_ref)
        private_ref = self.create_private_key()
        self.update_private_key(private_ref)
        container_ref = self.store_container(public_ref, private_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_equal(secrets)

    @testcase.attr('positive')
    @testtools.skipIf(utils.is_vault_enabled() or utils.is_pkcs11_enabled(),
                      "Vault does not support this operation")
    def test_rsa_order_certificate_from_ordered_container(self):
        """Post an order for a certificate"""
        order_ref = self.order_container()
        container_ref = self.get_container_order(order_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_valid(secrets)
        order_ref = self.order_certificate(container_ref)
        order_status = self.get_certificate_order(order_ref)
        self.verify_certificate_order_status(order_status)

    @testcase.attr('positive')
    @testtools.skipIf(utils.is_kmip_enabled() or utils.is_vault_enabled()
                      or utils.is_pkcs11_enabled(),
                      "PyKMIP does not support this operation")
    def test_rsa_order_certificate_from_ordered_container_with_pass(self):
        """Post an order for a certificate"""
        order_ref = self.order_container(with_passphrase=True)
        container_ref = self.get_container_order(order_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_valid(secrets, with_passphrase=True)
        order_ref = self.order_certificate(container_ref)
        order_status = self.get_certificate_order(order_ref)
        self.verify_certificate_order_status(order_status)

    @testcase.attr('positive')
    def test_rsa_order_certificate_from_stored_container(self):
        """Post an order for a certificate"""
        public_ref = self.create_public_key()
        self.update_public_key(public_ref)
        private_ref = self.create_private_key()
        self.update_private_key(private_ref)
        container_ref = self.store_container(public_ref, private_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_equal(secrets)
        order_ref = self.order_certificate(container_ref)
        order_status = self.get_certificate_order(order_ref)
        self.verify_certificate_order_status(order_status)

    @testcase.attr('positive')
    @testtools.skipIf(utils.is_kmip_enabled(),
                      "PyKMIP does not support this operation")
    def test_rsa_order_certificate_from_stored_container_with_pass(self):
        """Post an order for a certificate"""
        public_ref = self.store_public_key()
        private_ref = self.store_encrypted_private_key()
        phrase_ref = self.store_passphrase()
        container_ref = self.store_container(
            public_ref, private_ref, phrase_ref)
        secrets = self.get_container(container_ref)
        self.verify_container_keys_equal(secrets, with_passphrase=True)
        order_ref = self.order_certificate(container_ref)
        order_status = self.get_certificate_order(order_ref)
        self.verify_certificate_order_status(order_status)

    @testcase.attr('positive')
    def test_rsa_order_certificate_from_csr(self):
        """Post an order for a certificate"""
        order_ref = self.order_certificate_from_csr()
        order_status = self.get_certificate_order(order_ref)
        self.verify_certificate_order_status(order_status)

# ----------------------- Helper Functions ---------------------------
    def store_private_key(self):
        pem = keys.get_private_key_pem()
        test_model = secret_models.SecretModel(
            **get_private_key_req(base64.b64encode(pem)))
        resp, private_key_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return private_key_secret_ref

    def get_private_key(self, private_key_secret_ref):
        resp = self.secret_behaviors.get_secret(
            private_key_secret_ref, 'application/octet-stream')
        self.assertEqual(200, resp.status_code)
        return resp.content

    def verify_private_key_equal(self, retrieved_private_key):
        pem = keys.get_private_key_pem()
        self.assertEqual(pem, retrieved_private_key)

    def create_private_key(self):
        create_req = get_private_key_req("")
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, private_key_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return private_key_secret_ref

    def update_private_key(self, private_key_secret_ref):
        pem = keys.get_private_key_pem()
        update_resp = self.secret_behaviors.update_secret_payload(
            private_key_secret_ref,
            pem,
            'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

    def store_encrypted_private_key(self):
        pem = keys.get_encrypted_private_key_pem()
        test_model = secret_models.SecretModel(
            **get_private_key_req(base64.b64encode(pem)))
        resp, private_key_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return private_key_secret_ref

    def get_encrypted_private_key(self, private_key_secret_ref):
        resp = self.secret_behaviors.get_secret(
            private_key_secret_ref, 'application/octet-stream')
        self.assertEqual(200, resp.status_code)
        return resp.content

    def verify_encrypted_private_key_equal(self, retrieved_private_key):
        pem = keys.get_encrypted_private_key_pem()
        self.assertEqual(pem, retrieved_private_key)

    def create_encrypted_private_key(self):
        create_req = get_private_key_req("")
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, private_key_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return private_key_secret_ref

    def update_encrypted_private_key(self, private_key_secret_ref):
        pem = keys.get_encrypted_private_key_pem()
        update_resp = self.secret_behaviors.update_secret_payload(
            private_key_secret_ref,
            pem,
            'application/octet-stream')
        self.assertEqual(204, update_resp.status_code)

    def store_public_key(self):
        pem = keys.get_public_key_pem()
        test_model = secret_models.SecretModel(
            **get_public_key_req(base64.b64encode(pem)))
        resp, public_key_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return public_key_secret_ref

    def get_public_key(self, public_key_secret_ref):
        resp = self.secret_behaviors.get_secret(
            public_key_secret_ref, 'application/octet-stream')
        self.assertEqual(200, resp.status_code)
        return resp.content

    def verify_public_key_equal(self, retrieved_public_key):
        pem = keys.get_public_key_pem()
        self.assertEqual(pem, retrieved_public_key)

    def create_public_key(self):
        create_req = get_public_key_req("")
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, public_key_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return public_key_secret_ref

    def update_public_key(self, public_key_secret_ref):
        pem = keys.get_public_key_pem()
        resp = self.secret_behaviors.update_secret_payload(
            public_key_secret_ref,
            pem,
            'application/octet-stream')
        self.assertEqual(204, resp.status_code)

    def store_passphrase(self):
        passphrase = keys.get_passphrase_txt()
        test_model = secret_models.SecretModel(
            **get_passphrase_req(passphrase))
        resp, passphrase_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return passphrase_secret_ref

    def get_passphrase(self, passphrase_secret_ref):
        content_type = 'application/octet-stream'
        get_resp = self.secret_behaviors.get_secret(
            passphrase_secret_ref, content_type)
        self.assertEqual(200, get_resp.status_code)
        return get_resp.content

    def verify_passphrase_equal(self, retrieved_passphrase):
        passphrase = keys.get_passphrase_txt()
        self.assertEqual(passphrase, retrieved_passphrase)

    def store_certificate(self):
        pem = keys.get_certificate_pem()
        test_model = secret_models.SecretModel(
            **get_certificate_req(base64.b64encode(pem)))
        resp, certificate_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return certificate_secret_ref

    def get_certificate(self, certificate_secret_ref):
        content_type = 'application/octet-stream'
        resp = self.secret_behaviors.get_secret(
            certificate_secret_ref, content_type)
        self.assertEqual(200, resp.status_code)
        return resp.content

    def verify_certificate_equal(self, retrieved_certificate):
        pem = keys.get_certificate_pem()
        self.assertEqual(pem, retrieved_certificate)

    def create_certificate(self):
        create_req = get_certificate_req("")
        del create_req['payload']
        del create_req['payload_content_type']
        del create_req['payload_content_encoding']
        test_model = secret_models.SecretModel(**create_req)
        resp, certificate_secret_ref = self.secret_behaviors.create_secret(
            test_model)
        self.assertEqual(201, resp.status_code)
        return certificate_secret_ref

    def update_certificate(self, certificate_secret_ref):
        pem = keys.get_certificate_pem()
        resp = self.secret_behaviors.update_secret_payload(
            certificate_secret_ref,
            pem,
            'application/octet-stream')
        self.assertEqual(204, resp.status_code)

    def store_container(self,
                        public_key_secret_ref,
                        private_key_secret_ref,
                        passphrase_secret_ref=None):
        test_model = container_models.ContainerModel(
            **get_container_req(public_key_secret_ref,
                                private_key_secret_ref,
                                passphrase_secret_ref))
        resp, container_ref = self.container_behaviors.create_container(
            test_model)
        self.assertEqual(201, resp.status_code)
        return container_ref

    def make_secret_dict(self, secret_refs):
        """Get the secrets from the container and store in a dict"""
        secret_dict = {}
        for secret in secret_refs:
            self.assertIsNotNone(secret.secret_ref)
            secret_resp = self.secret_behaviors.get_secret(
                secret.secret_ref, "application/octet-stream")
            self.assertIsNotNone(secret_resp)
            secret_dict[secret.name] = secret_resp.content
        return secret_dict

    def get_container(self, container_ref):
        resp = self.container_behaviors.get_container(container_ref)
        self.assertEqual(200, resp.status_code)
        return self.make_secret_dict(resp.model.secret_refs)

    def verify_container_keys_equal(self,
                                    secret_dict,
                                    with_passphrase=False):
        if with_passphrase:
            passphrase = keys.get_passphrase_txt()
            self.assertEqual(passphrase,
                             secret_dict['private_key_passphrase'])
            private_pem = keys.get_encrypted_private_key_pem()
        else:
            self.assertNotIn('private_key_passphrase', secret_dict)
            private_pem = keys.get_private_key_pem()
        self.assertEqual(private_pem, secret_dict['private_key'])
        public_pem = keys.get_public_key_pem()
        self.assertEqual(public_pem, secret_dict['public_key'])

    def verify_container_keys_valid(self,
                                    secret_dict,
                                    with_passphrase=False):
        # verify generated keys can be parsed
        if with_passphrase:
            crypto.load_privatekey(
                crypto.FILETYPE_PEM,
                secret_dict['private_key'],
                secret_dict['private_key_passphrase'])
        else:
            self.assertNotIn('private_key_passphrase', secret_dict)
            crypto.load_privatekey(
                crypto.FILETYPE_PEM,
                secret_dict['private_key'])
        serialization.load_pem_public_key(
            secret_dict['public_key'],
            backend=default_backend()
        )

    def order_container(self, with_passphrase=False):
        if with_passphrase:
            test_model = order_models.OrderModel(
                **get_order_rsa_container_with_passphrase())
        else:
            test_model = order_models.OrderModel(
                **get_order_rsa_container())
        resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, resp.status_code)
        return order_ref

    def get_container_order(self, order_ref):
        resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(200, resp.status_code)
        return resp.model.container_ref

    def order_certificate(self, container_ref):
        test_model = order_models.OrderModel(
            **get_order_certificate(container_ref))
        resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, resp.status_code)
        return order_ref

    def get_certificate_order(self, order_ref):
        resp = self.order_behaviors.get_order(order_ref)
        self.assertEqual(200, resp.status_code)
        order_status = (resp.model.status,
                        resp.model.sub_status)
        return order_status

    def verify_certificate_order_status(self, order_status):
        self.assertEqual(("PENDING", "cert_request_pending"),
                         order_status)

    def order_certificate_from_csr(self):
        csr = keys.get_csr_pem()
        test_model = order_models.OrderModel(
            **get_order_certificate_simple_cmc(base64.b64encode(csr)))
        resp, order_ref = self.order_behaviors.create_order(test_model)
        self.assertEqual(202, resp.status_code)
        return order_ref
