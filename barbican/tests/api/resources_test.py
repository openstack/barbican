# Copyright (c) 2013 Rackspace, Inc.
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

from mock import MagicMock
import falcon
import json
import unittest

from datetime import datetime
from barbican.api.resources import VersionResource
from barbican.api.resources import TenantsResource, TenantResource
from barbican.api.resources import CSRsResource, CSRResource
from barbican.api.resources import CertificatesResource, CertificateResource
from barbican.api.resources import SecretsResource, SecretResource
from barbican.model.models import Certificate, CSR, Secret, Tenant
from barbican.model.repositories import CSRRepo, CertificateRepo
from barbican.model.repositories import TenantRepo, SecretRepo
from barbican.crypto.fields import decrypt_value, encrypt_value
from barbican.common import config
from barbican.common import exception


def suite():
    suite = unittest.TestSuite()
    suite.addTest(WhenTestingVersionResource())

    return suite


class WhenTestingVersionResource(unittest.TestCase):

    def setUp(self):
        self.req = MagicMock()
        self.resp = MagicMock()
        self.resource = VersionResource()

    def test_should_return_200_on_get(self):
        self.resource.on_get(self.req, self.resp)
        self.assertEqual(falcon.HTTP_200, self.resp.status)

    def test_should_return_version_json(self):
        self.resource.on_get(self.req, self.resp)

        parsed_body = json.loads(self.resp.body)

        self.assertTrue('v1' in parsed_body)
        self.assertEqual('current', parsed_body['v1'])


class WhenCreatingTenantsUsingTenantsResource(unittest.TestCase):

    def setUp(self):
        self.username = '1234'
        self.json = u'{ "username" : "%s" }' % self.username

        self.tenant_repo = MagicMock()
        self.tenant_repo.find_by_name.return_value = None
        self.tenant_repo.create_from.return_value = None

        self.stream = MagicMock()
        self.stream.read.return_value = self.json

        self.req = MagicMock()
        self.req.stream = self.stream

        self.resp = MagicMock()
        self.resource = TenantsResource(self.tenant_repo)

    def test_should_add_new_tenant(self):
        self.resource.on_post(self.req, self.resp)

        self.tenant_repo.find_by_name.assert_called_once_with(
            name=self.username, suppress_exception=True)
        args, kwargs = self.tenant_repo.create_from.call_args
        assert isinstance(args[0], Tenant)

    def test_should_throw_exception_for_tenants_that_exist(self):
        self.tenant_repo.find_by_name.return_value = Tenant()

        with self.assertRaises(falcon.HTTPError):
            self.resource.on_post(self.req, self.resp)

        self.tenant_repo.find_by_name.assert_called_once_with(
            name=self.username, suppress_exception=True)


class WhenGettingOrDeletingTenantUsingTenantResource(unittest.TestCase):

    def setUp(self):
        self.username = '1234'

        self.tenant = Tenant()
        self.tenant.id = "id1"
        self.tenant.username = self.username

        self.tenant_repo = MagicMock()
        self.tenant_repo.get.return_value = self.tenant
        self.tenant_repo.delete_entity.return_value = None

        self.req = MagicMock()
        self.resp = MagicMock()
        self.resource = TenantResource(self.tenant_repo)

    def test_should_get_tenant(self):
        self.resource.on_get(self.req, self.resp, self.tenant.id)

        self.tenant_repo.get.assert_called_once_with(entity_id=self.tenant.id)

    def test_should_delete_tenant(self):
        self.resource.on_delete(self.req, self.resp, self.tenant.id)

        self.tenant_repo.get.assert_called_once_with(entity_id=self.tenant.id)
        self.tenant_repo.delete_entity.assert_called_once_with(self.tenant)

    def test_should_throw_exception_for_get_when_tenant_not_found(self):
        self.tenant_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_get(self.req, self.resp, self.tenant.id)

    def test_should_throw_exception_for_delete_when_tenant_not_found(self):
        self.tenant_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_delete(self.req, self.resp, self.tenant.id)


class WhenCreatingSecretsUsingSecretsResource(unittest.TestCase):

    def setUp(self):
        self.name = 'name'
        self.secret = 'secret'
        self.json = u'{"name":"%s","secret":"%s"}' % (self.name, self.secret)

        self.username = 'user1234'
        self.tenant_id = 'tenantid1234'
        self.tenant = Tenant()
        self.tenant.id = self.tenant_id
        self.tenant.username = self.username
        self.tenant_repo = MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.secret_repo = MagicMock()
        self.secret_repo.create_from.return_value = None
        self.secret_repo.find_by_name.return_value = None

        self.stream = MagicMock()
        self.stream.read.return_value = self.json

        self.req = MagicMock()
        self.req.stream = self.stream

        self.resp = MagicMock()
        self.resource = SecretsResource(self.tenant_repo, self.secret_repo)

    def test_should_add_new_secret(self):
        self.resource.on_post(self.req, self.resp, self.tenant_id)

        args, kwargs = self.secret_repo.create_from.call_args
        secret = args[0]
        assert isinstance(secret, Secret)

        assert encrypt_value(self.secret) == secret.secret


class WhenGettingOrDeletingSecretUsingSecretResource(unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.name = 'name1234'
        self.secret_value = 'secretvalue'

        self.secret = Secret()
        self.secret.id = "id1"
        self.secret.name = self.name
        self.secret.secret = encrypt_value(self.secret_value)

        self.secret_repo = MagicMock()
        self.secret_repo.get.return_value = self.secret
        self.secret_repo.delete_entity.return_value = None

        self.req = MagicMock()
        self.resp = MagicMock()
        self.resource = SecretResource(self.secret_repo)

    def test_should_get_secret(self):
        self.resource.on_get(self.req, self.resp, self.tenant_id,
                             self.secret.id)

        self.secret_repo.get.assert_called_once_with(entity_id=self.secret.id)

    def test_should_delete_secret(self):
        self.resource.on_delete(self.req, self.resp, self.tenant_id,
                                self.secret.id)

        self.secret_repo.get.assert_called_once_with(entity_id=self.secret.id)
        self.secret_repo.delete_entity.assert_called_once_with(self.secret)

    def test_should_throw_exception_for_get_when_secret_not_found(self):
        self.secret_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_get(self.req, self.resp, self.tenant_id,
                                 self.secret.id)

    def test_should_throw_exception_for_delete_when_secret_not_found(self):
        self.secret_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_delete(self.req, self.resp, self.tenant_id,
                                    self.secret.id)


class WhenCreatingCSRsUsingCSRsResource(unittest.TestCase):

    def setUp(self):
        self.username = 'user1234'
        self.requestor = 'requestor1234'
        self.tenant_id = 'tenantid1234'

        self.tenant = Tenant()
        self.tenant.id = self.tenant_id
        self.tenant.username = self.username

        self.tenant_repo = MagicMock()
        self.tenant_repo.get.return_value = self.tenant

        self.csr_repo = MagicMock()
        self.csr_repo.create_from.return_value = None

        self.queue_resource = MagicMock()
        self.queue_resource.begin_csr.return_value = None

        self.stream = MagicMock()
        ret_read = u'{ "requestor" : "%s" }' % self.requestor
        self.stream.read.return_value = ret_read

        self.req = MagicMock()
        self.req.stream = self.stream

        self.resp = MagicMock()
        self.resource = CSRsResource(self.tenant_repo, self.csr_repo,
                                     self.queue_resource)

    def test_should_add_new_csr(self):
        self.resource.on_post(self.req, self.resp, self.tenant_id)

        self.queue_resource.begin_csr.assert_called_once_with(csr_id=None)

        args, kwargs = self.csr_repo.create_from.call_args
        assert isinstance(args[0], CSR)


class WhenGettingOrDeletingCSRUsingCSRResource(unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.requestor = 'requestor1234'
        self.csr = CSR()
        self.csr.id = "id1"
        self.csr.requestor = self.requestor

        self.csr_repo = MagicMock()
        self.csr_repo.get.return_value = self.csr
        self.csr_repo.delete_entity.return_value = None

        self.req = MagicMock()
        self.resp = MagicMock()
        self.resource = CSRResource(self.csr_repo)

    def test_should_get_csr(self):
        self.resource.on_get(self.req, self.resp, self.tenant_id, self.csr.id)

        self.csr_repo.get.assert_called_once_with(entity_id=self.csr.id)

    def test_should_delete_csr(self):
        self.resource.on_delete(self.req, self.resp, self.tenant_id,
                                self.csr.id)

        self.csr_repo.get.assert_called_once_with(entity_id=self.csr.id)
        self.csr_repo.delete_entity.assert_called_once_with(self.csr)

    def test_should_throw_exception_for_get_when_csr_not_found(self):
        self.csr_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_get(self.req, self.resp, self.tenant_id,
                                 self.csr.id)

    def test_should_throw_exception_for_delete_when_csr_not_found(self):
        self.csr_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_delete(self.req, self.resp, self.tenant_id,
                                    self.csr.id)


class WhenCreatingCertsUsingCertsResource(unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'

        self.certs_repo = MagicMock()
        self.certs_repo.create_from.side_effect = falcon.HTTPError(
            falcon.HTTP_405, "Error")

        self.req = MagicMock()
        self.resp = MagicMock()
        self.resource = CertificatesResource(self.certs_repo)

    def test_should_fail_to_add_new_cert_directly(self):
        with self.assertRaises(falcon.HTTPError):
            self.resource.on_post(self.req, self.resp, self.tenant_id)


class WhenGettingOrDeletingCertsUsingCertResource(unittest.TestCase):

    def setUp(self):
        self.tenant_id = 'tenant1234'
        self.public_key = 'public_key'
        self.private_key = 'private_key'
        self.cert = Certificate()
        self.cert.id = "id1"
        self.cert.private_key = self.private_key
        self.cert.public_key = self.public_key

        self.cert_repo = MagicMock()
        self.cert_repo.get.return_value = self.cert
        self.cert_repo.delete_entity.return_value = None

        self.req = MagicMock()
        self.resp = MagicMock()
        self.resource = CertificateResource(self.cert_repo)

    def test_should_get_cert(self):
        self.resource.on_get(self.req, self.resp, self.tenant_id,
                             self.cert.id)

        self.cert_repo.get.assert_called_once_with(entity_id=self.cert.id)

    def test_should_delete_cert(self):
        self.resource.on_delete(self.req, self.resp, self.tenant_id,
                                self.cert.id)

        self.cert_repo.get.assert_called_once_with(entity_id=self.cert.id)
        self.cert_repo.delete_entity.assert_called_once_with(self.cert)

    def test_should_throw_exception_for_get_when_cert_not_found(self):
        self.cert_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_get(self.req, self.resp, self.tenant_id,
                                 self.cert.id)

    def test_should_throw_exception_for_delete_when_cert_not_found(self):
        self.cert_repo.get.side_effect = exception.NotFound(
            "Test not found exception")

        with self.assertRaises(exception.NotFound):
            self.resource.on_delete(self.req, self.resp, self.tenant_id,
                                    self.cert.id)


if __name__ == '__main__':
    unittest.main()
