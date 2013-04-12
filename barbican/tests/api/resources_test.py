from datetime import datetime
from barbican.api.resources import *
from barbican.model.models import Tenant
from barbican.common import config

from mock import MagicMock

import falcon
import unittest
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
        
        self.tenant_repo = MagicMock()
        self.tenant_repo.find_by_name.return_value = None
        self.tenant_repo.create_from.return_value = None

        self.stream = MagicMock()
        self.stream.read.return_value = u'{ "username" : "%s" }' % self.username

        self.req = MagicMock()
        self.req.stream = self.stream

        self.resp = MagicMock()
        self.resource = TenantsResource(self.tenant_repo)

    def test_should_add_new_tenant(self):
        self.resource.on_post(self.req, self.resp)

        self.tenant_repo.find_by_name.assert_called_once_with(name=self.username, suppress_exception=True)
        # TBD: Make this work: self.tenant_repo.create_from.assert_called_once_with(unittest.mock.ANY)

    def test_should_throw_exception_for_tenants_that_exist(self):
        self.tenant_repo.find_by_name.return_value = Tenant()
        
        with self.assertRaises(falcon.HTTPError):
            self.resource.on_post(self.req, self.resp)

        self.tenant_repo.find_by_name.assert_called_once_with(name=self.username, suppress_exception=True)


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
        self.tenant_repo.get.side_effect = exception.NotFound("Test not found exception")
        
        with self.assertRaises(exception.NotFound):
            self.resource.on_get(self.req, self.resp, self.tenant.id)

    def test_should_throw_exception_for_delete_when_tenant_not_found(self):
        self.tenant_repo.get.side_effect = exception.NotFound("Test not found exception")
        
        with self.assertRaises(exception.NotFound):
            self.resource.on_delete(self.req, self.resp, self.tenant.id)


if __name__ == '__main__':
    unittest.main()
