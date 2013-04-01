from datetime import datetime
from barbican.api.resources import *
from barbican.model.tenant import Tenant

from mock import MagicMock

import falcon
import unittest


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
        db_filter = MagicMock()
        db_filter.one.return_value = Tenant('tenant_id')

        db_query = MagicMock()
        db_query.filter_by.return_value = db_filter

        self.db_session = MagicMock()
        self.db_session.query.return_value = db_query

        self.stream = MagicMock()
        self.stream.read.return_value = u'{ "username" : "1234" }'

        self.req = MagicMock()
        self.req.stream = self.stream

        self.resp = MagicMock()
        self.resource = TenantsResource(self.db_session)

    def test_should_throw_exception_for_tenants_that_exist(self):
        with self.assertRaises(falcon.HTTPError):
            self.resource.on_post(self.req, self.resp)

        self.db_session.query.assert_called_once_with(Tenant)


if __name__ == '__main__':
    unittest.main()
