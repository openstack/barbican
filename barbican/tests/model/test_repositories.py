# Copyright 2013-2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import fixtures
import mock
from oslo.config import cfg
import sqlalchemy.orm as sa_orm

from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import utils


class Database(fixtures.Fixture):

    def __init__(self):
        super(Database, self).__init__()
        repositories.CONF.set_override("sql_connection", "sqlite:///:memory:")

    def setUp(self):
        super(Database, self).setUp()
        repositories.configure_db()
        engine = repositories.get_engine()
        models.register_models(engine)
        self.addCleanup(lambda: models.unregister_models(engine))


class RepositoryTestCase(utils.BaseTestCase):

    def setUp(self):
        super(RepositoryTestCase, self).setUp()
        self.useFixture(Database())


class TestSecretRepository(RepositoryTestCase):

    def setUp(self):
        super(TestSecretRepository, self).setUp()
        self.repo = repositories.SecretRepo()

    def test_get_by_create_date(self):
        session = self.repo.get_session()

        secret = self.repo.create_from(models.Secret(), session=session)
        tenant = models.Tenant(keystone_id="my keystone id")
        tenant.save(session=session)
        tenant_secret = models.TenantSecret(
            secret_id=secret.id,
            tenant_id=tenant.id,
        )
        tenant_secret.save(session=session)

        secrets, offset, limit, total = self.repo.get_by_create_date(
            "my keystone id",
            session=session,
        )

        self.assertEqual([s.id for s in secrets], [secret.id])
        self.assertEqual(offset, 0)
        self.assertEqual(limit, 10)
        self.assertEqual(total, 1)

    def test_get_by_create_date_with_name(self):
        session = self.repo.get_session()

        secret1 = self.repo.create_from(
            models.Secret(dict(name="name1")),
            session=session,
        )
        secret2 = self.repo.create_from(
            models.Secret(dict(name="name2")),
            session=session,
        )
        tenant = models.Tenant(keystone_id="my keystone id")
        tenant.save(session=session)
        tenant_secret1 = models.TenantSecret(
            secret_id=secret1.id,
            tenant_id=tenant.id,
        )
        tenant_secret1.save(session=session)
        tenant_secret2 = models.TenantSecret(
            secret_id=secret2.id,
            tenant_id=tenant.id,
        )
        tenant_secret2.save(session=session)

        secrets, offset, limit, total = self.repo.get_by_create_date(
            "my keystone id",
            name="name1",
            session=session,
        )

        self.assertEqual([s.id for s in secrets], [secret1.id])
        self.assertEqual(offset, 0)
        self.assertEqual(limit, 10)
        self.assertEqual(total, 1)

    def test_get_by_create_date_with_alg(self):
        session = self.repo.get_session()

        secret1 = self.repo.create_from(
            models.Secret(dict(algorithm="algorithm1")),
            session=session,
        )
        secret2 = self.repo.create_from(
            models.Secret(dict(algorithm="algorithm2")),
            session=session,
        )
        tenant = models.Tenant(keystone_id="my keystone id")
        tenant.save(session=session)
        tenant_secret1 = models.TenantSecret(
            secret_id=secret1.id,
            tenant_id=tenant.id,
        )
        tenant_secret1.save(session=session)
        tenant_secret2 = models.TenantSecret(
            secret_id=secret2.id,
            tenant_id=tenant.id,
        )
        tenant_secret2.save(session=session)

        secrets, offset, limit, total = self.repo.get_by_create_date(
            "my keystone id",
            alg="algorithm1",
            session=session,
        )

        self.assertEqual([s.id for s in secrets], [secret1.id])
        self.assertEqual(offset, 0)
        self.assertEqual(limit, 10)
        self.assertEqual(total, 1)

    def test_get_by_create_date_with_mode(self):
        session = self.repo.get_session()

        secret1 = self.repo.create_from(
            models.Secret(dict(mode="mode1")),
            session=session,
        )
        secret2 = self.repo.create_from(
            models.Secret(dict(mode="mode2")),
            session=session,
        )
        tenant = models.Tenant(keystone_id="my keystone id")
        tenant.save(session=session)
        tenant_secret1 = models.TenantSecret(
            secret_id=secret1.id,
            tenant_id=tenant.id,
        )
        tenant_secret1.save(session=session)
        tenant_secret2 = models.TenantSecret(
            secret_id=secret2.id,
            tenant_id=tenant.id,
        )
        tenant_secret2.save(session=session)

        secrets, offset, limit, total = self.repo.get_by_create_date(
            "my keystone id",
            mode="mode1",
            session=session,
        )

        self.assertEqual([s.id for s in secrets], [secret1.id])
        self.assertEqual(offset, 0)
        self.assertEqual(limit, 10)
        self.assertEqual(total, 1)

    def test_get_by_create_date_with_bits(self):
        session = self.repo.get_session()

        secret1 = self.repo.create_from(
            models.Secret(dict(bit_length=1024)),
            session=session,
        )
        secret2 = self.repo.create_from(
            models.Secret(dict(bit_length=2048)),
            session=session,
        )
        tenant = models.Tenant(keystone_id="my keystone id")
        tenant.save(session=session)
        tenant_secret1 = models.TenantSecret(
            secret_id=secret1.id,
            tenant_id=tenant.id,
        )
        tenant_secret1.save(session=session)
        tenant_secret2 = models.TenantSecret(
            secret_id=secret2.id,
            tenant_id=tenant.id,
        )
        tenant_secret2.save(session=session)

        secrets, offset, limit, total = self.repo.get_by_create_date(
            "my keystone id",
            bits=1024,
            session=session,
        )

        self.assertEqual([s.id for s in secrets], [secret1.id])
        self.assertEqual(offset, 0)
        self.assertEqual(limit, 10)
        self.assertEqual(total, 1)

    def test_get_by_create_date_nothing(self):
        session = self.repo.get_session()
        secrets, offset, limit, total = self.repo.get_by_create_date(
            "my keystone id",
            bits=1024,
            session=session,
        )

        self.assertEqual(secrets, [])
        self.assertEqual(offset, 0)
        self.assertEqual(limit, 10)
        self.assertEqual(total, 0)

    def test_do_entity_name(self):
        self.assertEqual(self.repo._do_entity_name(), "Secret")

    def test_do_create_instance(self):
        self.assertIsInstance(self.repo._do_create_instance(), models.Secret)


class WhenCleaningRepositoryPagingParameters(utils.BaseTestCase):

    def setUp(self):
        super(WhenCleaningRepositoryPagingParameters, self).setUp()
        self.CONF = cfg.CONF

    def test_parameters_not_assigned(self):
        """The cleaner should use defaults when params are not specified."""
        clean_offset, clean_limit = repositories.clean_paging_values()

        self.assertEqual(clean_offset, 0)
        self.assertEqual(clean_limit, self.CONF.default_limit_paging)

    def test_limit_as_none(self):
        """When Limit is set to None it should use the default limit."""
        offset = 0
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=offset,
            limit_arg=None)

        self.assertEqual(clean_offset, offset)
        self.assertIsNotNone(clean_limit)

    def test_offset_as_none(self):
        """When Offset is set to None it should use an offset of 0."""
        limit = self.CONF.default_limit_paging
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=None,
            limit_arg=limit)

        self.assertIsNotNone(clean_offset)
        self.assertEqual(clean_limit, limit)

    def test_limit_as_uncastable_str(self):
        """When Limit cannot be cast to an int, expect the default."""
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=0,
            limit_arg='boom')
        self.assertEqual(clean_offset, 0)
        self.assertEqual(clean_limit, self.CONF.default_limit_paging)

    def test_offset_as_uncastable_str(self):
        """When Offset cannot be cast to an int, it should be zero."""
        limit = self.CONF.default_limit_paging
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg='boom',
            limit_arg=limit)
        self.assertEqual(clean_offset, 0)
        self.assertEqual(clean_limit, limit)

    def test_limit_is_less_than_one(self):
        """Offset should default to 1."""
        limit = -1
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=1,
            limit_arg=limit)
        self.assertEqual(clean_offset, 1)
        self.assertEqual(clean_limit, 1)

    def test_limit_ist_too_big(self):
        """Limit should max out at configured value."""
        limit = self.CONF.max_limit_paging + 10
        clean_offset, clean_limit = repositories.clean_paging_values(
            offset_arg=1,
            limit_arg=limit)
        self.assertEqual(clean_limit, self.CONF.max_limit_paging)

    def test_should_raise_exception_create_kek_datum_with_null_name(self):
        repositories._ENGINE = mock.MagicMock()
        tenant = mock.MagicMock(id="1")
        plugin_name = None
        suppress_exception = False
        session = mock.MagicMock()
        session.query.side_effect = sa_orm.exc.NoResultFound()

        kek_repo = repositories.KEKDatumRepo()
        self.assertRaises(exception.BarbicanException,
                          kek_repo.find_or_create_kek_datum, tenant,
                          plugin_name, suppress_exception, session)

    def test_should_raise_exception_create_kek_datum_with_empty_name(self):
        repositories._ENGINE = mock.MagicMock()
        tenant = mock.MagicMock(id="1")
        plugin_name = ""
        suppress_exception = False
        session = mock.MagicMock()
        session.query.side_effect = sa_orm.exc.NoResultFound()

        kek_repo = repositories.KEKDatumRepo()
        self.assertRaises(exception.BarbicanException,
                          kek_repo.find_or_create_kek_datum, tenant,
                          plugin_name, suppress_exception, session)
