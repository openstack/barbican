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

"""
Supports database/repositories oriented unit testing.

Warning: Do not merge this content with the utils.py module, as doing so will
break the DevStack functional test discovery process.
"""
import datetime
import oslotest.base as oslotest

from sqlalchemy.engine import Engine
from sqlalchemy import event

from barbican.model import models
from barbican.model import repositories


@event.listens_for(Engine, "connect")
def set_foreign_key_constraint(dbapi_connection, connection_record):
    # Ensure that foreign key constraints are enforced during tests
    dbapi_connection.execute("PRAGMA foreign_keys=ON")


def setup_in_memory_db():
    # Ensure we are using in-memory SQLite database, and creating tables.
    repositories.CONF.set_override("sql_connection", "sqlite:///:memory:",
                                   enforce_type=True)
    repositories.CONF.set_override("db_auto_create", True, enforce_type=True)
    repositories.CONF.set_override("debug", True, enforce_type=True)

    # Ensure the connection is completely closed, so any previous in-memory
    # database can be removed prior to starting the next test run.
    repositories.hard_reset()

    # Start the in-memory database, creating required tables.
    repositories.start()


def in_memory_cleanup():
    repositories.clear()


def get_session():
    return repositories.get_session()


def create_project(external_id="my keystone id", session=None):
    project = models.Project()
    project.external_id = external_id
    project_repo = repositories.get_project_repository()
    project_repo.create_from(project, session=session)
    return project


def create_order(project=None, session=None, secret=None, container=None):
    if not project:
        project = create_project(session=session)

    order = models.Order()
    order.project_id = project.id

    if secret:
        order.secret_id = secret.id
    if container:
        order.container_id = container.id

    order_repo = repositories.get_order_repository()
    order_repo.create_from(order, session=session)
    return order


def create_secret(project=None, session=None):
    secret = models.Secret()
    secret.project_id = project.id
    secret_repo = repositories.get_secret_repository()
    secret_repo.create_from(secret, session=session)
    return secret


def create_transport_key(plugin_name="plugin", transport_key="tkey",
                         session=None):
    transport_key = models.TransportKey(plugin_name, transport_key)
    transport_key_repo = repositories.get_transport_key_repository()
    transport_key_repo.create_from(transport_key, session=session)
    return transport_key


def create_secret_metadatum(secret=None, key="key", value="value",
                            session=None):
    secret_meta = models.SecretStoreMetadatum(key, value)
    secret_meta.secret_id = secret.id
    secret_meta_repo = repositories.get_secret_meta_repository()
    secret_meta_repo.create_from(secret_meta, session=session)
    return secret_meta


def create_secret_user_metadatum(secret=None, key="user_key",
                                 value="user_value", session=None):
    secret_user_metadatum = models.SecretUserMetadatum(key, value)
    secret_user_metadatum.secret_id = secret.id
    secret_user_metadatum_repo = repositories.get_secret_user_meta_repository()
    secret_user_metadatum_repo.create_from(secret_user_metadatum,
                                           session=session)
    return secret_user_metadatum


def create_container(project=None, session=None):
    container = models.Container()
    container.project_id = project.id
    container_repo = repositories.get_container_repository()
    container_repo.create_from(container, session=session)
    return container


def create_container_secret(container=None, secret=None, session=None):
    container_secret = models.ContainerSecret()
    container_secret.container_id = container.id
    container_secret.secret_id = secret.id
    container_secret_repo = repositories.get_container_secret_repository()
    container_secret_repo.create_from(container_secret, session=session)
    return container_secret


def create_kek_datum(project=None, plugin_name="plugin", session=None):
    kek_datum = models.KEKDatum()
    kek_datum.plugin_name = plugin_name
    kek_datum.project_id = project.id
    kek_datum_repo = repositories.get_kek_datum_repository()
    kek_datum_repo.create_from(kek_datum, session=session)
    return kek_datum


def create_encrypted_datum(secret=None, kek_datum=None, session=None):
    enc_datum = models.EncryptedDatum()
    enc_datum.secret_id = secret.id
    enc_datum.kek_id = kek_datum.id
    enc_datum_repo = repositories.get_encrypted_datum_repository()
    enc_datum_repo.create_from(enc_datum, session=session)
    return enc_datum


def create_order_meta_datum(order=None, key="key", value="value",
                            session=None):
    order_meta_datum = models.OrderBarbicanMetadatum(key, value)
    order_meta_datum.order_id = order.id
    order_meta_datum_repo = repositories.get_order_barbican_meta_repository()
    order_meta_datum_repo.create_from(order_meta_datum, session=session)
    return order_meta_datum


def create_order_retry(order=None, retry_task="", retry_args=[],
                       retry_kwargs={}, retry_at=None, session=None):
    order_retry = models.OrderRetryTask()
    order_retry.retry_task = retry_task
    order_retry.retry_args = retry_args
    order_retry.retry_kwargs = retry_kwargs
    if not retry_at:
        order_retry.retry_at = datetime.datetime.utcnow()
    order_retry.order_id = order.id
    order_retry_task_repo = repositories.get_order_retry_tasks_repository()
    order_retry_task_repo.create_from(order_retry, session)
    return order_retry


def create_order_plugin_metadatum(order=None, key="key", value="value",
                                  session=None):
    order_plugin_metadatum = models.OrderPluginMetadatum(key, value)
    order_plugin_metadatum.order_id = order.id
    order_plugin_repo = repositories.get_order_plugin_meta_repository()
    order_plugin_repo.create_from(order_plugin_metadatum, session=session)
    return order_plugin_metadatum


def create_container_consumer_meta(container=None, parsed_request=None,
                                   session=None):
    if not parsed_request:
        parsed_request = {"name": "name", "URL": "URL"}
    container_consumer_meta = models.ContainerConsumerMetadatum(
        container_id=container.id,
        project_id=container.project_id,
        parsed_request=parsed_request,
    )
    cont_cons_meta_repo = repositories.get_container_consumer_repository()
    cont_cons_meta_repo.create_from(container_consumer_meta, session=session)
    return container_consumer_meta


def create_certificate_authority(project=None, parsed_ca_in=None,
                                 session=None):
    if not parsed_ca_in:
        parsed_ca_in = {'plugin_name': 'plugin_name',
                        'plugin_ca_id': 'plugin_ca_id',
                        'expiration:': 'expiration',
                        'creator_id': 'creator_id',
                        'project_id': project.id}
    certificate_authority = models.CertificateAuthority(
        parsed_ca_in=parsed_ca_in)
    cert_auth_repo = repositories.get_ca_repository()
    cert_auth_repo.create_from(certificate_authority, session=session)
    return certificate_authority


def create_preferred_cert_authority(cert_authority, session=None):
    prefered_cert_authority = models.PreferredCertificateAuthority(
        ca_id=cert_authority.id,
        project_id=cert_authority.project_id)
    preferred_ca_repo = repositories.get_preferred_ca_repository()
    preferred_ca_repo.create_from(prefered_cert_authority, session=session)
    return prefered_cert_authority


def create_project_cert_authority(certificate_authority=None, session=None):
    project_cert_authority = models.ProjectCertificateAuthority(
        ca_id=certificate_authority.id,
        project_id=certificate_authority.project_id)
    project_cert_repo = repositories.get_project_ca_repository()
    project_cert_repo.create_from(project_cert_authority, session=session)
    return project_cert_authority


def create_project_quotas(project=None, parsed_project_quotas=None,
                          session=None):
    project_quota = models.ProjectQuotas(
        project_id=project.id,
        parsed_project_quotas=parsed_project_quotas)
    project_quota_repo = repositories.get_project_quotas_repository()
    project_quota_repo.create_from(project_quota, session=session)
    return project_quota


def create_acl_secret(secret=None, user_ids=[], session=None):
    acl_secret = models.SecretACL(secret.id, "read")
    acl_secret.secret_id = secret.id
    acl_secret_repo = repositories.get_secret_acl_repository()
    acl_secret_repo.create_from(acl_secret, session=session)
    return acl_secret


class RepositoryTestCase(oslotest.BaseTestCase):
    """Base test case class for in-memory database unit tests.

    Database/Repository oriented unit tests should *not* modify the global
    state in the barbican/model/repositories.py module, as this can lead to
    hard to debug errors. Instead only utilize methods in this fixture.

    Also, database-oriented unit tests extending this class MUST NO INVOKE
    the repositories.start()/clear()/hard_reset() methods!*, otherwise *VERY*
    hard to debug 'Broken Pipe' errors could result!
    """
    def setUp(self):
        super(RepositoryTestCase, self).setUp()
        setup_in_memory_db()

        # Clean up once tests are completed.
        self.addCleanup(in_memory_cleanup)
