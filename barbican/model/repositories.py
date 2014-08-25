# Copyright (c) 2013-2014 Rackspace, Inc.
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

"""
Defines interface for DB access that Resource controllers may reference

TODO: The top part of this file was 'borrowed' from Glance, but seems
quite intense for sqlalchemy, and maybe could be simplified.
"""


import logging
import time
import uuid

from oslo.config import cfg

import sqlalchemy
from sqlalchemy import or_
import sqlalchemy.orm as sa_orm

from barbican.common import exception
from barbican.common import utils
from barbican.model.migration import commands
from barbican.model import models
from barbican.openstack.common import gettextutils as u
from barbican.openstack.common import timeutils

LOG = utils.getLogger(__name__)


_ENGINE = None
_MAKER = None
_MAX_RETRIES = None
_RETRY_INTERVAL = None
BASE = models.BASE
sa_logger = None


db_opts = [
    cfg.IntOpt('sql_idle_timeout', default=3600),
    cfg.IntOpt('sql_max_retries', default=60),
    cfg.IntOpt('sql_retry_interval', default=1),
    cfg.BoolOpt('db_auto_create', default=True),
    cfg.StrOpt('sql_connection'),
    cfg.IntOpt('max_limit_paging', default=100),
    cfg.IntOpt('default_limit_paging', default=10),
]

CONF = cfg.CONF
CONF.register_opts(db_opts)
CONF.import_opt('debug', 'barbican.openstack.common.log')

_CONNECTION = None
_IDLE_TIMEOUT = None


def setup_db_env():
    """Setup configuration for database."""
    global sa_logger, _IDLE_TIMEOUT, _MAX_RETRIES, _RETRY_INTERVAL, _CONNECTION

    _IDLE_TIMEOUT = CONF.sql_idle_timeout
    _MAX_RETRIES = CONF.sql_max_retries
    _RETRY_INTERVAL = CONF.sql_retry_interval
    _CONNECTION = CONF.sql_connection
    LOG.debug("Sql connection = %s", _CONNECTION)
    sa_logger = logging.getLogger('sqlalchemy.engine')
    if CONF.debug:
        sa_logger.setLevel(logging.DEBUG)


def configure_db():
    """Establish the database, create an engine if needed, and
    register the models.
    """
    setup_db_env()
    get_engine()


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session."""
    global _MAKER
    if not _MAKER:
        get_engine()
        get_maker(autocommit, expire_on_commit)
        assert(_MAKER)
    session = _MAKER()
    return session


def get_engine():
    """Return a SQLAlchemy engine."""
    """May assign _ENGINE if not already assigned"""
    global _ENGINE, sa_logger, _CONNECTION, _IDLE_TIMEOUT, _MAX_RETRIES, \
        _RETRY_INTERVAL

    if not _ENGINE:
        if not _CONNECTION:
            raise exception.BarbicanException('No _CONNECTION configured')

    #TODO(jfwood) connection_dict = sqlalchemy.engine.url.make_url(_CONNECTION)

        engine_args = {
            'pool_recycle': _IDLE_TIMEOUT,
            'echo': False,
            'convert_unicode': True}

        try:
            LOG.debug("Sql connection: %s; Args: %s", _CONNECTION, engine_args)
            _ENGINE = sqlalchemy.create_engine(_CONNECTION, **engine_args)

        #TODO(jfwood): if 'mysql' in connection_dict.drivername:
        #TODO(jfwood): sqlalchemy.event.listen(_ENGINE, 'checkout',
        #TODO(jfwood):                         ping_listener)

            _ENGINE.connect = wrap_db_error(_ENGINE.connect)
            _ENGINE.connect()
        except Exception as err:
            msg = u._("Error configuring registry database with supplied "
                      "sql_connection. Got error: %s") % err
            LOG.exception(msg)
            raise

        sa_logger = logging.getLogger('sqlalchemy.engine')
        if CONF.debug:
            sa_logger.setLevel(logging.DEBUG)

        if CONF.db_auto_create:
            meta = sqlalchemy.MetaData()
            meta.reflect(bind=_ENGINE)
            tables = meta.tables
            if tables and 'alembic_version' in tables:
                # Upgrade the database to the latest version.
                LOG.info(u._('Updating schema to latest version'))
                commands.upgrade()
            else:
                # Create database tables from our models.
                LOG.info(u._('Auto-creating barbican registry DB'))
                models.register_models(_ENGINE)

                # Sync the alembic version 'head' with current models.
                commands.stamp()

        else:
            LOG.info(u._('not auto-creating barbican registry DB'))

    return _ENGINE


def get_maker(autocommit=True, expire_on_commit=False):
    """Return a SQLAlchemy sessionmaker."""
    """May assign __MAKER if not already assigned"""
    global _MAKER, _ENGINE
    assert _ENGINE
    if not _MAKER:
        _MAKER = sa_orm.sessionmaker(bind=_ENGINE,
                                     autocommit=autocommit,
                                     expire_on_commit=expire_on_commit)
    return _MAKER


def is_db_connection_error(args):
    """Return True if error in connecting to db."""
    # NOTE(adam_g): This is currently MySQL specific and needs to be extended
    #               to support Postgres and others.
    conn_err_codes = ('2002', '2003', '2006')
    for err_code in conn_err_codes:
        if args.find(err_code) != -1:
            return True
    return False


def wrap_db_error(f):
    """Retry DB connection. Copied from nova and modified."""
    def _wrap(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except sqlalchemy.exc.OperationalError as e:
            if not is_db_connection_error(e.args[0]):
                raise

            remaining_attempts = _MAX_RETRIES
            while True:
                LOG.warning(u._('SQL connection failed. %d attempts left.'),
                            remaining_attempts)
                remaining_attempts -= 1
                time.sleep(_RETRY_INTERVAL)
                try:
                    return f(*args, **kwargs)
                except sqlalchemy.exc.OperationalError as e:
                    if (remaining_attempts == 0 or not
                            is_db_connection_error(e.args[0])):
                        raise
                except sqlalchemy.exc.DBAPIError:
                    raise
        except sqlalchemy.exc.DBAPIError:
            raise
    _wrap.func_name = f.func_name
    return _wrap


def clean_paging_values(offset_arg=0, limit_arg=CONF.default_limit_paging):
    """Cleans and safely limits raw paging offset/limit values."""
    offset_arg = offset_arg or 0
    limit_arg = limit_arg or CONF.default_limit_paging

    try:
        offset = int(offset_arg)
        offset = offset if offset >= 0 else 0
    except ValueError:
        offset = 0

    try:
        limit = int(limit_arg)
        if limit < 1:
            limit = 1
        if limit > CONF.max_limit_paging:
            limit = CONF.max_limit_paging
    except ValueError:
        limit = CONF.default_limit_paging

    LOG.debug("Clean paging values limit=%s, offset=%s",
              limit, offset
              )

    return offset, limit


class Repositories(object):
    """Convenient way to pass repositories around.

    Selecting a given repository has 3 choices:
       1) Use a specified repository instance via **kwargs
       2) Create a repository here if it is specified as None via **kwargs
       3) Just use None if no repository is specified
    """
    def __init__(self, **kwargs):
        if kwargs:
            # Enforce that either all arguments are non-None or else all None.
            test_set = set(kwargs.values())
            if None in test_set and len(test_set) > 1:
                raise NotImplementedError('No support for mixing None '
                                          'and non-None repository instances')

            # Only set properties for specified repositories.
            self._set_repo('tenant_repo', TenantRepo, kwargs)
            self._set_repo('tenant_secret_repo', TenantSecretRepo, kwargs)
            self._set_repo('secret_repo', SecretRepo, kwargs)
            self._set_repo('datum_repo', EncryptedDatumRepo, kwargs)
            self._set_repo('kek_repo', KEKDatumRepo, kwargs)
            self._set_repo('secret_meta_repo', SecretStoreMetadatumRepo,
                           kwargs)
            self._set_repo('order_repo', OrderRepo, kwargs)
            self._set_repo('order_plugin_meta_repo', OrderPluginMetadatumRepo,
                           kwargs)
            self._set_repo('transport_key_repo', TransportKeyRepo, kwargs)

    def _set_repo(self, repo_name, repo_cls, specs):
        if specs and repo_name in specs:
            setattr(self, repo_name, specs[repo_name] or repo_cls())


class BaseRepo(object):
    """Base repository for the barbican entities.

    This class provides template methods that allow sub-classes to hook
    specific functionality as needed.
    """

    def __init__(self):
        LOG.debug("BaseRepo init...")
        configure_db()

    def get_session(self, session=None):
        LOG.debug("Getting session...")
        return session or get_session()

    def get(self, entity_id, keystone_id=None,
            force_show_deleted=False,
            suppress_exception=False, session=None):
        """Get an entity or raise if it does not exist."""
        session = self.get_session(session)

        try:
            query = self._do_build_get_query(entity_id,
                                             keystone_id, session)

            # filter out deleted entities if requested
            if not force_show_deleted:
                query = query.filter_by(deleted=False)

            entity = query.one()

        except sa_orm.exc.NoResultFound:
            LOG.exception("Not found for %s", entity_id)
            entity = None
            if not suppress_exception:
                raise exception.NotFound("No %s found with ID %s"
                                         % (self._do_entity_name(), entity_id))

        return entity

    def create_from(self, entity):
        """Sub-class hook: create from entity."""
        start = time.time()  # DEBUG
        if not entity:
            msg = "Must supply non-None {0}.".format(self._do_entity_name)
            raise exception.Invalid(msg)

        if entity.id:
            msg = "Must supply {0} with id=None(i.e. new entity).".format(
                self._do_entity_name)
            raise exception.Invalid(msg)

        LOG.debug("Begin create from...")
        session = get_session()
        with session.begin():

            # Validate the attributes before we go any further. From my
            # (unknown Glance developer) investigation, the @validates
            # decorator does not validate
            # on new records, only on existing records, which is, well,
            # idiotic.
            values = self._do_validate(entity.to_dict())

            try:
                LOG.debug("Saving entity...")
                entity.save(session=session)
            except sqlalchemy.exc.IntegrityError:
                LOG.exception('Problem saving entity for create')
                values_id = values['id'] if values else None
                raise exception.Duplicate("Entity ID {0} already exists!"
                                          .format(values_id))
        LOG.debug('Elapsed repo '
                  'create secret:%s', (time.time() - start))  # DEBUG

        return entity

    def save(self, entity):
        """Saves the state of the entity.

        :raises NotFound if entity does not exist.
        """
        session = get_session()
        with session.begin():
            entity.updated_at = timeutils.utcnow()

            # Validate the attributes before we go any further. From my
            # (unknown Glance developer) investigation, the @validates
            # decorator does not validate
            # on new records, only on existing records, which is, well,
            # idiotic.
            self._do_validate(entity.to_dict())

            try:
                entity.save(session=session)
            except sqlalchemy.exc.IntegrityError:
                LOG.exception('Problem saving entity for update')
                raise exception.NotFound("Entity ID %s not found"
                                         % entity.id)

    def update(self, entity_id, values, purge_props=False):
        """Set the given properties on an entity and update it.

        :raises NotFound if entity does not exist.
        """
        return self._update(entity_id, values, purge_props)

    def delete_entity_by_id(self, entity_id, keystone_id):
        """Remove the entity by its ID."""

        session = get_session()
        with session.begin():

            entity = self.get(entity_id=entity_id, keystone_id=keystone_id,
                              session=session)

            try:
                entity.delete(session=session)
            except sqlalchemy.exc.IntegrityError:
                LOG.exception('Problem finding entity to delete')
                raise exception.NotFound("Entity ID %s not found"
                                         % entity_id)

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Entity"

    def _do_create_instance(self):
        """Sub-class hook: return new entity instance (in Python, not in db).
        """
        return None

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return None

    def _do_convert_values(self, values):
        """Sub-class hook: convert text-based values to target types for the
        database.
        """
        pass

    def _do_validate(self, values):
        """Sub-class hook: validate values.

        Validates the incoming data and raises an Invalid exception
        if anything is out of order.

        :param values: Mapping of entity metadata to check
        """
        status = values.get('status', None)
        if not status:
            #TODO(jfwood): I18n this!
            msg = "{0} status is required.".format(self._do_entity_name())
            raise exception.Invalid(msg)

        if not models.States.is_valid(status):
            msg = "Invalid status '{0}' for {1}.".format(
                status, self._do_entity_name())
            raise exception.Invalid(msg)

        return values

    def _update(self, entity_id, values, purge_props=False):
        """Used internally by update()

        :param values: A dict of attributes to set
        :param entity_id: If None, create the entity, otherwise,
                          find and update it
        """
        session = get_session()
        with session.begin():

            if entity_id:
                entity_ref = self.get(entity_id, session=session)
                values['updated_at'] = timeutils.utcnow()
            else:
                self._do_convert_values(values)
                entity_ref = self._do_create_instance()

            # Need to canonicalize ownership
            if 'owner' in values and not values['owner']:
                values['owner'] = None

            entity_ref.update(values)

            # Validate the attributes before we go any further. From my
            # (unknown Glance developer) investigation, the @validates
            # decorator does not validate
            # on new records, only on existing records, which is, well,
            # idiotic.
            self._do_validate(entity_ref.to_dict())
            self._update_values(entity_ref, values)

            try:
                entity_ref.save(session=session)
            except sqlalchemy.exc.IntegrityError:
                LOG.exception('Problem saving entity for _update')
                if entity_id:
                    raise exception.NotFound("Entity ID %s not found"
                                             % entity_id)
                else:
                    raise exception.Duplicate("Entity ID %s already exists!"
                                              % values['id'])

        return self.get(entity_ref.id)

    def _update_values(self, entity_ref, values):
        for k in values:
            if getattr(entity_ref, k) != values[k]:
                setattr(entity_ref, k, values[k])


class TenantRepo(BaseRepo):
    """Repository for the Tenant entity."""

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Tenant"

    def _do_create_instance(self):
        return models.Tenant()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.Tenant).filter_by(id=entity_id)

    def find_by_keystone_id(self, keystone_id, suppress_exception=False,
                            session=None):
        session = self.get_session(session)

        try:
            query = session.query(models.Tenant).filter_by(keystone_id=
                                                           keystone_id)

            entity = query.one()

        except sa_orm.exc.NoResultFound:
            entity = None
            if not suppress_exception:
                LOG.exception("Problem getting Tenant %s", keystone_id)
                raise exception.NotFound("No %s found with keystone-ID %s"
                                         % (self._do_entity_name(),
                                            keystone_id))

        return entity


class SecretRepo(BaseRepo):
    """Repository for the Secret entity."""

    def get_by_create_date(self, keystone_id, offset_arg=None, limit_arg=None,
                           name=None, alg=None, mode=None, bits=0,
                           suppress_exception=False, session=None):
        """Returns a list of secrets, ordered by the date they were created at
        and paged based on the offset and limit fields. The keystone_id is
        external-to-Barbican value assigned to the tenant by Keystone.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)
        utcnow = timeutils.utcnow()

        try:
            query = session.query(models.Secret) \
                           .order_by(models.Secret.created_at) \
                           .filter_by(deleted=False)

            # Note: Must use '== None' below, not 'is None'.
            query = query.filter(or_(models.Secret.expiration == None,
                                     models.Secret.expiration > utcnow))

            if name:
                query = query.filter(models.Secret.name.like(name))
            if alg:
                query = query.filter(models.Secret.algorithm.like(alg))
            if mode:
                query = query.filter(models.Secret.mode.like(mode))
            if bits > 0:
                query = query.filter(models.Secret.bit_length == bits)

            query = query.join(models.TenantSecret,
                               models.Secret.tenant_assocs) \
                         .join(models.Tenant, models.TenantSecret.tenants) \
                         .filter(models.Tenant.keystone_id == keystone_id)

            start = offset
            end = offset + limit
            LOG.debug('Retrieving from %s to %s', start, end)
            total = query.count()
            entities = query[start:end]
            LOG.debug('Number entities retrieved: %s out of %s',
                      len(entities), total
                      )

        except sa_orm.exc.NoResultFound:
            entities = None
            total = 0
            if not suppress_exception:
                raise exception.NotFound("No %s's found"
                                         % (self._do_entity_name()))

        return entities, offset, limit, total

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Secret"

    def _do_create_instance(self):
        return models.Secret()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        utcnow = timeutils.utcnow()

        # Note: Must use '== None' below, not 'is None'.
        # TODO(jfwood): Performance? Is the many-to-many join needed?
        return session.query(models.Secret).filter_by(id=entity_id) \
                      .filter_by(deleted=False) \
                      .filter(or_(models.Secret.expiration == None,
                                  models.Secret.expiration > utcnow)) \
                      .join(models.TenantSecret, models.Secret.tenant_assocs)\
                      .join(models.Tenant, models.TenantSecret.tenants) \
                      .filter(models.Tenant.keystone_id == keystone_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class EncryptedDatumRepo(BaseRepo):
    """Repository for the EncryptedDatum entity (that stores encrypted
    information on behalf of a Secret).
    """

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "EncryptedDatum"

    def _do_create_instance(self):
        return models.EncryptedDatum()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.EncryptedDatum).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class SecretStoreMetadatumRepo(BaseRepo):
    """Repository for the SecretStoreMetadatum entity (that stores key/value
    information on behalf of a Secret).
    """

    def save(self, metadata, secret_model):
        """Saves the the specified metadata for the secret.

        :raises NotFound if entity does not exist.
        """
        now = timeutils.utcnow()
        session = get_session()
        with session.begin():
            for k, v in metadata.items():
                meta_model = models.SecretStoreMetadatum(k, v)
                meta_model.updated_at = now
                meta_model.secret = secret_model
                meta_model.save(session=session)

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "SecretStoreMetadatum"

    def _do_create_instance(self):
        return models.SecretStoreMetadatum()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.SecretStoreMetadatum).\
            filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class KEKDatumRepo(BaseRepo):
    """Repository for the KEKDatum entity (that stores key encryption key (KEK)
    metadata used by crypto plugins to encrypt/decrypt secrets).
    """

    def find_or_create_kek_datum(self, tenant,
                                 plugin_name,
                                 suppress_exception=False,
                                 session=None):
        """Find or create a KEK datum instance."""
        if not plugin_name:
            raise exception.BarbicanException(
                u._('Tried to register crypto plugin with null or empty '
                    'name.'))

        kek_datum = None

        session = self.get_session(session)

        # TODO(jfwood): Reverse this...attempt insert first, then get on fail.
        try:
            query = session.query(models.KEKDatum) \
                           .filter_by(tenant_id=tenant.id) \
                           .filter_by(plugin_name=plugin_name) \
                           .filter_by(active=True) \
                           .filter_by(deleted=False)

            kek_datum = query.one()

        except sa_orm.exc.NoResultFound:

            kek_datum = models.KEKDatum()

            kek_datum.kek_label = "tenant-{0}-key-{1}".format(
                tenant.keystone_id, uuid.uuid4())
            kek_datum.tenant_id = tenant.id
            kek_datum.plugin_name = plugin_name
            kek_datum.status = models.States.ACTIVE

            self.save(kek_datum)

        return kek_datum

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "KEKDatum"

    def _do_create_instance(self):
        return models.KEKDatum()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.KEKDatum).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class TenantSecretRepo(BaseRepo):
    """Repository for the TenantSecret entity."""

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "TenantSecret"

    def _do_create_instance(self):
        return models.TenantSecret()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.TenantSecret).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class OrderRepo(BaseRepo):
    """Repository for the Order entity."""

    def get_by_create_date(self, keystone_id, offset_arg=None, limit_arg=None,
                           suppress_exception=False, session=None):
        """Returns a list of orders, ordered by the date they were created at
        and paged based on the offset and limit fields.

        :param keystone_id: The keystone id for the tenant.
        :param offset_arg: The entity number where the query result should
                           start.
        :param limit_arg: The maximum amount of entities in the result set.
        :param suppress_exception: Whether NoResultFound exceptions should be
                                   suppressed.
        :param session: SQLAlchemy session object.

        :returns: Tuple consisting of (list_of_entities, offset, limit, total).
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        try:
            query = session.query(models.Order) \
                           .order_by(models.Order.created_at)
            query = query.filter_by(deleted=False) \
                         .join(models.Tenant, models.Order.tenant) \
                         .filter(models.Tenant.keystone_id == keystone_id)

            start = offset
            end = offset + limit
            LOG.debug('Retrieving from %s to %s', start, end)
            total = query.count()
            entities = query[start:end]
            LOG.debug('Number entities retrieved: %s out of %s',
                      len(entities), total
                      )

        except sa_orm.exc.NoResultFound:
            entities = None
            total = 0
            if not suppress_exception:
                raise exception.NotFound("No %s's found"
                                         % (self._do_entity_name()))

        return entities, offset, limit, total

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Order"

    def _do_create_instance(self):
        return models.Order()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.Order).filter_by(id=entity_id) \
                      .filter_by(deleted=False) \
                      .join(models.Tenant, models.Order.tenant) \
                      .filter(models.Tenant.keystone_id == keystone_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class OrderPluginMetadatumRepo(BaseRepo):
    """Repository for the OrderPluginMetadatum entity (that stores key/value
    plugin information on behalf of a Order).
    """

    def save(self, metadata, order_model):
        """Saves the the specified metadata for the order.

        :raises NotFound if entity does not exist.
        """
        now = timeutils.utcnow()
        session = get_session()
        with session.begin():
            for k, v in metadata.items():
                meta_model = models.OrderPluginMetadatum(k, v)
                meta_model.updated_at = now
                meta_model.order = order_model
                meta_model.save(session=session)

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "OrderPluginMetadatum"

    def _do_create_instance(self):
        return models.OrderPluginMetadatum()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.OrderPluginMetadatum)
        return query.filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class ContainerRepo(BaseRepo):
    """Repository for the Container entity."""

    def get_by_create_date(self, keystone_id, offset_arg=None, limit_arg=None,
                           suppress_exception=False, session=None):
        """Returns a list of containers, ordered by the date they were
        created at and paged based on the offset and limit fields. The
        keystone_id is external-to-Barbican value assigned to the tenant
        by Keystone.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        try:
            query = session.query(models.Container) \
                           .order_by(models.Container.created_at)
            query = query.filter_by(deleted=False) \
                         .join(models.Tenant, models.Container.tenant) \
                         .filter(models.Tenant.keystone_id == keystone_id)

            start = offset
            end = offset + limit
            LOG.debug('Retrieving from %s to %s', start, end)
            total = query.count()
            entities = query[start:end]
            LOG.debug('Number entities retrieved: %s out of %s',
                      len(entities), total
                      )

        except sa_orm.exc.NoResultFound:
            entities = None
            total = 0
            if not suppress_exception:
                raise exception.NotFound("No %s's found"
                                         % (self._do_entity_name()))

        return entities, offset, limit, total

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Container"

    def _do_create_instance(self):
        return models.Container()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.Container).filter_by(id=entity_id)\
            .filter_by(deleted=False)\
            .join(models.Tenant, models.Container.tenant)\
            .filter(models.Tenant.keystone_id == keystone_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class ContainerConsumerRepo(BaseRepo):
    """Repository for the Service entity."""

    def get_by_container_id(self, container_id,
                            offset_arg=None, limit_arg=None,
                            suppress_exception=False, session=None):
        """Returns a list of Consumers, ordered by the date they were
        created at and paged based on the offset and limit fields. The
        keystone_id is external-to-Barbican value assigned to the tenant
        by Keystone.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        try:
            query = session.query(models.ContainerConsumerMetadatum) \
                           .order_by(models.ContainerConsumerMetadatum.name)
            query = query.filter_by(deleted=False) \
                         .filter(models.ContainerConsumerMetadatum.container_id
                                 == container_id)
            start = offset
            end = offset + limit
            LOG.debug('Retrieving from %s to %s', start, end)
            total = query.count()
            entities = query[start:end]
            LOG.debug('Number entities retrieved: %s out of %s',
                      len(entities), total
                      )

        except sa_orm.exc.NoResultFound:
            entities = None
            total = 0
            if not suppress_exception:
                raise exception.NotFound("No %ss found"
                                         % (self._do_entity_name()))

        return entities, offset, limit, total

    def get_by_values(self, container_id, name, URL, suppress_exception=False,
                      show_deleted=False, session=None):
        session = self.get_session(session)

        try:
            query = session.query(models.ContainerConsumerMetadatum) \
                .filter_by(container_id=container_id) \
                .filter_by(name=name).filter_by(URL=URL)
            if not show_deleted:
                query.filter_by(deleted=False)
            consumer = query.one()
        except sa_orm.exc.NoResultFound:
            if not suppress_exception:
                raise exception.NotFound("Could not find %s"
                                         % (self._do_entity_name()))
        except sa_orm.exc.MultipleResultsFound:
            if not suppress_exception:
                raise exception.NotFound("Found more than one %s"
                                         % (self._do_entity_name()))
        return consumer

    def create_from(self, new_consumer):
        try:
            super(ContainerConsumerRepo, self).create_from(new_consumer)
        except exception.Duplicate:
            #This operation is idempotent, so log this and move on
            LOG.debug("Consumer %s already exists for container %s,"
                      " continuing...", (new_consumer.name, new_consumer.URL),
                      new_consumer.container_id)
            #Get the existing entry and reuse it by clearing the deleted flags
            existing_consumer = self.get_by_values(
                new_consumer.container_id, new_consumer.name, new_consumer.URL,
                show_deleted=True)
            existing_consumer.deleted = False
            existing_consumer.deleted_at = None
            #We are not concerned about timing here -- set only, no reads
            existing_consumer.save()

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "ContainerConsumer"

    def _do_create_instance(self):
        return models.ContainerConsumerMetadatum("uuid")

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.ContainerConsumerMetadatum) \
            .filter_by(id=entity_id).filter_by(deleted=False)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class TransportKeyRepo(BaseRepo):
    """Repository for the TransportKey entity (that stores transport keys
    for wrapping the secret data to/from a barbican client).
    """

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "TransportKey"

    def _do_create_instance(self):
        return models.TransportKey()

    def get_by_create_date(self, plugin_name=None,
                           offset_arg=None, limit_arg=None,
                           suppress_exception=False, session=None):
        """Returns a list of transport keys, ordered from latest created first.
        The search accepts plugin_id as an optional parameter for the search.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        try:
            query = session.query(models.TransportKey) \
                           .order_by(models.TransportKey.created_at)
            if plugin_name is not None:
                query = session.query(models.TransportKey).\
                    filter_by(deleted=False, plugin_name=plugin_name)
            else:
                query = query.filter_by(deleted=False)

            start = offset
            end = offset + limit
            LOG.debug('Retrieving from %s to %s', start, end)
            total = query.count()
            entities = query[start:end]
            LOG.debug('Number of entities retrieved: %s out of %s',
                      len(entities), total)

        except sa_orm.exc.NoResultFound:
            entities = None
            total = 0
            if not suppress_exception:
                raise exception.NotFound("No {0}'s found".format(
                    self._do_entity_name()))

        return entities, offset, limit, total

    def get_latest_transport_key(self, plugin_name, suppress_exception=False,
                                 session=None):
        """Returns the latest transport key for a given plugin
        """
        entity, offset, limit, total = self.get_by_create_date(
            plugin_name, offset_arg=0, limit_arg=1,
            suppress_exception=suppress_exception, session=session)
        return entity

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.TransportKey).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass
