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

"""
Defines interface for DB access that Resource controllers may reference

TODO: The top part of this file was 'borrowed' from Glance, but seems
quite intense for sqlalchemy, and maybe could be simplified.
"""


import time
import logging

from oslo.config import cfg

import sqlalchemy
import sqlalchemy.orm as sa_orm
import sqlalchemy.sql as sa_sql
from sqlalchemy import or_

from barbican.common import exception
#TODO: from barbican.db.sqlalchemy import migration
from barbican.model import models
from barbican.openstack.common import timeutils
from barbican.openstack.common.gettextutils import _
from barbican.common import utils

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
    cfg.StrOpt('sql_connection', default=None),
    cfg.IntOpt('max_limit_paging', default=100),
    cfg.IntOpt('default_limit_paging', default=10),
]

CONF = cfg.CONF
CONF.register_opts(db_opts)
CONF.import_opt('debug', 'barbican.openstack.common.log')


def setup_db_env():
    """
    Setup configuration for database
    """
    global sa_logger, _IDLE_TIMEOUT, _MAX_RETRIES, _RETRY_INTERVAL, _CONNECTION

    _IDLE_TIMEOUT = CONF.sql_idle_timeout
    _MAX_RETRIES = CONF.sql_max_retries
    _RETRY_INTERVAL = CONF.sql_retry_interval
    _CONNECTION = CONF.sql_connection
    LOG.debug("Sql connection = {0}".format(_CONNECTION))
    sa_logger = logging.getLogger('sqlalchemy.engine')
    if CONF.debug:
        sa_logger.setLevel(logging.DEBUG)


def configure_db():
    """
    Establish the database, create an engine if needed, and
    register the models.
    """
    setup_db_env()
    get_engine()


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session"""
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
        tries = _MAX_RETRIES
        retry_interval = _RETRY_INTERVAL

        connection_dict = sqlalchemy.engine.url.make_url(_CONNECTION)

        engine_args = {
            'pool_recycle': _IDLE_TIMEOUT,
            'echo': False,
            'convert_unicode': True}

        try:
            LOG.debug("Sql connection: {0}; Args: {1}".format(_CONNECTION,
                                                              engine_args))
            _ENGINE = sqlalchemy.create_engine(_CONNECTION, **engine_args)

#TODO:          if 'mysql' in connection_dict.drivername:
#TODO:          sqlalchemy.event.listen(_ENGINE, 'checkout', ping_listener)

            _ENGINE.connect = wrap_db_error(_ENGINE.connect)
            _ENGINE.connect()
        except Exception as err:
            msg = _("Error configuring registry database with supplied "
                    "sql_connection. Got error: %s") % err
            LOG.exception(msg)
            raise

        sa_logger = logging.getLogger('sqlalchemy.engine')
        if CONF.debug:
            sa_logger.setLevel(logging.DEBUG)

        if CONF.db_auto_create:
            LOG.info(_('auto-creating barbican registry DB'))
            models.register_models(_ENGINE)
#TODO:      try:
#TODO:          migration.version_control()
#TODO:      except exception.DatabaseMigrationError:
#TODO:          # only arises when the DB exists and is under version control
#TODO:          pass
        else:
            LOG.info(_('not auto-creating barbican registry DB'))

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
                LOG.warning(_('SQL connection failed. %d attempts left.'),
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


def clean_paging_values(offset_arg=None, limit_arg=None):
    """Cleans and safely limits raw paging offset/limit values."""
    offset = int(offset_arg) if offset_arg else 0
    offset = offset if offset >= 0 else 0

    limit = int(limit_arg) if limit_arg else CONF.default_limit_paging
    limit = limit if limit >= 2 else 2
    limit = limit if limit <= CONF.max_limit_paging else CONF.max_limit_paging
    
    LOG.debug("Limit={0}, offset={1}".format(limit, offset))

    return (offset, limit)


class BaseRepo(object):
    """
    Base repository for the barbican entities.

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
            LOG.exception("Not found for {0}".format(entity_id))
            entity = None
            if not suppress_exception:
                raise exception.NotFound("No %s found with ID %s"
                                         % (self._do_entity_name(), entity_id))

        return entity

    def create_from(self, entity):
        """Sub-class hook: create from entity."""

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
                raise exception.Duplicate("Entity ID %s already exists!"
                                          % values['id'])

        return entity

    def save(self, entity):
        """
        Saves the state of the entity.

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
                                         % entity_id)

    def update(self, entity_id, values, purge_props=False):
        """
        Set the given properties on an entity and update it.

        :raises NotFound if entity does not exist.
        """
        return self._update(entity_id, values, purge_props)

    def delete_entity_by_id(self, entity_id, keystone_id):
        """Remove the entity by its ID"""

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
        """
        Sub-class hook: return new entity instance (in Python, not in db).
        """
        return None

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        return None

    def _do_convert_values(self, values):
        """
        Sub-class hook: convert text-based values to
        target types for the database.
        """
        pass

    def _do_validate(self, values):
        """
        Sub-class hook: validate values.

        Validates the incoming data and raises a Invalid exception
        if anything is out of order.

        :param values: Mapping of entity metadata to check
        """
        status = values.get('status', None)
        if not status:
            #TODO: I18n this!
            msg = "{0} status is required.".format(self._do_entity_name())
            raise exception.Invalid(msg)

        if not models.States.is_valid(status):
            msg = "Invalid status '{0}' for {1}.".format(
                status, self._do_entity_name())
            raise exception.Invalid(msg)

        return values

    def _update(self, entity_id, values, purge_props=False):
        """
        Used internally by update()

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
            LOG.exception("Problem getting Tenant {0}".format(keystone_id))
            entity = None
            if not suppress_exception:
                raise exception.NotFound("No %s found with keystone-ID %s"
                                         % (self._do_entity_name(),
                                            keystone_id))

        return entity


class SecretRepo(BaseRepo):
    """Repository for the Secret entity."""

    def get_by_create_date(self, keystone_id, offset_arg=None, limit_arg=None,
                           suppress_exception=False, session=None):
        """
        Returns a list of secrets, ordered by the date they were created at
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

            query = query.join(models.TenantSecret,
                               models.Secret.tenant_assocs) \
                         .join(models.Tenant, models.TenantSecret.tenants) \
                         .filter(models.Tenant.keystone_id == keystone_id)

            start = offset
            end = offset + limit
            LOG.debug('Retrieving from {0} to {1}'.format(start, end))

            entities = query[start:end]
            LOG.debug('Number entities retrieved: {0}'.format(len(entities)))

        except sa_orm.exc.NoResultFound:
            entities = None
            if not suppress_exception:
                raise exception.NotFound("No %s's found"
                                         % (self._do_entity_name()))

        return (entities, offset, limit)

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Secret"

    def _do_create_instance(self):
        return models.Secret()

    def _do_build_get_query(self, entity_id, keystone_id, session):
        """Sub-class hook: build a retrieve query."""
        utcnow = timeutils.utcnow()

        # Note: Must use '== None' below, not 'is None'.
        # TODO: Performance? Is the many-to-many join needed?
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
    """
    Repository for the EncryptedDatum entity (that stores encrypted
    information on behalf of a Secret.
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
        """
        Returns a list of orders, ordered by the date they were created at
        and paged based on the offset and limit fields.
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
            LOG.debug('Retrieving from {0} to {1}'.format(start, end))

            entities = query[start:end]
            LOG.debug('Number entities retrieved: {0}'.format(len(entities)))

        except sa_orm.exc.NoResultFound:
            entities = None
            if not suppress_exception:
                raise exception.NotFound("No %s's found"
                                         % (self._do_entity_name()))

        return (entities, offset, limit)

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
