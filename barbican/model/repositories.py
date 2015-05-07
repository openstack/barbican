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

from oslo_config import cfg
from oslo_log import log
import sqlalchemy
from sqlalchemy import func as sa_func
from sqlalchemy import or_
import sqlalchemy.orm as sa_orm

from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
from barbican.model.migration import commands
from barbican.model import models
from barbican.openstack.common import timeutils

LOG = utils.getLogger(__name__)


_ENGINE = None
_SESSION_FACTORY = None
BASE = models.BASE
sa_logger = None

# Singleton repository references, instantiated via get_xxxx_repository()
#   functions below.  Please keep this list in alphabetical order.
_CA_REPOSITORY = None
_CONTAINER_ACL_REPOSITORY = None
_CONTAINER_CONSUMER_REPOSITORY = None
_CONTAINER_REPOSITORY = None
_CONTAINER_SECRET_REPOSITORY = None
_ENCRYPTED_DATUM_REPOSITORY = None
_KEK_DATUM_REPOSITORY = None
_ORDER_PLUGIN_META_REPOSITORY = None
_ORDER_BARBICAN_META_REPOSITORY = None
_ORDER_REPOSITORY = None
_ORDER_RETRY_TASK_REPOSITORY = None
_PREFERRED_CA_REPOSITORY = None
_PROJECT_REPOSITORY = None
_PROJECT_CA_REPOSITORY = None
_PROJECT_SECRET_REPOSITORY = None
_SECRET_ACL_REPOSITORY = None
_SECRET_META_REPOSITORY = None
_SECRET_REPOSITORY = None
_TRANSPORT_KEY_REPOSITORY = None

db_opts = [
    cfg.IntOpt('sql_idle_timeout', default=3600),
    cfg.IntOpt('sql_max_retries', default=60),
    cfg.IntOpt('sql_retry_interval', default=1),
    cfg.BoolOpt('db_auto_create', default=True),
    cfg.StrOpt('sql_connection'),
    cfg.IntOpt('max_limit_paging', default=100),
    cfg.IntOpt('default_limit_paging', default=10),
    cfg.StrOpt('sql_pool_class', default=None),
    cfg.BoolOpt('sql_pool_logging', default=False),
    cfg.IntOpt('sql_pool_size', default=None),
    cfg.IntOpt('sql_pool_max_overflow', default=None),
]

CONF = cfg.CONF
CONF.register_opts(db_opts)
log.register_options(CONF)


def hard_reset():
    """Performs a hard reset of database resources, used for unit testing."""
    # TODO(jvrbanac): Remove this as soon as we improve our unit testing
    # to not require this.
    global _ENGINE, _SESSION_FACTORY
    if _ENGINE:
        _ENGINE.dispose()
    _ENGINE = None
    _SESSION_FACTORY = None

    # Make sure we reinitialize the engine and session factory
    setup_database_engine_and_factory()


def setup_database_engine_and_factory():
    global sa_logger, _SESSION_FACTORY, _ENGINE

    LOG.info('Setting up database engine and session factory')
    LOG.debug('Sql connection = %s', CONF.sql_connection)
    if CONF.debug:
        sa_logger = logging.getLogger('sqlalchemy.engine')
        sa_logger.setLevel(logging.DEBUG)
    if CONF.sql_pool_logging:
        pool_logger = logging.getLogger('sqlalchemy.pool')
        pool_logger.setLevel(logging.DEBUG)

    _ENGINE = _get_engine(_ENGINE)

    # Utilize SQLAlchemy's scoped_session to ensure that we only have one
    # session instance per thread.
    session_maker = sa_orm.sessionmaker(bind=_ENGINE)
    _SESSION_FACTORY = sqlalchemy.orm.scoped_session(session_maker)


def start():
    """Start for read-write requests placeholder

    Typically performed at the start of a request cycle, say for POST or PUT
    requests.
    """
    pass


def start_read_only():
    """Start for read-only requests placeholder

    Typically performed at the start of a request cycle, say for GET or HEAD
    requests.
    """
    pass


def commit():
    """Commit session state so far to the database.

    Typically performed at the end of a request cycle.
    """
    get_session().commit()


def rollback():
    """Rollback session state so far.

    Typically performed when the request cycle raises an Exception.
    """
    get_session().rollback()


def clear():
    """Dispose of this session, releases db resources.

    Typically performed at the end of a request cycle, after a
    commit() or rollback().
    """
    _SESSION_FACTORY.remove()


def get_session():
    """Helper method to grab session."""
    return _SESSION_FACTORY()


def _get_engine(engine):
    if not engine:
        connection = CONF.sql_connection
        if not connection:
            raise exception.BarbicanException(
                u._('No SQL connection configured'))

    # TODO(jfwood):
    # connection_dict = sqlalchemy.engine.url.make_url(_CONNECTION)

        engine_args = {
            'pool_recycle': CONF.sql_idle_timeout,
            'echo': False,
            'convert_unicode': True}
        if CONF.sql_pool_class:
            engine_args['poolclass'] = utils.get_class_for(
                'sqlalchemy.pool', CONF.sql_pool_class)
        if CONF.sql_pool_size:
            engine_args['pool_size'] = CONF.sql_pool_size
        if CONF.sql_pool_max_overflow:
            engine_args['max_overflow'] = CONF.sql_pool_max_overflow

        try:
            engine = _create_engine(connection, **engine_args)
            engine.connect()
        except Exception as err:
            msg = u._("Error configuring registry database with supplied "
                      "sql_connection. Got error: {error}").format(error=err)
            LOG.exception(msg)
            raise exception.BarbicanException(msg)

        if CONF.db_auto_create:
            meta = sqlalchemy.MetaData()
            meta.reflect(bind=engine)
            tables = meta.tables

            _auto_generate_tables(engine, tables)
        else:
            LOG.info(u._LI('Not auto-creating barbican registry DB'))

    return engine


def is_db_connection_error(args):
    """Return True if error in connecting to db."""
    # NOTE(adam_g): This is currently MySQL specific and needs to be extended
    #               to support Postgres and others.
    conn_err_codes = ('2002', '2003', '2006')
    for err_code in conn_err_codes:
        if args.find(err_code) != -1:
            return True
    return False


def _create_engine(connection, **engine_args):
    LOG.debug("Sql connection: %s; Args: %s", connection, engine_args)

    engine = sqlalchemy.create_engine(connection, **engine_args)

    # TODO(jfwood): if 'mysql' in connection_dict.drivername:
    # TODO(jfwood): sqlalchemy.event.listen(_ENGINE, 'checkout',
    # TODO(jfwood):                         ping_listener)

    # Wrap the engine's connect method with a retry decorator.
    engine.connect = wrap_db_error(engine.connect)

    return engine


def _auto_generate_tables(engine, tables):
    if tables and 'alembic_version' in tables:
        # Upgrade the database to the latest version.
        LOG.info(u._LI('Updating schema to latest version'))
        commands.upgrade()
    else:
        # Create database tables from our models.
        LOG.info(u._LI('Auto-creating barbican registry DB'))
        models.register_models(engine)

        # Sync the alembic version 'head' with current models.
        commands.stamp()


def wrap_db_error(f):
    """Retry DB connection. Copied from nova and modified."""
    def _wrap(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except sqlalchemy.exc.OperationalError as e:
            if not is_db_connection_error(e.args[0]):
                raise

            remaining_attempts = CONF.sql_max_retries
            while True:
                LOG.warning(u._LW('SQL connection failed. %d attempts left.'),
                            remaining_attempts)
                remaining_attempts -= 1
                time.sleep(CONF.sql_retry_interval)
                try:
                    return f(*args, **kwargs)
                except sqlalchemy.exc.OperationalError as e:
                    if (remaining_attempts <= 0 or not
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
        if offset < 0:
            offset = 0
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


def delete_all_project_resources(project_id):
    """Logic to cleanup all project resources.

    This cleanup uses same alchemy session to perform all db operations as a
    transaction and will commit only when all db operations are performed
    without error.
    """
    session = get_session()

    container_repo = get_container_repository()
    container_repo.delete_project_entities(
        project_id, suppress_exception=False, session=session)
    # secret children SecretStoreMetadatum, EncryptedDatum
    # and container_secrets are deleted as part of secret delete
    secret_repo = get_secret_repository()
    secret_repo.delete_project_entities(
        project_id, suppress_exception=False, session=session)
    kek_repo = get_kek_datum_repository()
    kek_repo.delete_project_entities(
        project_id, suppress_exception=False, session=session)
    project_secret_repo = get_project_secret_repository()
    project_secret_repo.delete_project_entities(
        project_id, suppress_exception=False, session=session)
    project_repo = get_project_repository()
    project_repo.delete_project_entities(
        project_id, suppress_exception=False, session=session)


class BaseRepo(object):
    """Base repository for the barbican entities.

    This class provides template methods that allow sub-classes to hook
    specific functionality as needed. Clients access instances of this class
    via singletons, therefore implementations should be stateless aside from
    configuration.
    """

    def get_session(self, session=None):
        LOG.debug("Getting session...")
        return session or get_session()

    def get(self, entity_id, external_project_id=None,
            force_show_deleted=False,
            suppress_exception=False, session=None):
        """Get an entity or raise if it does not exist."""
        session = self.get_session(session)

        try:
            query = self._do_build_get_query(entity_id,
                                             external_project_id,
                                             session)

            # filter out deleted entities if requested
            if not force_show_deleted:
                query = query.filter_by(deleted=False)

            entity = query.one()

        except sa_orm.exc.NoResultFound:
            LOG.exception(u._LE("Not found for %s"), entity_id)
            entity = None
            if not suppress_exception:
                _raise_entity_not_found(self._do_entity_name(), entity_id)

        return entity

    def create_from(self, entity, session=None):
        """Sub-class hook: create from entity."""
        if not entity:
            msg = u._(
                "Must supply non-None {entity_name}."
            ).format(entity_name=self._do_entity_name())
            raise exception.Invalid(msg)

        if entity.id:
            msg = u._(
                "Must supply {entity_name} with id=None (i.e. new entity)."
            ).format(entity_name=self._do_entity_name())
            raise exception.Invalid(msg)

        LOG.debug("Begin create from...")
        start = time.time()  # DEBUG

        # Validate the attributes before we go any further. From my
        # (unknown Glance developer) investigation, the @validates
        # decorator does not validate
        # on new records, only on existing records, which is, well,
        # idiotic.
        self._do_validate(entity.to_dict())

        try:
            LOG.debug("Saving entity...")
            entity.save(session=session)
        except sqlalchemy.exc.IntegrityError:
            LOG.exception(u._LE('Problem saving entity for create'))
            _raise_entity_already_exists(self._do_entity_name())

        LOG.debug('Elapsed repo '
                  'create secret:%s', (time.time() - start))  # DEBUG

        return entity

    def save(self, entity):
        """Saves the state of the entity."""
        entity.updated_at = timeutils.utcnow()

        # Validate the attributes before we go any further. From my
        # (unknown Glance developer) investigation, the @validates
        # decorator does not validate
        # on new records, only on existing records, which is, well,
        # idiotic.
        self._do_validate(entity.to_dict())

        entity.save()

    def delete_entity_by_id(self, entity_id, external_project_id,
                            session=None):
        """Remove the entity by its ID."""

        session = self.get_session(session)

        entity = self.get(entity_id=entity_id,
                          external_project_id=external_project_id,
                          session=session)

        entity.delete(session=session)

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Entity"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        return None

    def _do_convert_values(self, values):
        """Sub-class hook: convert text-based values to target types

        This is specifically for database values.
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
            # TODO(jfwood): I18n this!
            msg = u._("{entity_name} status is required.").format(
                entity_name=self._do_entity_name())
            raise exception.Invalid(msg)

        if not models.States.is_valid(status):
            msg = u._("Invalid status '{status}' for {entity_name}.").format(
                status=status, entity_name=self._do_entity_name())
            raise exception.Invalid(msg)

        return values

    def _update_values(self, entity_ref, values):
        for k in values:
            if getattr(entity_ref, k) != values[k]:
                setattr(entity_ref, k, values[k])

    def _build_get_project_entities_query(self, project_id, session):
        """Sub-class hook: build a query to retrieve entities for a project.

        :param project_id: id of barbican project entity
        :param session: existing db session reference.
        :returns: A query object for getting all project related entities

        This will filter deleted entities if there.
        """
        msg = u._(
            "{entity_name} is missing query build method for get "
            "project entities.").format(
                entity_name=self._do_entity_name())
        raise NotImplementedError(msg)

    def get_project_entities(self, project_id, session=None):
        """Gets entities associated with a given project.

        :param project_id: id of barbican project entity
        :param session: existing db session reference. If None, gets session.
        :returns: list of matching entities found otherwise returns empty list
                  if no entity exists for a given project.

        Sub-class should implement `_build_get_project_entities_query` function
        to delete related entities otherwise it would raise NotImplementedError
        on its usage.
        """

        session = self.get_session(session)
        query = self._build_get_project_entities_query(project_id, session)
        if query:
            return query.all()
        else:
            return []

    def delete_project_entities(self, project_id,
                                suppress_exception=False,
                                session=None):
        """Deletes entities for a given project.

        :param project_id: id of barbican project entity
        :param suppress_exception: Pass True if want to suppress exception
        :param session: existing db session reference. If None, gets session.

        Sub-class should implement `_build_get_project_entities_query` function
        to delete related entities otherwise it would raise NotImplementedError
        on its usage.
        """
        session = self.get_session(session)
        query = self._build_get_project_entities_query(project_id,
                                                       session=session)
        try:
            # query cannot be None as related repo class is expected to
            # implement it otherwise error is raised in build query call
            for entity in query:
                # Its a soft delete so its more like entity update
                entity.delete(session=session)
        except sqlalchemy.exc.SQLAlchemyError:
            LOG.exception(u._LE('Problem finding project related entity to '
                                'delete'))
            if not suppress_exception:
                raise exception.BarbicanException(u._('Error deleting project '
                                                      'entities for '
                                                      'project_id=%s'),
                                                  project_id)


class ProjectRepo(BaseRepo):
    """Repository for the Project entity."""

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Project"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.Project).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def find_by_external_project_id(self, external_project_id,
                                    suppress_exception=False, session=None):
        session = self.get_session(session)

        try:
            query = session.query(models.Project)
            query = query.filter_by(external_id=external_project_id)

            entity = query.one()

        except sa_orm.exc.NoResultFound:
            entity = None
            if not suppress_exception:
                LOG.exception(u._LE("Problem getting Project %s"),
                              external_project_id)
                raise exception.NotFound(u._(
                    "No {entity_name} found with keystone-ID {id}").format(
                        entity_name=self._do_entity_name(),
                        id=external_project_id))

        return entity

    def _build_get_project_entities_query(self, project_id, session):
        """Builds query for retrieving project for given id."""
        query = session.query(models.Project)
        return query.filter_by(id=project_id).filter_by(deleted=False)


class SecretRepo(BaseRepo):
    """Repository for the Secret entity."""

    def get_by_create_date(self, external_project_id, offset_arg=None,
                           limit_arg=None, name=None, alg=None, mode=None,
                           bits=0, secret_type=None, suppress_exception=False,
                           session=None):
        """Returns a list of secrets

        The returned secrets are ordered by the date they were created at
        and paged based on the offset and limit fields. The external_project_id
        is external-to-Barbican value assigned to the project by Keystone.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)
        utcnow = timeutils.utcnow()

        query = session.query(models.Secret)
        query = query.order_by(models.Secret.created_at)
        query = query.filter_by(deleted=False)

        # Note(john-wood-w): SQLAlchemy requires '== None' below,
        #   not 'is None'.
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
        if secret_type:
            query = query.filter(models.Secret.secret_type == secret_type)

        query = query.join(models.ProjectSecret,
                           models.Secret.project_assocs)
        query = query.join(models.Project, models.ProjectSecret.projects)
        query = query.filter(models.Project.external_id == external_project_id)

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number entities retrieved: %s out of %s',
                  len(entities), total
                  )

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Secret"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        utcnow = timeutils.utcnow()

        # Note(john-wood-w): SQLAlchemy requires '== None' below,
        #   not 'is None'.
        # TODO(jfwood): Performance? Is the many-to-many join needed?
        expiration_filter = or_(models.Secret.expiration == None,
                                models.Secret.expiration > utcnow)

        query = session.query(models.Secret)
        query = query.filter_by(id=entity_id, deleted=False)
        query = query.filter(expiration_filter)
        query = query.join(models.ProjectSecret, models.Secret.project_assocs)
        query = query.join(models.Project, models.ProjectSecret.projects)
        query = query.filter(models.Project.external_id == external_project_id)

        return query

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def _build_get_project_entities_query(self, project_id, session):
        """Builds query for retrieving Secrets associated with a given project

        Discovery is done via a ProjectSecret association.

        :param project_id: id of barbican project entity
        :param session: existing db session reference.
        """
        query = session.query(models.Secret).filter_by(deleted=False)
        query = query.join(models.ProjectSecret, models.Secret.project_assocs)
        query = query.filter(models.ProjectSecret.project_id == project_id)
        return query

    def get_secret_by_id(self, entity_id, suppress_exception=False,
                         session=None):
        """Gets secret by its entity id without project id check."""
        session = self.get_session(session)
        try:
            utcnow = timeutils.utcnow()
            # Note(john-wood-w): SQLAlchemy requires '== None' below,
            #   not 'is None'.
            expiration_filter = or_(models.Secret.expiration == None,
                                    models.Secret.expiration > utcnow)

            query = session.query(models.Secret)
            query = query.filter_by(id=entity_id, deleted=False)
            query = query.filter(expiration_filter)
            entity = query.one()
        except sa_orm.exc.NoResultFound:
            entity = None
            if not suppress_exception:
                LOG.exception(u._LE("Problem getting secret %s"),
                              entity_id)
                raise exception.NotFound(u._(
                    "No secret found with secret-ID {id}").format(
                        entity_name=self._do_entity_name(),
                        id=entity_id))
        return entity


class EncryptedDatumRepo(BaseRepo):
    """Repository for the EncryptedDatum entity

    Stores encrypted information on behalf of a Secret.
    """

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "EncryptedDatum"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.EncryptedDatum).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class SecretStoreMetadatumRepo(BaseRepo):
    """Repository for the SecretStoreMetadatum entity

    Stores key/value information on behalf of a Secret.
    """

    def save(self, metadata, secret_model):
        """Saves the the specified metadata for the secret.

        :raises NotFound if entity does not exist.
        """
        now = timeutils.utcnow()

        for k, v in metadata.items():
            meta_model = models.SecretStoreMetadatum(k, v)
            meta_model.updated_at = now
            meta_model.secret = secret_model
            meta_model.save()

    def get_metadata_for_secret(self, secret_id):
        """Returns a dict of SecretStoreMetadatum instances."""

        session = get_session()

        try:
            query = session.query(models.SecretStoreMetadatum)
            query = query.filter_by(deleted=False)

            query = query.filter(
                models.SecretStoreMetadatum.secret_id == secret_id)

            metadata = query.all()

        except sa_orm.exc.NoResultFound:
            metadata = {}

        return {m.key: m.value for m in metadata}

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "SecretStoreMetadatum"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.SecretStoreMetadatum)
        return query.filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class KEKDatumRepo(BaseRepo):
    """Repository for the KEKDatum entity

    Stores key encryption key (KEK) metadata used by crypto plugins to
    encrypt/decrypt secrets.
    """

    def find_or_create_kek_datum(self, project,
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
            query = session.query(models.KEKDatum)
            query = query.filter_by(project_id=project.id,
                                    plugin_name=plugin_name,
                                    active=True,
                                    deleted=False)

            kek_datum = query.one()

        except sa_orm.exc.NoResultFound:

            kek_datum = models.KEKDatum()

            kek_datum.kek_label = "project-{0}-key-{1}".format(
                project.external_id, uuid.uuid4())
            kek_datum.project_id = project.id
            kek_datum.plugin_name = plugin_name
            kek_datum.status = models.States.ACTIVE

            self.save(kek_datum)

        return kek_datum

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "KEKDatum"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.KEKDatum).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def _build_get_project_entities_query(self, project_id, session):
        """Builds query for retrieving KEK Datum instance(s).

        The returned KEK Datum instance(s) are related to a given project.

        :param project_id: id of barbican project entity
        :param session: existing db session reference.
        """
        return session.query(models.KEKDatum).filter_by(
            project_id=project_id).filter_by(deleted=False)


class ProjectSecretRepo(BaseRepo):
    """Repository for the ProjectSecret entity."""

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "ProjectSecret"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.ProjectSecret).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def _build_get_project_entities_query(self, project_id, session):
        """Builds query for retrieving ProjectSecret related to given project.

        :param project_id: id of barbican project entity
        :param session: existing db session reference.
        """
        return session.query(models.ProjectSecret).filter_by(
            project_id=project_id).filter_by(deleted=False)


class OrderRepo(BaseRepo):
    """Repository for the Order entity."""

    def get_by_create_date(self, external_project_id, offset_arg=None,
                           limit_arg=None, suppress_exception=False,
                           session=None):
        """Returns a list of orders

        The list is ordered by the date they were created at and paged
        based on the offset and limit fields.

        :param external_project_id: The keystone id for the project.
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

        query = session.query(models.Order)
        query = query.order_by(models.Order.created_at)
        query = query.filter_by(deleted=False)
        query = query.join(models.Project, models.Order.project)
        query = query.filter(models.Project.external_id == external_project_id)

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number entities retrieved: %s out of %s',
                  len(entities), total
                  )

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Order"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.Order)
        query = query.filter_by(id=entity_id, deleted=False)
        query = query.join(models.Project, models.Order.project)
        query = query.filter(models.Project.external_id == external_project_id)
        return query

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def _build_get_project_entities_query(self, project_id, session):
        """Builds query for retrieving orders related to given project.

        :param project_id: id of barbican project entity
        :param session: existing db session reference.
        """
        return session.query(models.Order).filter_by(
            project_id=project_id).filter_by(deleted=False)


class OrderPluginMetadatumRepo(BaseRepo):
    """Repository for the OrderPluginMetadatum entity

    Stores key/value plugin information on behalf of an Order.
    """

    def save(self, metadata, order_model):
        """Saves the the specified metadata for the order.

        :raises NotFound if entity does not exist.
        """
        now = timeutils.utcnow()
        session = get_session()

        for k, v in metadata.items():
            meta_model = models.OrderPluginMetadatum(k, v)
            meta_model.updated_at = now
            meta_model.order = order_model
            meta_model.save(session=session)

    def get_metadata_for_order(self, order_id):
        """Returns a dict of OrderPluginMetadatum instances."""

        session = get_session()

        try:
            query = session.query(models.OrderPluginMetadatum)
            query = query.filter_by(deleted=False)

            query = query.filter(
                models.OrderPluginMetadatum.order_id == order_id)

            metadata = query.all()

        except sa_orm.exc.NoResultFound:
            metadata = {}

        return {m.key: m.value for m in metadata}

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "OrderPluginMetadatum"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.OrderPluginMetadatum)
        return query.filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class OrderBarbicanMetadatumRepo(BaseRepo):
    """Repository for the OrderBarbicanMetadatum entity

    Stores key/value plugin information on behalf of a Order.
    """

    def save(self, metadata, order_model):
        """Saves the the specified metadata for the order.

        :raises NotFound if entity does not exist.
        """
        now = timeutils.utcnow()
        session = get_session()

        for k, v in metadata.items():
            meta_model = models.OrderBarbicanMetadatum(k, v)
            meta_model.updated_at = now
            meta_model.order = order_model
            meta_model.save(session=session)

    def get_metadata_for_order(self, order_id):
        """Returns a dict of OrderBarbicanMetadatum instances."""

        session = get_session()

        try:
            query = session.query(models.OrderBarbicanMetadatum)
            query = query.filter_by(deleted=False)

            query = query.filter(
                models.OrderBarbicanMetadatum.order_id == order_id)

            metadata = query.all()

        except sa_orm.exc.NoResultFound:
            metadata = {}

        return {m.key: m.value for m in metadata}

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "OrderBarbicanMetadatum"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.OrderBarbicanMetadatum)
        return query.filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class OrderRetryTaskRepo(BaseRepo):
    """Repository for the OrderRetryTask entity."""

    def get_by_create_date(
            self, only_at_or_before_this_date=None,
            offset_arg=None, limit_arg=None,
            suppress_exception=False,
            session=None):
        """Returns a list of order retry task entities

        The list is ordered by the date they were created at and paged
        based on the offset and limit fields.

        :param only_at_or_before_this_date: If specified, only entities at or
            before this date are returned.
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

        query = session.query(models.OrderRetryTask)
        query = query.order_by(models.OrderRetryTask.created_at)
        query = query.filter_by(deleted=False)
        if only_at_or_before_this_date:
            query = query.filter(
                models.OrderRetryTask.retry_at <= only_at_or_before_this_date)

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number entities retrieved: %s out of %s',
                  len(entities), total
                  )

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "OrderRetryTask"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.OrderRetryTask)
        query = query.filter_by(id=entity_id, deleted=False)
        return query

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class ContainerRepo(BaseRepo):
    """Repository for the Container entity."""

    def get_by_create_date(self, external_project_id, offset_arg=None,
                           limit_arg=None, suppress_exception=False,
                           session=None):
        """Returns a list of containers

        The list is ordered by the date they were created at and paged
        based on the offset and limit fields. The external_project_id is
        external-to-Barbican value assigned to the project by Keystone.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        query = session.query(models.Container)
        query = query.order_by(models.Container.created_at)
        query = query.filter_by(deleted=False)
        query = query.join(models.Project, models.Container.project)
        query = query.filter(models.Project.external_id == external_project_id)

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number entities retrieved: %s out of %s',
                  len(entities), total
                  )

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "Container"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.Container)
        query = query.filter_by(id=entity_id, deleted=False)
        query = query.join(models.Project, models.Container.project)
        query = query.filter(models.Project.external_id == external_project_id)
        return query

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def _build_get_project_entities_query(self, project_id, session):
        """Builds query for retrieving container related to given project.

        :param project_id: id of barbican project entity
        :param session: existing db session reference.
        """
        return session.query(models.Container).filter_by(
            deleted=False).filter_by(project_id=project_id)

    def get_container_by_id(self, entity_id, suppress_exception=False,
                            session=None):
        """Gets container by its entity id without project id check."""
        session = self.get_session(session)
        try:
            query = session.query(models.Container)
            query = query.filter_by(id=entity_id, deleted=False)
            entity = query.one()
        except sa_orm.exc.NoResultFound:
            entity = None
            if not suppress_exception:
                LOG.exception(u._LE("Problem getting container %s"),
                              entity_id)
                raise exception.NotFound(u._(
                    "No container found with container-ID {id}").format(
                        entity_name=self._do_entity_name(),
                        id=entity_id))
        return entity


class ContainerSecretRepo(BaseRepo):
        """Repository for the ContainerSecret entity."""
        def _do_entity_name(self):
            """Sub-class hook: return entity name, such as for debugging."""
            return "ContainerSecret"

        def _do_build_get_query(self, entity_id, external_project_id, session):
            """Sub-class hook: build a retrieve query."""
            return session.query(models.ContainerSecret
                                 ).filter_by(id=entity_id)

        def _do_validate(self, values):
            """Sub-class hook: validate values."""
            pass


class ContainerConsumerRepo(BaseRepo):
    """Repository for the Service entity."""

    def get_by_container_id(self, container_id,
                            offset_arg=None, limit_arg=None,
                            suppress_exception=False, session=None):
        """Returns a list of Consumers

        The list is ordered by the date they were created at and paged
        based on the offset and limit fields.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        query = session.query(models.ContainerConsumerMetadatum)
        query = query.order_by(models.ContainerConsumerMetadatum.name)
        query = query.filter_by(deleted=False)
        query = query.filter(
            models.ContainerConsumerMetadatum.container_id == container_id
        )

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number entities retrieved: %s out of %s',
                  len(entities), total
                  )

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def get_by_values(self, container_id, name, URL, suppress_exception=False,
                      show_deleted=False, session=None):
        session = self.get_session(session)

        try:
            query = session.query(models.ContainerConsumerMetadatum)
            query = query.filter_by(
                container_id=container_id,
                name=name,
                URL=URL)

            if not show_deleted:
                query.filter_by(deleted=False)
            consumer = query.one()
        except sa_orm.exc.NoResultFound:
            if not suppress_exception:
                raise exception.NotFound(
                    u._("Could not find {entity_name}").format(
                        entity_name=self._do_entity_name()))

        return consumer

    def create_or_update_from(self, new_consumer, container, session=None):
        session = self.get_session(session)
        try:
            container.updated_at = timeutils.utcnow()
            container.consumers.append(new_consumer)
            container.save(session=session)
        except sqlalchemy.exc.IntegrityError:
            session.rollback()  # We know consumer already exists.

            # This operation is idempotent, so log this and move on
            LOG.debug("Consumer %s already exists for container %s,"
                      " continuing...", (new_consumer.name, new_consumer.URL),
                      new_consumer.container_id)
            # Get the existing entry and reuse it by clearing the deleted flags
            existing_consumer = self.get_by_values(
                new_consumer.container_id, new_consumer.name, new_consumer.URL,
                show_deleted=True)
            existing_consumer.deleted = False
            existing_consumer.deleted_at = None
            # We are not concerned about timing here -- set only, no reads
            existing_consumer.save()

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "ContainerConsumer"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.ContainerConsumerMetadatum)
        return query.filter_by(id=entity_id, deleted=False)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class TransportKeyRepo(BaseRepo):
    """Repository for the TransportKey entity

    Stores transport keys for wrapping the secret data to/from a
    barbican client.
    """

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "TransportKey"

    def get_by_create_date(self, plugin_name=None,
                           offset_arg=None, limit_arg=None,
                           suppress_exception=False, session=None):
        """Returns a list of transport keys

        The list is ordered from latest created first. The search accepts
        plugin_id as an optional parameter for the search.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        query = session.query(models.TransportKey)
        query = query.order_by(models.TransportKey.created_at)
        if plugin_name is not None:
            query = session.query(models.TransportKey)
            query = query.filter_by(deleted=False, plugin_name=plugin_name)
        else:
            query = query.filter_by(deleted=False)

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number of entities retrieved: %s out of %s',
                  len(entities), total)

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def get_latest_transport_key(self, plugin_name, suppress_exception=False,
                                 session=None):
        """Returns the latest transport key for a given plugin."""
        entity, offset, limit, total = self.get_by_create_date(
            plugin_name, offset_arg=0, limit_arg=1,
            suppress_exception=suppress_exception, session=session)
        return entity

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.TransportKey).filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class CertificateAuthorityRepo(BaseRepo):
    """Repository for the CertificateAuthority entity."""

    def get_by_create_date(self, offset_arg=None, limit_arg=None,
                           plugin_name=None, plugin_ca_id=None,
                           suppress_exception=False, session=None,
                           show_expired=False):
        """Returns a list of certificate authorities

        The returned certificate authorities are ordered by the date they
        were created and paged based on the offset and limit fields.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        query = session.query(models.CertificateAuthority)
        query = query.order_by(models.CertificateAuthority.created_at)
        query = query.filter_by(deleted=False)

        # Note(alee) SQLAlchemy requires '== None' below,
        #   not 'is None'.
        if not show_expired:
            utcnow = timeutils.utcnow()
            query = query.filter(or_(
                models.CertificateAuthority.expiration == None,
                models.CertificateAuthority.expiration > utcnow))

        if plugin_name:
            query = query.filter(
                models.CertificateAuthority.plugin_name.like(plugin_name))
        if plugin_ca_id:
            query = query.filter(
                models.CertificateAuthority.plugin_ca_id.like(plugin_ca_id))

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number entities retrieved: %s out of %s',
                  len(entities), total
                  )

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def update_entity(self, old_ca, parsed_ca_in, session=None):
        """Updates CA entry and its sub-entries."""
        parsed_ca = dict(parsed_ca_in)

        # these fields cannot be  modified
        parsed_ca.pop('plugin_name', None)
        parsed_ca.pop('plugin_ca_id', None)

        expiration = parsed_ca.pop('expiration', None)
        expiration_iso = timeutils.parse_isotime(expiration.strip())
        new_expiration = timeutils.normalize_time(expiration_iso)

        session = self.get_session(session)
        query = session.query(models.CertificateAuthority).filter_by(
            id=old_ca.id, deleted=False)
        entity = query.one()

        entity.expiration = new_expiration

        for k, v in entity.ca_meta.items():
            if k not in parsed_ca.keys():
                v.delete(session)

        for key in parsed_ca:
            if key not in entity.ca_meta.keys():
                meta = models.CertificateAuthorityMetadatum(
                    key, parsed_ca[key])
                entity.ca_meta[key] = meta
            else:
                entity.ca_meta[key].value = parsed_ca[key]

        entity.save()
        return entity

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "CertificateAuthority"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        utcnow = timeutils.utcnow()

        # Note(alee): SQLAlchemy requires '== None' below,
        #   not 'is None'.
        # TODO(jfwood): Performance? Is the many-to-many join needed?
        expiration_filter = or_(
            models.CertificateAuthority.expiration == None,
            models.CertificateAuthority.expiration > utcnow)

        query = session.query(models.CertificateAuthority)
        query = query.filter_by(id=entity_id, deleted=False)
        query = query.filter(expiration_filter)

        return query

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class CertificateAuthorityMetadatumRepo(BaseRepo):
    """Repository for the CertificateAuthorityMetadatum entity

    Stores key/value information on behalf of a CA.
    """

    def save(self, metadata, ca_model):
        """Saves the the specified metadata for the CA.

        :raises NotFound if entity does not exist.
        """
        now = timeutils.utcnow()
        session = get_session()

        for k, v in metadata.items():
            meta_model = models.CertificateAuthorityMetadatum(k, v)
            meta_model.updated_at = now
            meta_model.ca = ca_model
            meta_model.save(session=session)

    def get_metadata_for_certificate_authority(self, ca_id):
        """Returns a dict of CertificateAuthorityMetadatum instances."""

        session = get_session()

        try:
            query = session.query(models.CertificateAuthorityMetadatum)
            query = query.filter_by(deleted=False)

            query = query.filter(
                models.CertificateAuthorityMetadatum.ca_id == ca_id)

            metadata = query.all()

        except sa_orm.exc.NoResultFound:
            metadata = dict()

        return dict((m.key, m.value) for m in metadata)

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "CertificateAuthorityMetadatum"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.CertificateAuthorityMetadatum)
        return query.filter_by(id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass


class ProjectCertificateAuthorityRepo(BaseRepo):
    """Repository for the ProjectCertificateAuthority entity."""

    def get_by_create_date(self, offset_arg=None, limit_arg=None,
                           project_id=None, ca_id=None,
                           suppress_exception=False, session=None):
        """Returns a list of project CAs

        The returned project are ordered by the date they
        were created and paged based on the offset and limit fields.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        query = session.query(models.ProjectCertificateAuthority)
        query = query.order_by(models.ProjectCertificateAuthority.created_at)
        query = query.filter_by(deleted=False)

        if project_id:
            query = query.filter(
                models.ProjectCertificateAuthority.project_id.like(project_id))
        if ca_id:
            query = query.filter(
                models.ProjectCertificateAuthority.ca_id.like(ca_id))

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number entities retrieved: %s out of %s',
                  len(entities), total
                  )

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "ProjectCertificateAuthority"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.ProjectCertificateAuthority).filter_by(
            id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def _build_get_project_entities_query(self, project_id, session):
        """Builds query for retrieving CA related to given project.

        :param project_id: id of barbican project entity
        :param session: existing db session reference.
        """
        return session.query(models.ProjectCertificateAuthority).filter_by(
            project_id=project_id).filter_by(deleted=False)


class PreferredCertificateAuthorityRepo(BaseRepo):
    """Repository for the PreferredCertificateAuthority entity."""

    PREFERRED_PROJECT_ID = "0"

    def get_by_create_date(self, offset_arg=None, limit_arg=None,
                           project_id=None, ca_id=None,
                           suppress_exception=False, session=None):
        """Returns a list of preferred CAs

        The returned CAs are ordered by the date they
        were created and paged based on the offset and limit fields.
        """

        offset, limit = clean_paging_values(offset_arg, limit_arg)

        session = self.get_session(session)

        query = session.query(models.PreferredCertificateAuthority)
        query = query.order_by(models.PreferredCertificateAuthority.created_at)
        query = query.filter_by(deleted=False)

        if project_id:
            query = query.filter(
                models.PreferredCertificateAuthority.project_id.like(
                    project_id))
        if ca_id:
            query = query.filter(
                models.PreferredCertificateAuthority.ca_id.like(ca_id))

        start = offset
        end = offset + limit
        LOG.debug('Retrieving from %s to %s', start, end)
        total = query.count()
        entities = query[start:end]
        LOG.debug('Number entities retrieved: %s out of %s',
                  len(entities), total
                  )

        if total <= 0 and not suppress_exception:
            _raise_no_entities_found(self._do_entity_name())

        return entities, offset, limit, total

    def get_global_preferred_ca(self):
        pref_cas = self.get_project_entities(self.PREFERRED_PROJECT_ID)
        if len(pref_cas) > 0:
            return pref_cas[0]
        return None

    def update_global_preferred_ca(self, new_ca):
        self.update_preferred_ca(self.PREFERRED_PROJECT_ID, new_ca)

    def update_preferred_ca(self, project_id, new_ca):
        session = self.get_session()
        query = session.query(models.PreferredCertificateAuthority).filter_by(
            project_id=project_id)
        entity = query.one()
        entity.ca_id = new_ca.id
        entity.save()

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "PreferredCertificateAuthority"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        return session.query(models.PreferredCertificateAuthority).filter_by(
            id=entity_id)

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def _build_get_project_entities_query(self, project_id, session):
        """Builds query for retrieving preferred CA related to given project.

        :param project_id: id of barbican project entity
        :param session: existing db session reference.
        """
        return session.query(models.PreferredCertificateAuthority).filter_by(
            project_id=project_id).filter_by(deleted=False)


class SecretACLRepo(BaseRepo):
    """Repository for the SecretACL entity.

    There is no need for SecretACLUserRepo as none of logic access
    SecretACLUser (ACL user data) directly. Its always derived from
    SecretACL relationship.

    SecretACL and SecretACLUser data is not soft delete. So there is no need
    to have deleted=False filter in queries.
    """

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "SecretACL"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""
        query = session.query(models.SecretACL)
        query = query.filter_by(id=entity_id)
        return query

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def get_by_secret_id(self, secret_id, session=None):
        """Return list of secret ACLs by secret id."""

        session = self.get_session(session)

        query = session.query(models.SecretACL)
        query = query.filter_by(secret_id=secret_id)

        return query.all()

    def create_or_replace_from(self, secret, secret_acl, user_ids=None,
                               session=None):
        session = self.get_session(session)
        secret.updated_at = timeutils.utcnow()
        secret_acl.updated_at = timeutils.utcnow()
        secret.secret_acls.append(secret_acl)
        secret.save(session=session)

        self._create_or_replace_acl_users(secret_acl, user_ids,
                                          session=session)

    def _create_or_replace_acl_users(self, secret_acl, user_ids, session=None):
        """Creates or updates secret acl user based on input user_ids list.

        user_ids is expected to be list of ids (enforced by schema validation).
        Input user ids should have complete list of acl users. It does not
        apply partial update of user ids.

        If user_ids is None, no change is made in acl user data.
        If user_ids list is not None, then following change is made.
        For existing acl users, just update timestamp if user_id is present in
        input user ids list. Otherwise, remove existing acl user entries.
        Then add the remainining input user ids as new acl user db entries.
        """
        if user_ids is None:
            return

        user_ids = set(user_ids)

        now = timeutils.utcnow()
        session = self.get_session(session)
        secret_acl.updated_at = now

        for acl_user in secret_acl.acl_users:
            if acl_user.user_id in user_ids:  # input user_id already exists
                acl_user.updated_at = now
                user_ids.remove(acl_user.user_id)
            else:
                acl_user.delete(session)

        for user_id in user_ids:
            acl_user = models.SecretACLUser(secret_acl.id, user_id)
            secret_acl.acl_users.append(acl_user)

        secret_acl.save(session=session)

    def get_count(self, secret_id, session=None):
        """Gets count of existing secret ACL(s) for a given secret."""
        session = self.get_session(session)
        query = session.query(sa_func.count(models.SecretACL.id))
        query = query.filter(models.SecretACL.secret_id == secret_id)
        return query.scalar()

    def delete_acls_for_secret(self, secret, session=None):
        session = self.get_session(session)

        for entity in secret.secret_acls:
            entity.delete(session=session)


class ContainerACLRepo(BaseRepo):
    """Repository for the ContainerACL entity.

    There is no need for ContainerACLUserRepo as none of logic access
    ContainerACLUser (ACL user data) directly. Its always derived from
    ContainerACL relationship.

    ContainerACL and ContainerACLUser data is not soft delete. So there is no
    need to have deleted=False filter in queries.
    """

    def _do_entity_name(self):
        """Sub-class hook: return entity name, such as for debugging."""
        return "ContainerACL"

    def _do_build_get_query(self, entity_id, external_project_id, session):
        """Sub-class hook: build a retrieve query."""

        query = session.query(models.ContainerACL)
        query = query.filter_by(id=entity_id)

        return query

    def _do_validate(self, values):
        """Sub-class hook: validate values."""
        pass

    def get_by_container_id(self, container_id, session=None):
        """Return list of container ACLs by container id."""

        session = self.get_session(session)
        query = session.query(models.ContainerACL)
        query = query.filter_by(container_id=container_id)
        return query.all()

    def create_or_replace_from(self, container, container_acl,
                               user_ids=None, session=None):
        session = self.get_session(session)
        container.updated_at = timeutils.utcnow()
        container_acl.updated_at = timeutils.utcnow()
        container.container_acls.append(container_acl)
        container.save(session=session)

        self._create_or_replace_acl_users(container_acl, user_ids, session)

    def _create_or_replace_acl_users(self, container_acl, user_ids,
                                     session=None):
        """Creates or updates container acl user based on input user_ids list.

        user_ids is expected to be list of ids (enforced by schema validation).
        Input user ids should have complete list of acl users. It does not
        apply partial update of user ids.

        If user_ids is None, no change is made in acl user data.
        If user_ids list is not None, then following change is made.
        For existing acl users, just update timestamp if user_id is present in
        input user ids list. Otherwise, remove existing acl user entries.
        Then add the remainining input user ids as new acl user db entries.
        """
        if user_ids is None:
            return

        user_ids = set(user_ids)

        now = timeutils.utcnow()
        session = self.get_session(session)
        container_acl.updated_at = now

        for acl_user in container_acl.acl_users:
            if acl_user.user_id in user_ids:  # input user_id already exists
                acl_user.updated_at = now
                user_ids.remove(acl_user.user_id)
            else:
                acl_user.delete(session)

        for user_id in user_ids:
            acl_user = models.ContainerACLUser(container_acl.id, user_id)
            container_acl.acl_users.append(acl_user)

        container_acl.save(session=session)

    def get_count(self, container_id, session=None):
        """Gets count of existing container ACL(s) for a given container."""
        session = self.get_session(session)

        query = session.query(sa_func.count(models.ContainerACL.id))
        query = query.filter(models.ContainerACL.container_id == container_id)
        return query.scalar()

    def delete_acls_for_container(self, container, session=None):
        session = self.get_session(session)

        for entity in container.container_acls:
            entity.delete(session=session)


def get_ca_repository():
    """Returns a singleton Secret repository instance."""
    global _CA_REPOSITORY
    return _get_repository(_CA_REPOSITORY, CertificateAuthorityRepo)


def get_container_acl_repository():
    """Returns a singleton Container ACL repository instance."""
    global _CONTAINER_ACL_REPOSITORY
    return _get_repository(_CONTAINER_ACL_REPOSITORY, ContainerACLRepo)


def get_container_consumer_repository():
    """Returns a singleton Container Consumer repository instance."""
    global _CONTAINER_CONSUMER_REPOSITORY
    return _get_repository(_CONTAINER_CONSUMER_REPOSITORY,
                           ContainerConsumerRepo)


def get_container_repository():
    """Returns a singleton Container repository instance."""
    global _CONTAINER_REPOSITORY
    return _get_repository(_CONTAINER_REPOSITORY, ContainerRepo)


def get_container_secret_repository():
    """Returns a singleton Container-Secret repository instance."""
    global _CONTAINER_SECRET_REPOSITORY
    return _get_repository(_CONTAINER_SECRET_REPOSITORY, ContainerSecretRepo)


def get_encrypted_datum_repository():
    """Returns a singleton Encrypted Datum repository instance."""
    global _ENCRYPTED_DATUM_REPOSITORY
    return _get_repository(_ENCRYPTED_DATUM_REPOSITORY, EncryptedDatumRepo)


def get_kek_datum_repository():
    """Returns a singleton KEK Datum repository instance."""
    global _KEK_DATUM_REPOSITORY
    return _get_repository(_KEK_DATUM_REPOSITORY, KEKDatumRepo)


def get_order_plugin_meta_repository():
    """Returns a singleton Order-Plugin meta repository instance."""
    global _ORDER_PLUGIN_META_REPOSITORY
    return _get_repository(_ORDER_PLUGIN_META_REPOSITORY,
                           OrderPluginMetadatumRepo)


def get_order_barbican_meta_repository():
    """Returns a singleton Order-Barbican meta repository instance."""
    global _ORDER_BARBICAN_META_REPOSITORY
    return _get_repository(_ORDER_BARBICAN_META_REPOSITORY,
                           OrderBarbicanMetadatumRepo)


def get_order_repository():
    """Returns a singleton Order repository instance."""
    global _ORDER_REPOSITORY
    return _get_repository(_ORDER_REPOSITORY, OrderRepo)


def get_order_retry_tasks_repository():
    """Returns a singleton OrderRetryTask repository instance."""
    global _ORDER_RETRY_TASK_REPOSITORY
    return _get_repository(_ORDER_RETRY_TASK_REPOSITORY, OrderRetryTaskRepo)


def get_preferred_ca_repository():
    """Returns a singleton Secret repository instance."""
    global _PREFERRED_CA_REPOSITORY
    return _get_repository(_PREFERRED_CA_REPOSITORY,
                           PreferredCertificateAuthorityRepo)


def get_project_repository():
    """Returns a singleton Project repository instance."""
    global _PROJECT_REPOSITORY
    return _get_repository(_PROJECT_REPOSITORY, ProjectRepo)


def get_project_ca_repository():
    """Returns a singleton Secret repository instance."""
    global _PROJECT_CA_REPOSITORY
    return _get_repository(_PROJECT_CA_REPOSITORY,
                           ProjectCertificateAuthorityRepo)


def get_project_secret_repository():
    """Returns a singleton ProjectSecret repository instance."""
    global _PROJECT_SECRET_REPOSITORY
    return _get_repository(_PROJECT_SECRET_REPOSITORY, ProjectSecretRepo)


def get_secret_acl_repository():
    """Returns a singleton Secret ACL repository instance."""
    global _SECRET_ACL_REPOSITORY
    return _get_repository(_SECRET_ACL_REPOSITORY, SecretACLRepo)


def get_secret_meta_repository():
    """Returns a singleton Secret meta repository instance."""
    global _SECRET_META_REPOSITORY
    return _get_repository(_SECRET_META_REPOSITORY, SecretStoreMetadatumRepo)


def get_secret_repository():
    """Returns a singleton Secret repository instance."""
    global _SECRET_REPOSITORY
    return _get_repository(_SECRET_REPOSITORY, SecretRepo)


def get_transport_key_repository():
    """Returns a singleton Transport Key repository instance."""
    global _TRANSPORT_KEY_REPOSITORY
    return _get_repository(_TRANSPORT_KEY_REPOSITORY, TransportKeyRepo)


def _get_repository(global_ref, repo_class):
    if not global_ref:
        global_ref = repo_class()
    return global_ref


def _raise_entity_not_found(entity_name, entity_id):
    raise exception.NotFound(u._("No {entity} found with ID {id}").format(
        entity=entity_name,
        id=entity_id))


def _raise_entity_id_not_found(entity_id):
    raise exception.NotFound(u._("Entity ID {entity_id} not "
                                 "found").format(entity_id=entity_id))


def _raise_no_entities_found(entity_name):
    raise exception.NotFound(
        u._("No entities of type {entity_name} found").format(
            entity_name=entity_name))


def _raise_entity_already_exists(entity_name):
    raise exception.Duplicate(
        u._("Entity '{entity_name}' "
            "already exists").format(entity_name=entity_name))
