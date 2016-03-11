# Copyright (c) 2016 IBM
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

from barbican.common import config
from barbican.model import models
from barbican.model import repositories as repo
from oslo_log import log
from oslo_utils import timeutils

from sqlalchemy import sql as sa_sql

import datetime

# Import and configure logging.
CONF = config.CONF
log.setup(CONF, 'barbican')
LOG = log.getLogger(__name__)


def cleanup_unassociated_projects():
    """Clean up unassociated projects.

    This looks for projects that have no children entries on the dependent
    tables and removes them.
    """
    LOG.debug("Cleaning up unassociated projects")
    session = repo.get_session()
    project_children_tables = [models.Order,
                               models.KEKDatum,
                               models.Secret,
                               models.ContainerConsumerMetadatum,
                               models.Container,
                               models.PreferredCertificateAuthority,
                               models.CertificateAuthority,
                               models.ProjectCertificateAuthority,
                               models.ProjectQuotas]
    children_names = map(lambda child: child.__name__, project_children_tables)
    LOG.debug("Children tables for Project table being checked: %s",
              str(children_names))
    sub_query = session.query(models.Project.id)
    for model in project_children_tables:
        sub_query = sub_query.outerjoin(model,
                                        models.Project.id == model.project_id)
        sub_query = sub_query.filter(model.id == None)  # nopep8
    sub_query = sub_query.subquery()
    sub_query = sa_sql.select([sub_query])
    query = session.query(models.Project)
    query = query.filter(models.Project.id.in_(sub_query))
    delete_count = query.delete(synchronize_session='fetch')
    LOG.info("Cleaned up %s entries for %s", str(delete_count),
             models.Project.__name__)
    return delete_count


def cleanup_parent_with_no_child(parent_model, child_model,
                                 threshold_date=None):
    """Clean up soft deletions in parent that do not have references in child.

    Before running this function, the child table should be cleaned of
    soft deletions. This function left outer joins the parent and child
    tables and finds the parent entries that do not have a foreign key
    reference in the child table. Then the results are filtered by soft
    deletions and are cleaned up.

    :param parent_model: table class for parent
    :param child_model: table class for child which restricts parent deletion
    :param threshold_date: soft deletions older than this date will be removed
    :returns: total number of entries removed from database
    """
    LOG.debug("Cleaning soft deletes for %s without a child in %s",
              parent_model.__name__,
              child_model.__name__)
    session = repo.get_session()
    sub_query = session.query(parent_model.id)
    sub_query = sub_query.outerjoin(child_model)
    sub_query = sub_query.filter(child_model.id == None)  # nopep8
    sub_query = sub_query.subquery()
    sub_query = sa_sql.select([sub_query])
    query = session.query(parent_model)
    query = query.filter(parent_model.id.in_(sub_query))
    query = query.filter(parent_model.deleted)
    if threshold_date:
        query = query.filter(parent_model.deleted_at <= threshold_date)
    delete_count = query.delete(synchronize_session='fetch')
    LOG.info("Cleaned up %s entries for %s with no children in %s",
             delete_count, parent_model.__name__, child_model.__name__)
    return delete_count


def cleanup_softdeletes(model, threshold_date=None):
    """Remove soft deletions from a table.

    :param model: table class to remove soft deletions
    :param threshold_date: soft deletions older than this date will be removed
    :returns: total number of entries removed from the database
    """
    LOG.debug("Cleaning soft deletes: %s", model.__name__)
    session = repo.get_session()
    query = session.query(model)
    query = query.filter_by(deleted=True)
    if threshold_date:
        query = query.filter(model.deleted_at <= threshold_date)
    delete_count = query.delete()
    LOG.info("Cleaned up %s entries for %s", delete_count,
             model.__name__)
    return delete_count


def cleanup_all(threshold_date=None):
    """Clean up the main soft deletable resources.

    This function contains an order of calls to
    clean up the soft-deletable resources.

    :param threshold_date: soft deletions older than this date will be removed
    :returns: total number of entries removed from the database
    """
    LOG.debug("Cleaning up soft deletions where deletion date"
              " is older than %s", str(threshold_date))
    total = 0
    total += cleanup_softdeletes(models.TransportKey,
                                 threshold_date=threshold_date)

    total += cleanup_softdeletes(models.OrderBarbicanMetadatum,
                                 threshold_date=threshold_date)
    total += cleanup_softdeletes(models.OrderRetryTask,
                                 threshold_date=threshold_date)
    total += cleanup_softdeletes(models.OrderPluginMetadatum,
                                 threshold_date=threshold_date)
    total += cleanup_parent_with_no_child(models.Order, models.OrderRetryTask,
                                          threshold_date=threshold_date)

    total += cleanup_softdeletes(models.EncryptedDatum,
                                 threshold_date=threshold_date)
    total += cleanup_softdeletes(models.SecretUserMetadatum,
                                 threshold_date=threshold_date)
    total += cleanup_softdeletes(models.SecretStoreMetadatum,
                                 threshold_date=threshold_date)
    total += cleanup_softdeletes(models.ContainerSecret,
                                 threshold_date=threshold_date)

    total += cleanup_parent_with_no_child(models.Secret, models.Order,
                                          threshold_date=threshold_date)

    total += cleanup_softdeletes(models.ContainerConsumerMetadatum,
                                 threshold_date=threshold_date)
    total += cleanup_parent_with_no_child(models.Container, models.Order,
                                          threshold_date=threshold_date)
    total += cleanup_softdeletes(models.KEKDatum,
                                 threshold_date=threshold_date)

    # TODO(edtubill) Clean up projects that were soft deleted by
    # the keystone listener

    LOG.info("Cleaned up %s soft deleted entries", total)
    return total


def _soft_delete_expired_secrets(threshold_date):
    """Soft delete expired secrets.

    :param threshold_date: secrets that have expired past this date
                           will be soft deleted
    :returns: total number of secrets that were soft deleted
    """
    current_time = timeutils.utcnow()
    session = repo.get_session()
    query = session.query(models.Secret.id)
    query = query.filter(~models.Secret.deleted)
    query = query.filter(
        models.Secret.expiration <= threshold_date
    )
    update_count = query.update(
        {
            models.Secret.deleted: True,
            models.Secret.deleted_at: current_time
        },
        synchronize_session='fetch')
    return update_count


def _hard_delete_acls_for_soft_deleted_secrets():
    """Remove acl entries for secrets that have been soft deleted.

    Removes entries in SecretACL and SecretACLUser which are for secrets
    that have been soft deleted.
    """
    session = repo.get_session()
    acl_user_sub_query = session.query(models.SecretACLUser.id)
    acl_user_sub_query = acl_user_sub_query.join(models.SecretACL)
    acl_user_sub_query = acl_user_sub_query.join(models.Secret)
    acl_user_sub_query = acl_user_sub_query.filter(models.Secret.deleted)
    acl_user_sub_query = acl_user_sub_query.subquery()
    acl_user_sub_query = sa_sql.select([acl_user_sub_query])

    acl_user_query = session.query(models.SecretACLUser)
    acl_user_query = acl_user_query.filter(
        models.SecretACLUser.id.in_(acl_user_sub_query))
    acl_total = acl_user_query.delete(synchronize_session='fetch')

    acl_sub_query = session.query(models.SecretACL.id)
    acl_sub_query = acl_sub_query.join(models.Secret)
    acl_sub_query = acl_sub_query.filter(models.Secret.deleted)
    acl_sub_query = acl_sub_query.subquery()
    acl_sub_query = sa_sql.select([acl_sub_query])

    acl_query = session.query(models.SecretACL)
    acl_query = acl_query.filter(
        models.SecretACL.id.in_(acl_sub_query))
    acl_total += acl_query.delete(synchronize_session='fetch')
    return acl_total


def _soft_delete_expired_secret_children(threshold_date):
    """Soft delete the children tables of expired secrets.

    Soft deletes the children tables  and hard deletes the ACL children
    tables of the expired secrets.
    :param threshold_date: threshold date for secret expiration
    :returns: returns a pair for number of soft delete children and deleted
              ACLs
    """
    current_time = timeutils.utcnow()

    secret_children = [models.SecretStoreMetadatum,
                       models.SecretUserMetadatum,
                       models.EncryptedDatum,
                       models.ContainerSecret]
    children_names = map(lambda child: child.__name__, secret_children)
    LOG.debug("Children tables for Secret table being checked: %s",
              str(children_names))
    session = repo.get_session()
    update_count = 0

    for table in secret_children:
        # Go through children and soft delete them
        sub_query = session.query(table.id)
        sub_query = sub_query.join(models.Secret)
        sub_query = sub_query.filter(
            models.Secret.expiration <= threshold_date
        )
        sub_query = sub_query.subquery()
        sub_query = sa_sql.select([sub_query])
        query = session.query(table)
        query = query.filter(table.id.in_(sub_query))
        current_update_count = query.update(
            {
                table.deleted: True,
                table.deleted_at: current_time
            },
            synchronize_session='fetch')
        update_count += current_update_count

    session.flush()
    acl_total = _hard_delete_acls_for_soft_deleted_secrets()
    return update_count, acl_total


def soft_delete_expired_secrets(threshold_date):
    """Soft deletes secrets that are past expiration date.

    The expired secrets and its children are marked for deletion.
    ACLs are soft deleted and then purged from the database.

    :param threshold_date: secrets that have expired past this date
                           will be soft deleted
    :returns: the sum of soft deleted entries and hard deleted acl entries
    """
    # Note: sqllite does not support multiple table updates so
    # several db updates are used instead
    LOG.debug('Soft deleting expired secrets older than: %s',
              str(threshold_date))
    update_count = _soft_delete_expired_secrets(threshold_date)

    children_count, acl_total = _soft_delete_expired_secret_children(
        threshold_date)
    update_count += children_count
    LOG.info("Soft deleted %s entries due to secret expiration"
             " and %s secret acl entries were removed from the database",
             update_count, acl_total)
    return update_count + acl_total


def clean_command(sql_url, min_num_days, do_clean_unassociated_projects,
                  do_soft_delete_expired_secrets, verbose, log_file):
    """Clean command to clean up the database.

    :param sql_url: sql connection string to connect to a database
    :param min_num_days: clean up soft deletions older than this date
    :param do_clean_unassociated_projects: If True, clean up
                                           unassociated projects
    :param do_soft_delete_expired_secrets: If True, soft delete secrets
                                           that have expired
    :param verbose: If True, log and print more information
    :param log_file: If set, override the log_file configured
    """
    if verbose:
        # The verbose flag prints out log events to the screen, otherwise
        # the log events will only go to the log file
        CONF.set_override('debug', True)

    if log_file:
        CONF.set_override('log_file', log_file)

    LOG.info("Cleaning up soft deletions in the barbican database")
    log.setup(CONF, 'barbican')

    cleanup_total = 0
    current_time = timeutils.utcnow()
    stop_watch = timeutils.StopWatch()
    stop_watch.start()
    try:
        if sql_url:
            CONF.set_override('sql_connection', sql_url)
        repo.setup_database_engine_and_factory()

        if do_clean_unassociated_projects:
            cleanup_total += cleanup_unassociated_projects()

        if do_soft_delete_expired_secrets:
            cleanup_total += soft_delete_expired_secrets(
                threshold_date=current_time)

        threshold_date = None
        if min_num_days >= 0:
            threshold_date = current_time - datetime.timedelta(
                days=min_num_days)
        else:
            threshold_date = current_time
        cleanup_total += cleanup_all(threshold_date=threshold_date)
        repo.commit()

    except Exception as ex:
        LOG.exception('Failed to clean up soft deletions in database.')
        repo.rollback()
        cleanup_total = 0  # rollback happened, no entries affected
        raise ex
    finally:
        stop_watch.stop()
        elapsed_time = stop_watch.elapsed()
        if verbose:
            CONF.clear_override('debug')

        if log_file:
            CONF.clear_override('log_file')
        repo.clear()

        if sql_url:
            CONF.clear_override('sql_connection')

        log.setup(CONF, 'barbican')  # reset the overrides

        LOG.info("Cleaning of database affected %s entries",
                 cleanup_total)
        LOG.info('DB clean up finished in %s seconds', elapsed_time)
