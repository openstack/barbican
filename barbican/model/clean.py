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

import datetime

# Import and configure logging.
CONF = config.CONF
log.setup(CONF, 'barbican')
LOG = log.getLogger(__name__)

# Default batch size for cleanup operations. Sized so a single batch fits
# comfortably in the InnoDB buffer pool and undo log on a 10 GB pool.
DEFAULT_CLEANUP_BATCH_SIZE = 10000

# Emit a progress log line every Nth batch so operators can monitor long
# cleanup runs without attaching a debugger or querying the database.
_PROGRESS_LOG_EVERY_N_BATCHES = 10


def cleanup_unassociated_projects(
        batch_size=DEFAULT_CLEANUP_BATCH_SIZE):
    """Clean up unassociated projects, in batches.

    Finds projects that have no children entries on any dependent table and
    hard-deletes them. Operates in batches so large deployments with many
    orphaned projects do not exhaust the InnoDB buffer pool.

    :param batch_size: max rows hard-deleted per committed batch.
    :returns: total entries removed from the database.
    """
    LOG.debug("Cleaning up unassociated projects")

    project_children_tables = [models.Order,
                               models.KEKDatum,
                               models.SecretConsumerMetadatum,
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

    def _id_query():
        session = repo.get_session()
        sub_query = session.query(models.Project.id)
        for model in project_children_tables:
            sub_query = sub_query.outerjoin(
                model, models.Project.id == model.project_id)
            sub_query = sub_query.filter(model.id == None)  # noqa
        return sub_query

    total = 0
    batch_no = 0
    while True:
        session = repo.get_session()
        ids = [row[0] for row in _id_query().limit(batch_size).all()]
        if not ids:
            break
        count = session.query(models.Project).filter(
            models.Project.id.in_(ids)).delete(synchronize_session=False)
        session.expunge_all()
        repo.commit()
        total += count
        batch_no += 1
        if batch_no % _PROGRESS_LOG_EVERY_N_BATCHES == 0:
            LOG.debug("[%s] progress: %d batches committed, %d rows so far",
                      models.Project.__name__, batch_no, total)

    LOG.info("Cleaned up %(delete_count)s entries for "
             "%(project_name)s",
             {'delete_count': str(total),
              'project_name': models.Project.__name__})
    return total


def cleanup_parent_with_no_child(parent_model, child_model,
                                 threshold_date=None,
                                 batch_size=DEFAULT_CLEANUP_BATCH_SIZE):
    """Clean up soft-deleted parents that have no live child rows, in batches.

    Before running this function the child table should already be cleaned
    of soft-deleted rows. This function left-outer-joins the parent and
    child tables and finds parent entries that have no foreign-key match
    in the child table, then filters by soft-deletion / threshold_date and
    hard-deletes them.

    Operates in batches of ``batch_size`` rows. Each batch is committed
    independently so InnoDB can release pages and undo log between batches.
    Partial progress is durable: if an exception is raised mid-run, batches
    committed before the failure are NOT rolled back.

    :param parent_model: table class for parent.
    :param child_model: table class for child which restricts parent deletion.
    :param threshold_date: soft deletions older than this date will be
                           removed.
    :param batch_size: max rows hard-deleted per committed batch.
    :returns: total entries removed from the database.
    """
    LOG.debug("Cleaning soft deletes for %(parent_name)s without "
              "a child in %(child_name)s",
              {'parent_name': parent_model.__name__,
               'child_name': child_model.__name__})

    def _id_query():
        session = repo.get_session()
        sub_query = session.query(parent_model.id)
        sub_query = sub_query.outerjoin(child_model)
        sub_query = sub_query.filter(child_model.id == None)  # noqa
        sub_query = sub_query.filter(parent_model.deleted)
        if threshold_date:
            sub_query = sub_query.filter(
                parent_model.deleted_at <= threshold_date)
        return sub_query

    # Each iteration of the batched loop re-issues the id query against a
    # fresh session state. Because each batch hard-deletes the matched
    # rows, the candidate set strictly shrinks across iterations and the
    # loop terminates.
    total = 0
    batch_no = 0
    label = "%s/no-%s" % (parent_model.__name__, child_model.__name__)
    while True:
        session = repo.get_session()
        ids = [row[0] for row in _id_query().limit(batch_size).all()]
        if not ids:
            break
        count = session.query(parent_model).filter(
            parent_model.id.in_(ids)).delete(synchronize_session=False)
        session.expunge_all()
        repo.commit()
        total += count
        batch_no += 1
        if batch_no % _PROGRESS_LOG_EVERY_N_BATCHES == 0:
            LOG.debug("[%s] progress: %d batches committed, %d rows so far",
                      label, batch_no, total)

    LOG.info("Cleaned up %(delete_count)s entries for %(parent_name)s "
             "with no children in %(child_name)s",
             {'delete_count': total,
              'parent_name': parent_model.__name__,
              'child_name': child_model.__name__})
    return total


def cleanup_softdeletes(model, threshold_date=None,
                        batch_size=DEFAULT_CLEANUP_BATCH_SIZE):
    """Remove soft-deleted rows from a table, in batches.

    Selects up to ``batch_size`` soft-deleted ids per iteration, hard-
    deletes them, then commits. Each commit releases InnoDB pages and undo
    log so very large tables (millions of rows) can be cleaned without
    exhausting the buffer pool.

    Partial progress is durable: if an exception is raised mid-run, the
    batches committed before the failure are NOT rolled back. This is a
    deliberate trade-off vs. the previous one-shot semantics; without
    incremental commits the operation is impossible to complete on tables
    that no longer fit in the buffer pool.

    :param model: table class whose soft deletions should be removed.
    :param threshold_date: only rows soft-deleted on or before this date
                           are removed.
    :param batch_size: max rows hard-deleted per committed batch.
    :returns: total rows removed from the database.
    """
    LOG.debug("Cleaning soft deletes: %s", model.__name__)
    total = 0
    batch_no = 0
    label = model.__name__
    while True:
        session = repo.get_session()
        id_query = session.query(model.id).filter_by(deleted=True)
        if threshold_date:
            id_query = id_query.filter(model.deleted_at <= threshold_date)
        ids = [row[0] for row in id_query.limit(batch_size).all()]
        if not ids:
            break
        count = session.query(model).filter(
            model.id.in_(ids)).delete(synchronize_session=False)
        # Detach all ORM objects before commit so that expire_on_commit
        # does not clear their __dict__. Test code and callers holding
        # object references can still read pk attributes from the
        # detached state.
        session.expunge_all()
        repo.commit()
        total += count
        batch_no += 1
        if batch_no % _PROGRESS_LOG_EVERY_N_BATCHES == 0:
            LOG.debug("[%s] progress: %d batches committed, %d rows so far",
                      label, batch_no, total)
    LOG.info("Cleaned up %(delete_count)s entries for %(model_name)s",
             {'delete_count': total,
              'model_name': model.__name__})
    return total


def cleanup_all(threshold_date=None, batch_size=DEFAULT_CLEANUP_BATCH_SIZE):
    """Clean up the main soft deletable resources.

    This function contains an order of calls to
    clean up the soft-deletable resources.

    :param threshold_date: soft deletions older than this date will be removed
    :param batch_size: max rows hard-deleted per committed batch.
    :returns: total number of entries removed from the database
    """
    LOG.debug("Cleaning up soft deletions where deletion date"
              " is older than %s", str(threshold_date))
    total = 0
    total += cleanup_softdeletes(models.TransportKey,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)

    total += cleanup_softdeletes(models.OrderBarbicanMetadatum,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)
    total += cleanup_softdeletes(models.OrderRetryTask,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)
    total += cleanup_softdeletes(models.OrderPluginMetadatum,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)
    total += cleanup_parent_with_no_child(models.Order, models.OrderRetryTask,
                                          threshold_date=threshold_date,
                                          batch_size=batch_size)

    total += cleanup_softdeletes(models.EncryptedDatum,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)
    total += cleanup_softdeletes(models.SecretUserMetadatum,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)
    total += cleanup_softdeletes(models.SecretStoreMetadatum,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)
    total += cleanup_softdeletes(models.ContainerSecret,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)

    total += cleanup_softdeletes(models.SecretConsumerMetadatum,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)
    total += cleanup_parent_with_no_child(models.Secret, models.Order,
                                          threshold_date=threshold_date,
                                          batch_size=batch_size)

    total += cleanup_softdeletes(models.ContainerConsumerMetadatum,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)
    total += cleanup_parent_with_no_child(models.Container, models.Order,
                                          threshold_date=threshold_date,
                                          batch_size=batch_size)
    total += cleanup_softdeletes(models.KEKDatum,
                                 threshold_date=threshold_date,
                                 batch_size=batch_size)

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
    query = session.query(models.Secret)
    query = query.filter(~models.Secret.deleted)
    query = query.filter(
        models.Secret.expiration <= threshold_date
    )
    update_count = query.update(
        {
            models.Secret.deleted: True,
            models.Secret.deleted_at: current_time
        },
        synchronize_session=False)
    return update_count


def _hard_delete_acls_for_soft_deleted_secrets(
        batch_size=DEFAULT_CLEANUP_BATCH_SIZE):
    """Remove ACL entries for secrets that have been soft deleted, in batches.

    Removes entries in :class:`models.SecretACL` and
    :class:`models.SecretACLUser` whose owning secret has been soft deleted.
    Each batch is committed independently so this stays within InnoDB
    resource limits even on projects with very large ACL tables.

    :param batch_size: max rows hard-deleted per committed batch.
    :returns: total ACL rows deleted.
    """
    acl_total = 0
    batch_no = 0

    # SecretACLUser rows: joined-three-table predicate (user -> ACL -> secret).
    while True:
        session = repo.get_session()
        sub_query = session.query(models.SecretACLUser.id)
        sub_query = sub_query.join(models.SecretACL)
        sub_query = sub_query.join(models.Secret)
        sub_query = sub_query.filter(models.Secret.deleted)
        ids = [row[0] for row in sub_query.limit(batch_size).all()]
        if not ids:
            break
        count = session.query(models.SecretACLUser).filter(
            models.SecretACLUser.id.in_(ids)
        ).delete(synchronize_session=False)
        session.expunge_all()
        repo.commit()
        acl_total += count
        batch_no += 1
        if batch_no % _PROGRESS_LOG_EVERY_N_BATCHES == 0:
            LOG.debug("[SecretACLUser] progress: %d batches committed, "
                      "%d rows so far", batch_no, acl_total)

    # SecretACL rows: joined-two-table predicate (ACL -> secret).
    batch_no = 0
    while True:
        session = repo.get_session()
        sub_query = session.query(models.SecretACL.id)
        sub_query = sub_query.join(models.Secret)
        sub_query = sub_query.filter(models.Secret.deleted)
        ids = [row[0] for row in sub_query.limit(batch_size).all()]
        if not ids:
            break
        count = session.query(models.SecretACL).filter(
            models.SecretACL.id.in_(ids)
        ).delete(synchronize_session=False)
        session.expunge_all()
        repo.commit()
        acl_total += count
        batch_no += 1
        if batch_no % _PROGRESS_LOG_EVERY_N_BATCHES == 0:
            LOG.debug("[SecretACL] progress: %d batches committed, "
                      "%d rows so far", batch_no, acl_total)

    return acl_total


def _soft_delete_expired_secret_children(
        threshold_date, batch_size=DEFAULT_CLEANUP_BATCH_SIZE):
    """Soft-delete the children tables of expired secrets, in batches.

    Soft-deletes the children tables and hard-deletes the ACL children
    tables of the expired secrets. Processes rows in batches and commits
    after each batch to avoid unbatched SELECT/UPDATE on large tables.

    The id query filters with ``~table.deleted`` so each iteration only
    picks up rows not yet processed; this guarantees loop termination
    because every successful batch monotonically shrinks the candidate set.

    :param threshold_date: threshold date for secret expiration.
    :param batch_size: max rows updated per committed batch.
    :returns: pair (number of soft-deleted children, number of deleted ACLs).
    """
    current_time = timeutils.utcnow()

    secret_children = [models.SecretStoreMetadatum,
                       models.SecretUserMetadatum,
                       models.EncryptedDatum,
                       models.ContainerSecret]
    children_names = map(lambda child: child.__name__, secret_children)
    LOG.debug("Children tables for Secret table being checked: %s",
              str(children_names))
    update_count = 0

    for table in secret_children:
        batch_no = 0
        label = table.__name__
        while True:
            session = repo.get_session()
            id_query = session.query(table.id)
            id_query = id_query.join(models.Secret)
            id_query = id_query.filter(
                models.Secret.expiration <= threshold_date
            )
            id_query = id_query.filter(~table.deleted)
            ids = [row[0] for row in id_query.limit(batch_size).all()]
            if not ids:
                break
            count = session.query(table).filter(table.id.in_(ids)).update(
                {
                    table.deleted: True,
                    table.deleted_at: current_time
                },
                synchronize_session=False)
            session.expunge_all()
            repo.commit()
            update_count += count
            batch_no += 1
            if batch_no % _PROGRESS_LOG_EVERY_N_BATCHES == 0:
                LOG.debug("[%s] progress: %d batches committed, "
                          "%d rows so far", label, batch_no, update_count)

    acl_total = _hard_delete_acls_for_soft_deleted_secrets(
        batch_size=batch_size)
    return update_count, acl_total


def soft_delete_expired_secrets(threshold_date,
                                batch_size=DEFAULT_CLEANUP_BATCH_SIZE):
    """Soft deletes secrets that are past expiration date.

    The expired secrets and its children are marked for deletion.
    ACLs are soft deleted and then purged from the database.

    :param threshold_date: secrets that have expired past this date
                           will be soft deleted
    :param batch_size: max rows processed per committed batch.
    :returns: the sum of soft deleted entries and hard deleted acl entries
    """
    # Note: sqllite does not support multiple table updates so
    # several db updates are used instead
    LOG.debug('Soft deleting expired secrets older than: %s',
              str(threshold_date))
    update_count = _soft_delete_expired_secrets(threshold_date)

    children_count, acl_total = _soft_delete_expired_secret_children(
        threshold_date, batch_size=batch_size)
    update_count += children_count
    LOG.info("Soft deleted %(update_count)s entries due to secret "
             "expiration and %(acl_total)s secret acl entries "
             "were removed from the database",
             {'update_count': update_count,
              'acl_total': acl_total})
    return update_count + acl_total


def clean_command(sql_url, min_num_days, do_clean_unassociated_projects,
                  do_soft_delete_expired_secrets, verbose, log_file,
                  batch_size=DEFAULT_CLEANUP_BATCH_SIZE):
    """Clean command to clean up the database.

    :param sql_url: sql connection string to connect to a database
    :param min_num_days: clean up soft deletions older than this date
    :param do_clean_unassociated_projects: If True, clean up
                                           unassociated projects
    :param do_soft_delete_expired_secrets: If True, soft delete secrets
                                           that have expired
    :param verbose: If True, log and print more information
    :param log_file: If set, override the log_file configured
    :param batch_size: max rows hard-deleted per committed batch across all
                       cleanup operations. Defaults to
                       DEFAULT_CLEANUP_BATCH_SIZE.
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
            CONF.set_override('connection', sql_url, 'database')
        repo.setup_database_engine_and_factory()

        if do_clean_unassociated_projects:
            cleanup_total += cleanup_unassociated_projects(
                batch_size=batch_size)

        if do_soft_delete_expired_secrets:
            cleanup_total += soft_delete_expired_secrets(
                threshold_date=current_time,
                batch_size=batch_size)

        threshold_date = None
        if min_num_days >= 0:
            threshold_date = current_time - datetime.timedelta(
                days=min_num_days)
        else:
            threshold_date = current_time
        cleanup_total += cleanup_all(threshold_date=threshold_date,
                                     batch_size=batch_size)
        repo.commit()

    except Exception:
        # The batched cleanup helpers commit incrementally, so on failure
        # any batches already committed are durably persisted; only the
        # in-flight batch is rolled back here. ``cleanup_total`` therefore
        # reflects the rows that ARE permanently deleted up to the point
        # of failure -- DO NOT reset it to 0, that would mislead operators
        # during incident response.
        LOG.exception('Failed to clean up soft deletions in database. '
                      '%s entries were committed before the failure.',
                      cleanup_total)
        repo.rollback()
        raise
    finally:
        stop_watch.stop()
        elapsed_time = stop_watch.elapsed()
        if verbose:
            CONF.clear_override('debug')

        if log_file:
            CONF.clear_override('log_file')
        repo.clear()

        if sql_url:
            CONF.clear_override('connection', 'database')

        log.setup(CONF, 'barbican')  # reset the overrides

        LOG.info("Cleaning of database affected %s entries", cleanup_total)
        LOG.info('DB clean up finished in %s seconds', elapsed_time)
