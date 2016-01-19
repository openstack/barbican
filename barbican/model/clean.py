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

# Import and configure logging.
CONF = config.CONF
log.setup(CONF, 'barbican')
LOG = log.getLogger(__name__)


def _exception_is_successful_exit(thrown_exception):
    return (isinstance(thrown_exception, SystemExit) and
            (thrown_exception.code is None or thrown_exception.code == 0))


def cleanup_parent_with_no_child(parent_model, child_model):
    """Clean up soft deletions in parent that do not have references in child

    Before running this function, the child table should be cleaned of
    soft deletions. This function left outer joins the parent and child
    tables and finds the parent entries that do not have a foreign key
    reference in the child table. Then the results are filtered by soft
    deletions and are cleaned up.

    :param parent_model: table class for parent
    :param child_model: table class for child which restricts parent deletion
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
    delete_count = query.delete(synchronize_session='fetch')
    LOG.info("Cleaned up %s entries for %s with no children in %s",
             delete_count, parent_model.__name__, child_model.__name__)
    return delete_count


def cleanup_softdeletes(model):
    """Remove soft deletions from a table.

    :param model: table class to remove soft deletions
    :returns: total number of entries removed from the database
    """
    LOG.debug("Cleaning soft deletes: %s", model.__name__)
    session = repo.get_session()
    query = session.query(model)
    query = query.filter_by(deleted=True)
    delete_count = query.delete()
    LOG.info("Cleaned up %s entries for %s", delete_count,
             model.__name__)
    return delete_count


def cleanup_all():
    """Clean up the main soft deletable resources.

    This function contains an order of calls to
    clean up the soft-deletable resources.

    :returns: total number of entries removed from the database
    """
    total = 0
    total += cleanup_softdeletes(models.TransportKey)

    total += cleanup_softdeletes(models.OrderBarbicanMetadatum)
    total += cleanup_softdeletes(models.OrderRetryTask)
    total += cleanup_softdeletes(models.OrderPluginMetadatum)
    total += cleanup_parent_with_no_child(models.Order, models.OrderRetryTask)

    total += cleanup_softdeletes(models.EncryptedDatum)
    total += cleanup_softdeletes(models.SecretStoreMetadatum)
    total += cleanup_softdeletes(models.ContainerSecret)

    total += cleanup_parent_with_no_child(models.Secret, models.Order)

    total += cleanup_softdeletes(models.ContainerConsumerMetadatum)
    total += cleanup_parent_with_no_child(models.Container, models.Order)
    total += cleanup_softdeletes(models.KEKDatum)

    # TODO(edtubill) Clean up projects that were soft deleted by
    # the keystone listener

    LOG.info("Cleaning of database resulted in removing %s entries", total)
    return total


def clean_command(sql_url=None):
    """Clean command to clean up the database.

    :param sql_url: sql connection string to connect to a database
    """
    # TODO(edtubill) Make unit test for this method

    start_messg = "Cleaning up soft deletions in the barbican database"
    LOG.info(start_messg)

    stop_watch = timeutils.StopWatch()
    stop_watch.start()
    try:
        if sql_url:
            CONF.set_override('sql_connection', sql_url)
        repo.setup_database_engine_and_factory()
        cleanup_all()
        repo.commit()

    except Exception as ex:
        if not _exception_is_successful_exit(ex):
            LOG.exception('Failed to clean up soft deletions in database.')
            repo.rollback()
            raise ex
    finally:
        stop_watch.stop()
        elapsed_time = stop_watch.elapsed()
        finish_messg = 'DB clean up finished in {0} seconds'.format(
            elapsed_time)

        LOG.info(finish_messg)
        repo.clear()

        if sql_url:
            CONF.clear_override('sql_connection')
