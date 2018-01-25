# Copyright (c) 2018 Red Hat, Inc.
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
from barbican.model import repositories as repo
from oslo_log import log

# Import and configure logging.
CONF = config.CONF
log.setup(CONF, 'barbican')
LOG = log.getLogger(__name__)


def sync_secret_stores(sql_url, verbose, log_file):
    """Command to sync secret stores table with config .

    :param sql_url: sql connection string to connect to a database
    :param verbose: If True, log and print more information
    :param log_file: If set, override the log_file configured
    """
    if verbose:
        # The verbose flag prints out log events to the screen, otherwise
        # the log events will only go to the log file
        CONF.set_override('debug', True)

    if log_file:
        CONF.set_override('log_file', log_file)

    LOG.info("Syncing the secret_stores table with barbican.conf")
    log.setup(CONF, 'barbican')

    try:
        if sql_url:
            CONF.set_override('sql_connection', sql_url)
        repo.setup_database_engine_and_factory(
            initialize_secret_stores=True)
        repo.commit()
    except Exception as ex:
        LOG.exception('Failed to sync secret_stores table.')
        repo.rollback()
        raise ex
    finally:
        if verbose:
            CONF.clear_override('debug')

        if log_file:
            CONF.clear_override('log_file')
        repo.clear()

        if sql_url:
            CONF.clear_override('sql_connection')

        log.setup(CONF, 'barbican')  # reset the overrides
