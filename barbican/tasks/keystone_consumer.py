# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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
Server-side Keystone notification payload processing logic.
"""

from barbican.common import utils
from barbican import i18n as u
from barbican.model import repositories as rep
from barbican.tasks import resources


LOG = utils.getLogger(__name__)


class KeystoneEventConsumer(resources.BaseTask):
    """Event consumer listening for notifications sent by Keystone deployment.

    Currently this processes only Keystone project delete event.
    """

    def get_name(self):
        return u._('Project cleanup via Keystone notifications')

    def __init__(self, db_start=rep.start, db_commit=rep.commit,
                 db_rollback=rep.rollback, db_clear=rep.clear):
        LOG.debug('Creating KeystoneEventConsumer task processor')

        self.db_start = db_start
        self.db_commit = db_commit
        self.db_rollback = db_rollback
        self.db_clear = db_clear

    def process(self, *args, **kwargs):
        try:
            self.db_start()
            super(KeystoneEventConsumer, self).process(*args, **kwargs)
            self.db_commit()
        except Exception as e:
            """Exceptions that reach here needs to revert the entire
            transaction.
            No need to log error message as its already done earlier.
            """
            self.db_rollback()
            raise e
        finally:
            self.db_clear()

    def retrieve_entity(self, project_id, resource_type=None,
                        operation_type=None):
        project_repo = rep.get_project_repository()
        return project_repo.find_by_external_project_id(
            external_project_id=project_id,
            suppress_exception=True)

    def handle_processing(self, barbican_project, *args, **kwargs):
        self.handle_cleanup(barbican_project, *args, **kwargs)

    def handle_error(self, project, status, message, exception,
                     project_id=None, resource_type=None, operation_type=None):
        LOG.error(
            u._LE(
                'Error processing Keystone event, project_id=%(project_id)s, '
                'event resource=%(resource)s, event operation=%(operation)s, '
                'status=%(status)s, error message=%(message)s'
            ),
            {
                'project_id': project.project_id,
                'resource': resource_type,
                'operation': operation_type,
                'status': status,
                'message': message
            }
        )

    def handle_success(self, project, result, project_id=None,
                       resource_type=None, operation_type=None):
        # Note: The processing 'result' argument can be ignored as 'result'
        # only pertains to long-running tasks. See the documentation for
        # BaseTask for more details.
        LOG.info(
            u._LI(
                'Successfully handled Keystone event, '
                'project_id=%(project_id)s, event resource=%(resource)s, '
                'event operation=%(operation)s'
            ),
            {
                'project_id': project_id,
                'resource': resource_type,
                'operation': operation_type
            }
        )

    def handle_cleanup(self, project, project_id=None, resource_type=None,
                       operation_type=None):
        """Cleans up Barbican resources needed for Keystone project delete.

        :param project: Barbican project entity which is retrieved by project
        id available in Keystone notification.
        :param project_id: project identifier as present in Keystone
        notification.
        :param resource_type: type of resource updated as part of Keystone
        notification e.g. Keystone project, domain, user etc.
        :param operation_type: type of operation (created, updated, deleted
        etc.) performed on Keystone resource.
        """
        if project is None:
            LOG.info(u._LI('No action is needed as there are no Barbican '
                           'resources present for Keystone '
                           'project_id=%s'), project_id)
            return

        # barbican entities use projects table 'id' field as foreign key.
        # Delete apis are using that id to lookup related entities and not
        # keystone project id which requires additional project table join.
        project_id = project.id

        rep.delete_all_project_resources(project_id)

        # reached here means there is no error so log the successful
        # cleanup log entry.
        LOG.info(u._LI('Successfully completed Barbican resources cleanup for '
                       'Keystone project_id=%s'), project_id)
