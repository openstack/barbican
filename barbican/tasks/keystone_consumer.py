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
from barbican.model import repositories as rep
from barbican.openstack.common import gettextutils as u
from barbican.tasks import resources


LOG = utils.getLogger(__name__)


class KeystoneEventConsumer(resources.BaseTask):
    """Event consumer listening for notifications sent by Keystone deployment.

    Currently this processes only Keystone project delete event.
    """

    def get_name(self):
        return u._('Project cleanup via Keystone notifications')

    def __init__(self, project_repo=None, order_repo=None,
                 secret_repo=None, project_secret_repo=None,
                 datum_repo=None, kek_repo=None, secret_meta_repo=None,
                 container_repo=None):
        LOG.debug('Creating KeystoneEventConsumer task processor')
        self.repos = rep.Repositories(project_repo=project_repo,
                                      order_repo=order_repo,
                                      secret_repo=secret_repo,
                                      project_secret_repo=project_secret_repo,
                                      datum_repo=datum_repo,
                                      kek_repo=kek_repo,
                                      secret_meta_repo=secret_meta_repo,
                                      container_repo=container_repo)

    def process(self, *args, **kwargs):
        try:
            rep.start()
            super(KeystoneEventConsumer, self).process(*args, **kwargs)
            rep.commit()
        except Exception as e:
            """Exceptions that reach here needs to revert the entire
            transaction.
            No need to log error message as its already done earlier.
            """
            rep.rollback()
            raise e
        finally:
            rep.clear()

    def retrieve_entity(self, project_id, resource_type=None,
                        operation_type=None):
        project_repo = self.repos.project_repo
        return project_repo.find_by_keystone_id(keystone_id=project_id,
                                                suppress_exception=True)

    def handle_processing(self, barbican_project, *args, **kwargs):
        self.handle_cleanup(barbican_project, *args, **kwargs)

    def handle_error(self, project, status, message, exception,
                     project_id=None, resource_type=None, operation_type=None):
        LOG.error('Error processing Keystone event, project_id={0}, event '
                  'resource={1}, event operation={2}, status={3}, error '
                  'message={4}'.format(project.project_id, resource_type,
                                       operation_type, status, message))

    def handle_success(self, project, project_id=None, resource_type=None,
                       operation_type=None):
        LOG.info('Successfully handled Keystone event, project_id={0}, event '
                 'resource={1}, event operation={2}'.format(project_id,
                                                            resource_type,
                                                            operation_type))

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
            LOG.info('No action is needed as there are no Barbican resources '
                     'present for Keystone project_id={0}'.format(project_id))
            return

        # barbican entities use projects table 'id' field as foreign key.
        # Delete apis are using that id to lookup related entities and not
        # keystone project id which requires additional project table join.
        project_id = project.id

        rep.delete_all_project_resources(project_id, self.repos)

        # reached here means there is no error so log the successful
        # cleanup log entry.
        LOG.info('Successfully completed Barbican resources cleanup for '
                 'Keystone project_id={0}'.format(project_id))
