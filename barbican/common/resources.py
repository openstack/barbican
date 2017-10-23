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
Shared business logic.
"""
from barbican.common import exception
from barbican.common import utils
from barbican.model import models
from barbican.model import repositories


LOG = utils.getLogger(__name__)

GLOBAL_PREFERRED_PROJECT_ID = "GLOBAL_PREFERRED"


def get_or_create_global_preferred_project():
    return get_or_create_project(GLOBAL_PREFERRED_PROJECT_ID)


def get_or_create_project(project_id):
    """Returns project with matching project_id.

    Creates it if it does not exist.
    :param project_id: The external-to-Barbican ID for this project.
    :param project_repo: Project repository.
    :return: Project model instance
    """
    project_repo = repositories.get_project_repository()
    project = project_repo.find_by_external_project_id(project_id,
                                                       suppress_exception=True)
    if not project:
        LOG.debug('Creating project for %s', project_id)
        project = models.Project()
        project.external_id = project_id
        project.status = models.States.ACTIVE
        try:
            project_repo.create_from(project)
        except exception.ConstraintCheck:
            # catch race condition for when another thread just created one
            project = project_repo.find_by_external_project_id(
                project_id,
                suppress_exception=False)

    return project
