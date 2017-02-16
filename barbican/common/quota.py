# Copyright (c) 2015 Cisco Systems
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
from barbican.common import exception
from barbican.common import hrefs
from barbican.common import resources as res
from barbican.model import repositories as repo


# All negative values will be treated as unlimited
UNLIMITED_VALUE = -1
DISABLED_VALUE = 0

CONF = config.CONF


class QuotaDriver(object):
    """Driver to enforce quotas and obtain quota information."""

    def __init__(self):
        self.repo = repo.get_project_quotas_repository()

    def _get_resources(self):
        """List of resources that can be constrained by a quota"""
        return ['secrets', 'orders', 'containers', 'consumers', 'cas']

    def _get_defaults(self):
        """Return list of default quotas"""
        quotas = {
            'secrets': CONF.quotas.quota_secrets,
            'orders': CONF.quotas.quota_orders,
            'containers': CONF.quotas.quota_containers,
            'consumers': CONF.quotas.quota_consumers,
            'cas': CONF.quotas.quota_cas
        }
        return quotas

    def _extract_project_quotas(self, project_quotas_model):
        """Convert project quotas model to Python dict

        :param project_quotas_model: Model containing quota information
        :return: Python dict containing quota information
        """
        resp_quotas = {}
        for resource in self._get_resources():
            resp_quotas[resource] = getattr(project_quotas_model, resource)
        return resp_quotas

    def _compute_effective_quotas(self, configured_quotas):
        """Merge configured and default quota information

        When a quota value is not set, use the default value
        :param configured_quotas: configured quota values
        :return: effective quotas
        """
        default_quotas = self._get_defaults()
        resp_quotas = dict(configured_quotas)
        for resource, quota in resp_quotas.items():
            if quota is None:
                resp_quotas[resource] = default_quotas[resource]
        return resp_quotas

    def get_effective_quotas(self, external_project_id):
        """Collect and return the effective quotas for a project

        :param external_project_id: external ID of current project
        :return: dict with effective quotas
        """
        try:
            retrieved_project_quotas = self.repo.get_by_external_project_id(
                external_project_id)
        except exception.NotFound:
            resp_quotas = self._get_defaults()
        else:
            resp_quotas = self._compute_effective_quotas(
                self._extract_project_quotas(retrieved_project_quotas))
        return resp_quotas

    def is_unlimited_value(self, v):
        """A helper method to check for unlimited value."""
        return v <= UNLIMITED_VALUE

    def is_disabled_value(self, v):
        """A helper method to check for disabled value."""
        return v == DISABLED_VALUE

    def set_project_quotas(self, external_project_id, parsed_project_quotas):
        """Create a new database entry, or update existing one

        :param external_project_id: ID of project whose quotas are to be set
        :param parsed_project_quotas: quota values to save in database
        :return: None
        """
        project = res.get_or_create_project(external_project_id)
        self.repo.create_or_update_by_project_id(project.id,
                                                 parsed_project_quotas)
        # commit to DB to avoid async issues if the enforcer is called from
        # another thread
        repo.commit()

    def get_project_quotas(self, external_project_id):
        """Retrieve configured quota information from database

        :param external_project_id: ID of project for whose values are wanted
        :return: the values
        """
        try:
            retrieved_project_quotas = self.repo.get_by_external_project_id(
                external_project_id)
        except exception.NotFound:
            return None
        resp_quotas = self._extract_project_quotas(retrieved_project_quotas)
        resp = {'project_quotas': resp_quotas}
        return resp

    def get_project_quotas_list(self, offset_arg=None, limit_arg=None):
        """Return a dict and list of all configured quota information

        :return: a dict and list of a page of quota config info
        """
        retrieved_project_quotas, offset, limit, total =\
            self.repo.get_by_create_date(offset_arg=offset_arg,
                                         limit_arg=limit_arg,
                                         suppress_exception=True)
        resp_quotas = []
        for quotas in retrieved_project_quotas:
            list_item = {'project_id': quotas.project.external_id,
                         'project_quotas':
                             self._extract_project_quotas(quotas)}
            resp_quotas.append(list_item)
        resp = {'project_quotas': resp_quotas}
        resp_overall = hrefs.add_nav_hrefs(
            'project_quotas', offset, limit, total, resp)
        resp_overall.update({'total': total})
        return resp_overall

    def delete_project_quotas(self, external_project_id):
        """Remove configured quota information from database

        :param external_project_id: ID of project whose quotas will be deleted
        :raises NotFound: if project has no configured values
        :return: None
        """
        self.repo.delete_by_external_project_id(external_project_id)

    def get_quotas(self, external_project_id):
        """Get the effective quotas for a project

        Effective quotas are based on both configured and default values
        :param external_project_id: ID of project for which to get quotas
        :return: dict of effective quota values
        """
        resp_quotas = self.get_effective_quotas(external_project_id)
        resp = {'quotas': resp_quotas}
        return resp


class QuotaEnforcer(object):
    """Checks quotas limits and current resource usage levels"""
    def __init__(self, resource_type, resource_repo):
        self.quota_driver = QuotaDriver()
        self.resource_type = resource_type
        self.resource_repo = resource_repo

    def enforce(self, project):
        """Enforce the quota limit for the resource

        :param project: the project object corresponding to the sender
        :raises QuotaReached: exception raised if quota forbids request
        :return: None
        """
        quotas = self.quota_driver.get_effective_quotas(project.external_id)
        quota = quotas[self.resource_type]

        reached = False
        count = 0
        if self.quota_driver.is_unlimited_value(quota):
            pass
        elif self.quota_driver.is_disabled_value(quota):
            reached = True
        else:
            count = self.resource_repo.get_count(project.id)
            if count >= quota:
                reached = True

        if reached:
            raise exception.QuotaReached(
                external_project_id=project.external_id,
                resource_type=self.resource_type,
                quota=quota)
