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
from barbican.common import utils
from barbican.model import models


LOG = utils.getLogger(__name__)


def get_or_create_tenant(keystone_id, tenant_repo):
    """Returns tenant with matching keystone_id.

    Creates it if it does not exist.
    :param keystone_id: The external-to-Barbican ID for this tenant.
    :param tenant_repo: Tenant repository.
    :return: Tenant model instance
    """
    tenant = tenant_repo.find_by_keystone_id(keystone_id,
                                             suppress_exception=True)
    if not tenant:
        LOG.debug('Creating tenant for %s', keystone_id)
        tenant = models.Tenant()
        tenant.keystone_id = keystone_id
        tenant.status = models.States.ACTIVE
        tenant_repo.create_from(tenant)
    return tenant
