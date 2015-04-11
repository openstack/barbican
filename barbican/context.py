# Copyright  2011-2012 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
from oslo_policy import policy

from barbican.common import utils
from barbican.openstack.common import local


CONF = cfg.CONF


class RequestContext(object):
    """User security context object

    Stores information about the security context under which the user
    accesses the system, as well as additional request information.
    """

    def __init__(self, auth_tok=None, user=None, project=None, roles=None,
                 is_admin=False, read_only=False, show_deleted=False,
                 owner_is_project=True, service_catalog=None,
                 policy_enforcer=None):
        self.auth_tok = auth_tok
        self.user = user
        self.project = project
        self.roles = roles or []
        self.read_only = read_only
        # TODO(jwood): self._show_deleted = show_deleted
        # (mkbhanda) possibly domain could be owner
        # brings us to the key scope question
        self.owner_is_project = owner_is_project
        self.request_id = utils.generate_uuid()
        self.service_catalog = service_catalog
        self.policy_enforcer = policy_enforcer or policy.Enforcer(CONF)
        self.is_admin = is_admin
        # TODO(jwood): Is this needed?
        #        if not self.is_admin:
        #            self.is_admin = self.policy_enforcer.check_is_admin(self)

        if not hasattr(local.store, 'context'):
            self.update_store()

    def to_dict(self):
        # NOTE(ameade): These keys are named to correspond with the default
        # format string for logging the context in openstack common
        return {
            'request_id': self.request_id,

            # NOTE(bcwaldon): openstack-common logging expects 'user'
            'user': self.user,
            'user_id': self.user,

            # NOTE(bcwaldon): openstack-common logging expects 'project'
            'project': self.project,
            'project_id': self.project,
            # TODO(jwood):            'is_admin': self.is_admin,
            # TODO(jwood):            'read_deleted': self.show_deleted,
            'roles': self.roles,
            'auth_token': self.auth_tok,
            'service_catalog': self.service_catalog,
        }

    @classmethod
    def from_dict(cls, values):
        return cls(**values)

    def update_store(self):
        local.store.context = self

    @property
    def owner(self):
        """Return the owner to correlate with key."""
        if self.owner_is_project:
            return self.project
        return self.user

# TODO(jwood):
#    @property
#    def show_deleted(self):
#        """Admins can see deleted by default"""
#        if self._show_deleted or self.is_admin:
#            return True
#        return False
