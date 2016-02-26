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

import inspect
import oslo_context
from oslo_policy import policy

from barbican.common import config

CONF = config.CONF


class RequestContext(oslo_context.context.RequestContext):
    """User security context object

    Stores information about the security context under which the user
    accesses the system, as well as additional request information.
    """

    def __init__(self, roles=None, policy_enforcer=None, project=None,
                 **kwargs):
        # prefer usage of 'project' instead of 'tenant'
        if project:
            kwargs['tenant'] = project
        self.project = project
        self.policy_enforcer = policy_enforcer or policy.Enforcer(CONF)

        # NOTE(edtubill): oslo_context 2.2.0 now has a roles attribute in
        # the RequestContext. This will make sure of backwards compatibility
        # with past oslo_context versions.
        argspec = inspect.getargspec(super(RequestContext, self).__init__)
        if 'roles' in argspec.args:
            kwargs['roles'] = roles
        else:
            self.roles = roles or []

        super(RequestContext, self).__init__(**kwargs)

    def to_dict(self):
        out_dict = super(RequestContext, self).to_dict()
        out_dict['roles'] = self.roles

        # NOTE(jaosorior): For now, the oslo_context library uses 'tenant'
        # instead of project. But in case this changes, this will still issue
        # the dict we expect, which would contain 'project'.
        if out_dict.get('tenant'):
            out_dict['project'] = out_dict['tenant']
            out_dict.pop('tenant')
        return out_dict

    @classmethod
    def from_dict(cls, values):
        return cls(**values)
