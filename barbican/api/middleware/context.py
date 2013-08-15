# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011-2012 OpenStack LLC.
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

import json
import webob.exc

from oslo.config import cfg

from barbican.api import middleware as mw
from barbican.common import utils
import barbican.context
from barbican.openstack.common import gettextutils as u
from barbican.openstack.common import policy

LOG = utils.getLogger(__name__)

# TODO(jwood) Need to figure out why config is ignored in this module.
context_opts = [
    cfg.BoolOpt('owner_is_tenant', default=True,
                help=u._('When true, this option sets the owner of an image '
                         'to be the tenant. Otherwise, the owner of the '
                         ' image will be the authenticated user issuing the '
                         'request.')),
    cfg.StrOpt('admin_role', default='admin',
               help=u._('Role used to identify an authenticated user as '
                        'administrator.')),
    cfg.BoolOpt('allow_anonymous_access', default=False,
                help=u._('Allow unauthenticated users to access the API with '
                         'read-only privileges. This only applies when using '
                         'ContextMiddleware.')),
]


CONF = cfg.CONF
CONF.register_opts(context_opts)


# TODO(jwood): I'd like to get the utils.getLogger(...) working instead:
#  LOG = logging.getLogger(__name__)


class BaseContextMiddleware(mw.Middleware):
    def process_response(self, resp):
        try:
            request_id = resp.request.context.request_id
        except AttributeError:
            LOG.warn(u._('Unable to retrieve request id from context'))
        else:
            resp.headers['x-openstack-request-id'] = 'req-%s' % request_id
        return resp


class ContextMiddleware(BaseContextMiddleware):
    def __init__(self, app):
        self.policy_enforcer = policy.Enforcer()
        super(ContextMiddleware, self).__init__(app)

    def process_request(self, req):
        """Convert authentication information into a request context

        Generate a barbican.context.RequestContext object from the available
        authentication headers and store on the 'context' attribute
        of the req object.

        :param req: wsgi request object that will be given the context object
        :raises webob.exc.HTTPUnauthorized: when value of the X-Identity-Status
                                            header is not 'Confirmed' and
                                            anonymous access is disallowed
        """
        if req.headers.get('X-Identity-Status') == 'Confirmed':
            req.context = self._get_authenticated_context(req)
            LOG.debug("==== Inserted barbican auth "
                      "request context: %s ====" % (req.context.to_dict()))
        elif CONF.allow_anonymous_access:
            req.context = self._get_anonymous_context()
            LOG.debug("==== Inserted barbican unauth "
                      "request context: %s ====" % (req.context.to_dict()))
        else:
            raise webob.exc.HTTPUnauthorized()

        # Ensure that down wind mw.Middleware/app can see this context.
        req.environ['barbican.context'] = req.context

    def _get_anonymous_context(self):
        kwargs = {
            'user': None,
            'tenant': None,
            'roles': [],
            'is_admin': False,
            'read_only': True,
            'policy_enforcer': self.policy_enforcer,
        }
        return barbican.context.RequestContext(**kwargs)

    def _get_authenticated_context(self, req):
        #NOTE(bcwaldon): X-Roles is a csv string, but we need to parse
        # it into a list to be useful
        roles_header = req.headers.get('X-Roles', '')
        roles = [r.strip().lower() for r in roles_header.split(',')]

        #NOTE(bcwaldon): This header is deprecated in favor of X-Auth-Token
        #(mkbhanda) keeping this just-in-case for swift
        deprecated_token = req.headers.get('X-Storage-Token')

        service_catalog = None
        if req.headers.get('X-Service-Catalog') is not None:
            try:
                catalog_header = req.headers.get('X-Service-Catalog')
                service_catalog = json.loads(catalog_header)
            except ValueError:
                raise webob.exc.HTTPInternalServerError(
                    u._('Invalid service catalog json.'))

        kwargs = {
            'user': req.headers.get('X-User-Id'),
            'tenant': req.headers.get('X-Tenant-Id'),
            'roles': roles,
            'is_admin': CONF.admin_role.strip().lower() in roles,
            'auth_tok': req.headers.get('X-Auth-Token', deprecated_token),
            'owner_is_tenant': CONF.owner_is_tenant,
            'service_catalog': service_catalog,
            'policy_enforcer': self.policy_enforcer,
        }

        return barbican.context.RequestContext(**kwargs)


class UnauthenticatedContextMiddleware(BaseContextMiddleware):
    def process_request(self, req):
        """Create a context without an authorized user."""
        kwargs = {
            'user': None,
            'tenant': None,
            'roles': [],
            'is_admin': True,
        }

        req.context = barbican.context.RequestContext(**kwargs)
