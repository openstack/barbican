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
import webob.exc

from barbican.api import middleware as mw
from barbican.common import config
from barbican.common import utils
import barbican.context
from barbican import i18n as u

LOG = utils.getLogger(__name__)
CONF = config.CONF


class BaseContextMiddleware(mw.Middleware):
    def process_request(self, req):
        request_id = req.headers.get('x-openstack-request-id')
        if not request_id:
            request_id = 'req-' + utils.generate_uuid()
        setattr(req, 'request_id', request_id)
        LOG.info('Begin processing request %(request_id)s',
                 {'request_id': request_id})

    def process_response(self, resp):

        resp.headers['x-openstack-request-id'] = resp.request.request_id

        LOG.info('Processed request: %(status)s - %(method)s %(url)s',
                 {"status": resp.status,
                  "method": resp.request.method,
                  "url": resp.request.url})
        return resp


class ContextMiddleware(BaseContextMiddleware):
    def __init__(self, app):
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
        super(ContextMiddleware, self).process_request(req)

        if req.headers.get('X-Identity-Status') == 'Confirmed':
            req.context = self._get_authenticated_context(req)
        elif CONF.allow_anonymous_access:
            req.context = self._get_anonymous_context()
            LOG.debug("==== Inserted barbican unauth "
                      "request context: %s ====", req.context.to_dict())
        else:
            raise webob.exc.HTTPUnauthorized()

        # Ensure that down wind mw.Middleware/app can see this context.
        req.environ['barbican.context'] = req.context

    def _get_anonymous_context(self):
        kwargs = {
            'user_id': None,
            'tenant': None,
            'is_admin': False,
            'read_only': True,
        }
        return barbican.context.RequestContext(**kwargs)

    def _get_authenticated_context(self, req):
        ctx = barbican.context.RequestContext.from_environ(req.environ)

        if ctx.project_id is None:
            LOG.debug("X_PROJECT_ID not found in request")
            return webob.exc.HTTPUnauthorized()

        ctx.is_admin = CONF.admin_role.strip().lower() in ctx.roles

        return ctx


class UnauthenticatedContextMiddleware(BaseContextMiddleware):
    def _get_project_id_from_header(self, req):
        project_id = req.headers.get('X-Project-Id')
        if not project_id:
            accept_header = req.headers.get('Accept')
            if not accept_header:
                req.headers['Accept'] = 'text/plain'
            raise webob.exc.HTTPBadRequest(detail=u._('Missing X-Project-Id'))

        return project_id

    def process_request(self, req):
        """Create a context without an authorized user."""
        super(UnauthenticatedContextMiddleware, self).process_request(req)

        project_id = self._get_project_id_from_header(req)

        config_admin_role = CONF.admin_role.strip().lower()
        roles_header = req.headers.get('X-Roles', '')
        roles = [r.strip().lower() for r in roles_header.split(',') if r]

        # If a role wasn't specified we default to admin
        if not roles:
            roles = [config_admin_role]

        kwargs = {
            'user_id': req.headers.get('X-User-Id'),
            'domain': req.headers.get('X-Domain-Id'),
            'user_domain': req.headers.get('X-User-Domain-Id'),
            'project_domain': req.headers.get('X-Project-Domain-Id'),
            'project_id': project_id,
            'roles': roles,
            'is_admin': config_admin_role in roles,
            'request_id': req.request_id
        }

        context = barbican.context.RequestContext(**kwargs)

        req.environ['barbican.context'] = context
