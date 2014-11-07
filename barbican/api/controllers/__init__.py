#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import pecan
from webob import exc

from barbican import api
from barbican.common import utils
from barbican.openstack.common import gettextutils as u

LOG = utils.getLogger(__name__)


def is_json_request_accept(req):
    """Test if http request 'accept' header configured for JSON response.

    :param req: HTTP request
    :return: True if need to return JSON response.
    """
    return (not req.accept
            or req.accept.header_value == 'application/json'
            or req.accept.header_value == '*/*')


def _get_barbican_context(req):
    if 'barbican.context' in req.environ:
        return req.environ['barbican.context']
    else:
        return None


def _do_enforce_rbac(req, action_name, ctx):
    """Enforce RBAC based on 'request' information."""
    if action_name and ctx:

        # Prepare credentials information.
        credentials = {
            'roles': ctx.roles,
            'user': ctx.user,
            'project': ctx.project
        }

        # Enforce special case: secret GET decryption
        if 'secret:get' == action_name and not is_json_request_accept(req):
            action_name = 'secret:decrypt'  # Override to perform special rules

        # Enforce access controls.
        if ctx.policy_enforcer:
            ctx.policy_enforcer.enforce(action_name, {}, credentials,
                                        do_raise=True)


def enforce_rbac(action_name='default'):
    """Decorator handling RBAC enforcement on behalf of REST verb methods."""

    def rbac_decorator(fn):
        def enforcer(inst, *args, **kwargs):
            # Enforce RBAC rules.

            # context placed here by context.py
            # middleware
            ctx = _get_barbican_context(pecan.request)
            if ctx:
                keystone_id = ctx.project
            else:
                keystone_id = None

            _do_enforce_rbac(pecan.request, action_name, ctx)
            # insert keystone_id as the first arg to the guarded method
            args = list(args)
            args.insert(0, keystone_id)
            # Execute guarded method now.
            return fn(inst, *args, **kwargs)

        return enforcer

    return rbac_decorator


def handle_exceptions(operation_name=u._('System')):
    """Decorator handling generic exceptions from REST methods."""

    def exceptions_decorator(fn):

        def handler(inst, *args, **kwargs):
            try:
                return fn(inst, *args, **kwargs)
            except exc.HTTPError as f:
                LOG.exception('Webob error seen')
                raise f  # Already converted to Webob exception, just reraise
            except Exception as e:
                status, message = api.generate_safe_exception_message(
                    operation_name, e)
                LOG.exception(message)
                pecan.abort(status, message)

        return handler

    return exceptions_decorator


def _do_enforce_content_types(pecan_req, valid_content_types):
    """Content type enforcement

    Check to see that content type in the request is one of the valid
    types passed in by our caller.
    """
    if pecan_req.content_type not in valid_content_types:
        m = ("Unexpected content type: {0}.  Expected content types "
             "are: {1}").format(pecan_req.content_type, valid_content_types)
        pecan.abort(415, m)


def enforce_content_types(valid_content_types=[]):
    """Decorator handling content type enforcement on behalf of REST verbs."""

    def content_types_decorator(fn):

        def content_types_enforcer(inst, *args, **kwargs):
            _do_enforce_content_types(pecan.request, valid_content_types)
            return fn(inst, *args, **kwargs)

        return content_types_enforcer

    return content_types_decorator
