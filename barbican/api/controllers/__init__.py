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
    return not req.accept or req.accept.header_value == 'application/json' \
        or req.accept.header_value == '*/*'


def enforce_rbac(req, action_name, keystone_id=None):
    """Enforce RBAC based on 'request' information."""
    if action_name and 'barbican.context' in req.environ:

        # Prepare credentials information.
        ctx = req.environ['barbican.context']  # Placed here by context.py
                                               #   middleware
        credentials = {
            'roles': ctx.roles,
            'user': ctx.user,
            'tenant': ctx.tenant,
        }

        # Verify keystone_id matches the tenant ID.
        if keystone_id and keystone_id != ctx.tenant:
            pecan.abort(403, u._("URI tenant does not match "
                        "authenticated tenant."))

        # Enforce special case: secret GET decryption
        if 'secret:get' == action_name and not is_json_request_accept(req):
            action_name = 'secret:decrypt'  # Override to perform special rules

        # Enforce access controls.
        ctx.policy_enforcer.enforce(action_name, {}, credentials,
                                    do_raise=True)


def handle_rbac(action_name='default'):
    """Decorator handling RBAC enforcement on behalf of REST verb methods."""

    def rbac_decorator(fn):
        def enforcer(inst, *args, **kwargs):

            # Enforce RBAC rules.
            enforce_rbac(pecan.request, action_name,
                         keystone_id=kwargs.get('keystone_id'))

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
