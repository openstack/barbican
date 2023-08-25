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

import collections.abc

from oslo_policy import policy
import pecan
from webob import exc

from barbican import api
from barbican.common import accept
from barbican.common import config
from barbican.common import utils
from barbican import i18n as u


CONF = config.CONF
LOG = utils.getLogger(__name__)


def is_json_request_accept(req):
    """Test if http request 'accept' header configured for JSON response.

    :param req: HTTP request
    :return: True if need to return JSON response.
    """
    return (
        type(req.accept) is accept.NoHeaderType or
        type(req.accept) is accept.ValidHeaderType and (
            req.accept.header_value == 'application/json' or
            req.accept.header_value == '*/*'
        )
    )


def _get_barbican_context(req):
    if 'barbican.context' in req.environ:
        return req.environ['barbican.context']
    else:
        return None


def _do_enforce_rbac(inst, req, action_name, ctx, **kwargs):
    """Enforce RBAC based on 'request' information."""
    if action_name and ctx:

        # Enforce special case: secret GET decryption
        if 'secret:get' == action_name and not is_json_request_accept(req):
            action_name = 'secret:decrypt'  # Override to perform special rules

        target_name, target_data = inst.get_acl_tuple(req, **kwargs)
        policy_dict = {
            "enforce_new_defaults": CONF.oslo_policy.enforce_new_defaults
        }
        if target_name and target_data:
            policy_dict['target'] = {target_name: target_data}

        # Enforce access controls.
        if ctx.policy_enforcer:
            target = flatten(policy_dict)
            ctx.policy_enforcer.authorize(action_name, target,
                                          ctx, do_raise=True)


def enforce_rbac(action_name='default'):
    """Decorator handling RBAC enforcement on behalf of REST verb methods."""

    def rbac_decorator(fn):
        def enforcer(inst, *args, **kwargs):
            # Enforce RBAC rules.

            # context placed here by context.py
            # middleware
            ctx = _get_barbican_context(pecan.request)
            external_project_id = None
            if ctx:
                external_project_id = ctx.project_id

            _do_enforce_rbac(inst, pecan.request, action_name, ctx, **kwargs)
            # insert external_project_id as the first arg to the guarded method
            args = list(args)
            args.insert(0, external_project_id)
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
            except exc.HTTPError:
                LOG.exception('Webob error seen')
                raise  # Already converted to Webob exception, just reraise
            # In case PolicyNotAuthorized, we do not want to expose payload by
            # logging exception, so just LOG.error
            except policy.PolicyNotAuthorized as pna:
                status, message = api.generate_safe_exception_message(
                    operation_name, pna)
                LOG.error(message)
                pecan.abort(status, message)
            except Exception as e:
                # In case intervening modules have disabled logging.
                LOG.logger.disabled = False

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
        m = u._(
            "Unexpected content type. Expected content types "
            "are: {expected}"
        ).format(
            expected=valid_content_types
        )
        pecan.abort(415, m)


def enforce_content_types(valid_content_types=[]):
    """Decorator handling content type enforcement on behalf of REST verbs."""

    def content_types_decorator(fn):

        def content_types_enforcer(inst, *args, **kwargs):
            _do_enforce_content_types(pecan.request, valid_content_types)
            return fn(inst, *args, **kwargs)

        return content_types_enforcer

    return content_types_decorator


def flatten(d, parent_key=''):
    """Flatten a nested dictionary

    Converts a dictionary with nested values to a single level flat
    dictionary, with dotted notation for each key.

    """
    items = []
    for k, v in d.items():
        new_key = parent_key + '.' + k if parent_key else k
        if isinstance(v, collections.abc.MutableMapping):
            items.extend(flatten(v, new_key).items())
        else:
            items.append((new_key, v))
    return dict(items)


class ACLMixin(object):

    def __init__(self):
        self.secret = None
        self.container = None

    def get_acl_tuple(self, req, **kwargs):
        if self.secret is not None:
            entity = 'secret'
        elif self.container is not None:
            entity = 'container'
        else:
            return None, None
        entity_acls = getattr(getattr(self, entity), '{}_acls'.format(entity))
        acl = self.get_acl_dict_for_user(req, entity_acls)
        acl['project_id'] = getattr(self, entity).project.external_id
        acl['creator_id'] = getattr(self, entity).creator_id
        return entity, acl

    def get_acl_dict_for_user(self, req, acl_list):
        """Get acl operation found for token user in acl list.

        Token user is looked into users list present for each acl operation.
        If there is a match, it means that ACL data is applicable for policy
        logic. Policy logic requires data as dictionary so this method capture
        acl's operation, project_access data in that format.

        For operation value, matching ACL record's operation is stored in dict
        as key and value both.
        project_access flag is intended to make secret/container private for a
        given operation. It doesn't require user match. So its captured in dict
        format where key is prefixed with related operation and flag is used as
        its value.

        Then for acl related policy logic, this acl dict data is combined with
        target entity (secret or container) creator_id and project id. The
        whole dict serves as target in policy enforcement logic i.e. right
        hand side of policy rule.

        Following is sample outcome where secret or container has ACL defined
        and token user is among the ACL users defined for 'read' and 'list'
        operation.

        {'read': 'read', 'list': 'list', 'read_project_access': True,
        'list_project_access': True }

        Its possible that ACLs are defined without any user, they just
        have project_access flag set. This means only creator can read or list
        ACL entities. In that case, dictionary output can be as follows.

        {'read_project_access': False, 'list_project_access': False }

        """
        ctxt = _get_barbican_context(req)
        if not ctxt:
            return {}
        acl_dict = {acl.operation: acl.operation for acl in acl_list
                    if ctxt.user_id in acl.to_dict_fields().get('users', [])}
        co_dict = {'%s_project_access' % acl.operation: acl.project_access for
                   acl in acl_list if acl.project_access is not None}
        if not co_dict:
            """
            The co_dict is empty when the entity (secret or container) has no
            acls in its acl_list.  This causes any policy with

                "%(target.secret.read_project_access)s"
            or
                "%(target.container.read_project_access)s"

            to always evaluate to False.  This is probelmatic because we want
            to allow project access by default (with additional role checks).
            To work around this we allow read here.

            When the entity has an acl, co_dict will use the value from the
            database, and this if statement will be skipped.
            """
            co_dict = {'read_project_access': True}
        acl_dict.update(co_dict)

        return acl_dict
