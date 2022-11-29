# Copyright (c) 2013-2015 Rackspace, Inc.
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
API handler for Barbican
"""
import pkgutil

from oslo_policy import policy
from oslo_serialization import jsonutils as json
import pecan

from barbican.common import config
from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u


LOG = utils.getLogger(__name__)
CONF = config.CONF


class ApiResource(object):
    """Base class for API resources."""
    pass


def load_body(req, resp=None, validator=None):
    """Helper function for loading an HTTP request body from JSON.

    This body is placed into into a Python dictionary.

    :param req: The HTTP request instance to load the body from.
    :param resp: The HTTP response instance.
    :param validator: The JSON validator to enforce.
    :return: A dict of values from the JSON request.
    """
    try:
        body = req.body_file.read(CONF.max_allowed_request_size_in_bytes)
        req.body_file.seek(0)
    except IOError:
        LOG.exception("Problem reading request JSON stream.")
        pecan.abort(500, u._('Read Error'))

    try:
        # TODO(jwood): Investigate how to get UTF8 format via openstack
        # jsonutils:
        #     parsed_body = json.loads(raw_json, 'utf-8')
        parsed_body = json.loads(body)
        strip_whitespace(parsed_body)
    except ValueError:
        LOG.exception("Problem loading request JSON.")
        pecan.abort(400, u._('Malformed JSON'))

    if validator:
        try:
            parsed_body = validator.validate(parsed_body)
        except exception.BarbicanHTTPException as e:
            LOG.exception(str(e))
            pecan.abort(e.status_code, e.client_message)

    return parsed_body


def generate_safe_exception_message(operation_name, excep):
    """Generates an exception message that is 'safe' for clients to consume.

    A 'safe' message is one that doesn't contain sensitive information that
    could be used for (say) cryptographic attacks on Barbican. That generally
    means that em.CryptoXxxx should be captured here and with a simple
    message created on behalf of them.

    :param operation_name: Name of attempted operation, with a 'Verb noun'
                           format (e.g. 'Create Secret).
    :param excep: The Exception instance that halted the operation.
    :return: (status, message) where 'status' is one of the webob.exc.HTTP_xxx
                               codes, and 'message' is the sanitized message
                               associated with the error.
    """
    message = None
    reason = None
    status = 500

    try:
        raise excep
    except (policy.PolicyNotAuthorized, policy.InvalidScope):
        message = u._(
            '{operation} attempt not allowed - '
            'please review your '
            'user/project privileges').format(operation=operation_name)
        status = 403

    except exception.BarbicanHTTPException as http_exception:
        reason = http_exception.client_message
        status = http_exception.status_code
    except Exception:
        message = u._('{operation} failure seen - please contact site '
                      'administrator.').format(operation=operation_name)

    if reason:
        message = u._('{operation} issue seen - {reason}.').format(
            operation=operation_name, reason=reason)

    return status, message


@pkgutil.simplegeneric
def get_items(obj):
    """This is used to get items from either a list or a dictionary.

    While false generator is need to process scalar object
    """

    while False:
        yield None


@get_items.register(dict)
def _json_object(obj):
    return obj.items()


@get_items.register(list)
def _json_array(obj):
    return enumerate(obj)


def strip_whitespace(json_data):
    """Recursively trim values from the object passed in using get_items()."""

    for key, value in get_items(json_data):
        if hasattr(value, 'strip'):
            json_data[key] = value.strip()
        else:
            strip_whitespace(value)
