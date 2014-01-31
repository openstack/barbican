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
API handler for Cloudkeep's Barbican
"""
import falcon
from pkgutil import simplegeneric

from barbican.common import exception
from barbican.common import utils
from barbican.crypto import extension_manager as em
from barbican.openstack.common import gettextutils as u
from barbican.openstack.common import jsonutils as json
from barbican.openstack.common import policy


LOG = utils.getLogger(__name__)
MAX_BYTES_REQUEST_INPUT_ACCEPTED = 1000000


class ApiResource(object):
    """Base class for API resources."""
    pass


def abort(status=falcon.HTTP_500, message=None, req=None, resp=None):
    """Helper function for aborting an API request process.
    This function is useful for error reporting and exception handling.

    :param status: A falcon.HTTP_XXXX status code.
    :param message: The message to associate with the Falcon exception.
    :param req: The HTTP request.
    :param resp: The HTTP response.
    :return: None
    :raise: falcon.HTTPError
    """
    # Deal with odd Falcon behavior, whereby it does not encode error
    # response messages if requests specify a non-JSON Accept header.
    # If the Accept header does specify JSON, then Falcon properly
    # JSON-ifies the error message.
    if resp and message:
        if req and req.accept != 'application/json':
            resp.set_header('Content-Type', 'text/plain')
            resp.body = message
    raise falcon.HTTPError(status, message)


def load_body(req, resp=None, validator=None):
    """Helper function for loading an HTTP request body from JSON.
    This body is placed into into a Python dictionary.

    :param req: The HTTP request instance to load the body from.
    :param resp: The HTTP response instance.
    :param validator: The JSON validator to enforce.
    :return: A dict of values from the JSON request.
    """
    try:
        raw_json = req.stream.read(MAX_BYTES_REQUEST_INPUT_ACCEPTED)
    except IOError:
        LOG.exception("Problem reading request JSON stream.")
        abort(falcon.HTTP_500, 'Read Error', req, resp)

    try:
        #TODO(jwood): Investigate how to get UTF8 format via openstack
        # jsonutils:
        #     parsed_body = json.loads(raw_json, 'utf-8')
        parsed_body = json.loads(raw_json)
        strip_whitespace(parsed_body)
    except ValueError:
        LOG.exception("Problem loading request JSON.")
        abort(falcon.HTTP_400, 'Malformed JSON', req, resp)

    if validator:
        try:
            parsed_body = validator.validate(parsed_body)
        except exception.InvalidObject as e:
            LOG.exception("Failed to validate JSON information")
            abort(falcon.HTTP_400, str(e), req, resp)
        except exception.UnsupportedField as e:
            LOG.exception("Provided field value is not supported")
            abort(falcon.HTTP_400, str(e), req, resp)
        except exception.LimitExceeded as e:
            LOG.exception("Data limit exceeded")
            abort(falcon.HTTP_413, str(e), req, resp)

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
    :return: (status, message) where 'status' is one of the falcon.HTTP_xxxx
                               codes, and 'message' is the sanitized message
                               associated with the error.
    """
    message = None
    reason = None
    status = falcon.HTTP_500

    try:
        raise excep
    except falcon.HTTPError as f:
        message = f.title
        status = f.status
    except policy.PolicyNotAuthorized:
        message = u._('{0} attempt was not authorized - '
                      'please review your '
                      'user/tenant privileges').format(operation_name)
        status = falcon.HTTP_401
    except em.CryptoContentTypeNotSupportedException as cctnse:
        reason = u._("content-type of '{0}' not "
                     "supported").format(cctnse.content_type)
        status = falcon.HTTP_400
    except em.CryptoContentEncodingNotSupportedException as cc:
        reason = u._("content-encoding of '{0}' not "
                     "supported").format(cc.content_encoding)
        status = falcon.HTTP_400
    except em.CryptoAcceptNotSupportedException as canse:
        reason = u._("accept of '{0}' not "
                     "supported").format(canse.accept)
        status = falcon.HTTP_406
    except em.CryptoNoPayloadProvidedException:
        reason = u._("No payload provided")
        status = falcon.HTTP_400
    except em.CryptoNoSecretOrDataFoundException:
        reason = u._("Not Found.  Sorry but your secret is in "
                     "another castle")
        status = falcon.HTTP_404
    except em.CryptoPayloadDecodingError:
        reason = u._("Problem decoding payload")
        status = falcon.HTTP_400
    except em.CryptoContentEncodingMustBeBase64:
        reason = u._("Text-based binary secret payloads must "
                     "specify a content-encoding of 'base64'")
        status = falcon.HTTP_400
    except em.CryptoAlgorithmNotSupportedException:
        reason = u._("No plugin was found that supports the "
                     "requested algorithm")
        status = falcon.HTTP_400
    except em.CryptoSupportedPluginNotFound:
        reason = u._("No plugin was found that could support "
                     "your request")
        status = falcon.HTTP_400
    except exception.NoDataToProcess:
        reason = u._("No information provided to process")
        status = falcon.HTTP_400
    except exception.LimitExceeded:
        reason = u._("Provided information too large "
                     "to process")
        status = falcon.HTTP_413
    except Exception:
        message = u._('{0} failure seen - please contact site '
                      'administrator.').format(operation_name)

    if reason:
        message = u._('{0} issue seen - {1}.').format(operation_name,
                                                      reason)

    return status, message


@simplegeneric
def get_items(obj):
    """This is used to get items from either
       a list or a dictionary. While false
       generator is need to process scalar object
    """

    while False:
        yield None


@get_items.register(dict)
def _json_object(obj):
    return obj.iteritems()


@get_items.register(list)
def _json_array(obj):
    return enumerate(obj)


def strip_whitespace(json_data):
    """This function will recursively trim values from the
       object passed in using the get_items
    """

    for key, value in get_items(json_data):
        if hasattr(value, 'strip'):
            json_data[key] = value.strip()
        else:
            strip_whitespace(value)
