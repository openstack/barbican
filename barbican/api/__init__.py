# Copyright (c) 2013 Rackspace, Inc.
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
from barbican.openstack.common import jsonutils as json
from barbican.common import exception
from barbican.common import utils


LOG = utils.getLogger(__name__)
MAX_BYTES_REQUEST_INPUT_ACCEPTED = 1000000


class ApiResource(object):
    """
    Base class for API resources
    """
    pass


def abort(status=falcon.HTTP_500, message=None, req=None, resp=None):
    """
    Helper function for aborting an API request process. Useful for error
    reporting and expcetion handling.
    """
    if resp and message:
        if req and req.accept != 'application/json':
            resp.set_header('Content-Type', 'text/plain')
            resp.body = message
    raise falcon.HTTPError(status, message)


def load_body(req, resp=None, validator=None):
    """
    Helper function for loading an HTTP request body from JSON into a
    Python dictionary
    """
    try:
        raw_json = req.stream.read(MAX_BYTES_REQUEST_INPUT_ACCEPTED)
    except IOError:
        LOG.exception("Problem reading request JSON stream.")
        abort(falcon.HTTP_500, 'Read Error', req, resp)

    try:
        #TODO: Investigate how to get UTF8 format via openstack jsonutils:
        #     parsed_body = json.loads(raw_json, 'utf-8')
        parsed_body = json.loads(raw_json)
    except ValueError:
        LOG.exception("Problem loading request JSON.")
        abort(falcon.HTTP_400, 'Malformed JSON', req, resp)

    if validator:
        try:
            parsed_body = validator.validate(parsed_body)
        except exception.InvalidObject as e:
            LOG.exception("Failed to validate JSON information")
            abort(falcon.HTTP_400, str(e), req, resp)

    return parsed_body
