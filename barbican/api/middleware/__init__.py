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
Barbican middleware modules.
"""
import sys

import webob.dec

from barbican.common import utils

LOG = utils.getLogger(__name__)


class Middleware(object):
    """Base WSGI middleware wrapper

    These classes require an application to be
    initialized that will be called next.  By default the middleware will
    simply call its wrapped app, or you can override __call__ to customize its
    behavior.
    """

    def __init__(self, application):
        self.application = application

    @classmethod
    def factory(cls, global_conf, **local_conf):
        def filter(app):
            return cls(app)
        return filter

    def process_request(self, req):
        """Called on each request.

        If this returns None, the next application down the stack will be
        executed. If it returns a response then that response will be returned
        and execution will stop here.

        """
        return None

    def process_response(self, response):
        """Do whatever you'd like to the response."""
        return response

    @webob.dec.wsgify
    def __call__(self, req):
        response = self.process_request(req)
        if response:
            return response
        response = req.get_response(self.application)
        response.request = req
        return self.process_response(response)


# Brought over from an OpenStack project
class Debug(Middleware):
    """Debug helper class

    This class can be inserted into any WSGI application chain
    to get information about the request and response.
    """

    @webob.dec.wsgify
    def __call__(self, req):
        LOG.debug(("*" * 40) + " REQUEST ENVIRON")
        for key, value in req.environ.items():
            LOG.debug('%s=%s', key, value)
        LOG.debug(' ')
        resp = req.get_response(self.application)

        LOG.debug(("*" * 40) + " RESPONSE HEADERS")
        for (key, value) in resp.headers.items():
            LOG.debug('%s=%s', key, value)
        LOG.debug(' ')

        resp.app_iter = self.print_generator(resp.app_iter)

        return resp

    @staticmethod
    def print_generator(app_iter):
        """Iterator that prints the contents of a wrapper string iterator."""
        LOG.debug(("*" * 40) + " BODY")
        for part in app_iter:
            sys.stdout.write(part)
            sys.stdout.flush()
            yield part
        LOG.debug(' ')
