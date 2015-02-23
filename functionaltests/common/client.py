"""
Copyright 2014 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import os

import requests
from requests import auth
from tempest.common.utils import misc as misc_utils
from tempest import config
from tempest.openstack.common import log as logging

LOG = logging.getLogger(__name__)

CONF = config.CONF

# Use local tempest conf if one is available.
# This usually means we're running tests outside of devstack.
if os.path.exists('./etc/dev_tempest.conf'):
    CONF.set_config_path('./etc/dev_tempest.conf')


class BarbicanClientAuth(auth.AuthBase):
    """Implementation of Requests Auth for Barbican http calls."""

    def __init__(self, auth_provider):
        credentials = auth_provider.fill_credentials()

        self.username = credentials.username
        self.password = credentials.password

        if 'v3' in CONF.identity.auth_version:
            self.project_name = credentials.project_name
            self.project_id = credentials.project_id
        else:
            self.tenant_name = credentials.tenant_name
            self.project_id = credentials.tenant_id

        try:
            self.token = auth_provider.get_token()
        except ValueError:
            # hockeynut - some auth providers will allow the v3 expiration
            # date format which includes milliseconds.  This change will retry
            # the call to get the auth token with the milliseconds included in
            # the date format string.
            auth_provider.EXPIRY_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
            self.token = auth_provider.get_token()

    def __call__(self, r):
        r.headers['X-Project-Id'] = self.project_id
        r.headers['X-Auth-Token'] = self.token
        return r


class BarbicanClient(object):

    def __init__(self, auth_provider, api_version='v1'):
        self._auth = BarbicanClientAuth(auth_provider)
        self._auth_provider = auth_provider
        self.timeout = 10
        self.api_version = api_version
        self.default_headers = {
            'Content-Type': 'application/json'
        }
        self.region = CONF.identity.region

    def _attempt_to_stringify_content(self, content, content_tag):
        if content is None:
            return content
        try:
            # NOTE(jaosorior): The content is decoded as ascii since the
            # logging module has problems with utf-8 strings and will end up
            # trying to decode this as ascii.
            return content.decode('ascii')
        except UnicodeDecodeError:
            # NOTE(jaosorior): Since we are using base64 as default and this is
            # only for logging (in order to debug); Lets not put too much
            # effort in this and just use encoded string.
            return content.encode('base64')

    def stringify_request(self, request_kwargs, response):
        format_kwargs = {
            'code': response.status_code,
            'method': request_kwargs.get('method'),
            'url': request_kwargs.get('url'),
            'headers': response.request.headers,
        }

        format_kwargs['body'] = self._attempt_to_stringify_content(
            request_kwargs.get('data'), 'body')

        format_kwargs['response_body'] = self._attempt_to_stringify_content(
            response.content, 'response_body')

        return ('{code} {method} {url}\n'
                'Request Headers: {headers}\n'
                'Request Body: {body}\n'
                'Response: {response_body}').format(**format_kwargs)

    def log_request(self, request_kwargs, response):
        test_name = misc_utils.find_test_caller()
        str_request = self.stringify_request(request_kwargs, response)
        LOG.info('Request (%s)\n %s', test_name, str_request)

    def _status_is_2xx_success(self, status_code):
        return status_code >= 200 and status_code < 300

    def attempt_to_deserialize(self, response, model_type):
        if (self._status_is_2xx_success(response.status_code) and
                model_type and hasattr(model_type, 'json_to_obj')):
            return model_type.json_to_obj(response.content)
        return None

    def attempt_to_serialize(self, model):
        if model and hasattr(model, 'obj_to_json'):
            return model.obj_to_json()

    def get_base_url(self, include_version=True):
        if CONF.keymanager.override_url:
            if include_version:
                return os.path.join(CONF.keymanager.override_url,
                                    CONF.keymanager.override_url_version)
            else:
                return CONF.keymanager.override_url
        filters = {
            'service': 'key-manager',
            'region': self.region,
            'api_version': self.api_version if include_version else ''
        }

        return self._auth_provider.base_url(filters)

    def get_list_of_models(self, item_list, model_type):
        """Takes a list of barbican objects and creates a list of models

        :param item_list: the json returned from a barbican GET request for
         a list of objects
        :param model_type: The model used in the creation of the list of models
        :return A list of models and the refs for next and previous lists.
        """

        models, next_ref, prev_ref = [], None, None

        for item in item_list:
            if 'next' == item:
                next_ref = item_list.get('next')
            elif 'previous' == item:
                prev_ref = item_list.get('previous')
            elif item in ('secrets', 'orders', 'containers', 'consumers'):
                for entity in item_list.get(item):
                    models.append(model_type(**entity))

        return models, next_ref, prev_ref

    def request(self, method, url, data=None, extra_headers=None,
                use_auth=True, response_model_type=None, request_model=None,
                params=None):
        """Prepares and sends http request through Requests."""
        if 'http' not in url:
            url = os.path.join(self.get_base_url(), url)

        # Duplicate Base headers and add extras (if needed)
        headers = {}
        headers.update(self.default_headers)
        if extra_headers:
            headers.update(extra_headers)

        # Attempt to serialize model if required
        if request_model:
            data = self.attempt_to_serialize(request_model)

        # Prepare call arguments
        call_kwargs = {
            'method': method,
            'url': url,
            'headers': headers,
            'data': data,
            'timeout': self.timeout,
            'params': params
        }
        if use_auth:
            call_kwargs['auth'] = self._auth

        response = requests.request(**call_kwargs)

        # Attempt to deserialize the response
        response.model = self.attempt_to_deserialize(response,
                                                     response_model_type)
        self.log_request(call_kwargs, response)
        return response

    def get(self, *args, **kwargs):
        """Proxies the request method specifically for http GET methods."""
        return self.request('GET', *args, **kwargs)

    def post(self, *args, **kwargs):
        """Proxies the request method specifically for http POST methods."""
        return self.request('POST', *args, **kwargs)

    def put(self, *args, **kwargs):
        """Proxies the request method specifically for http PUT methods."""
        return self.request('PUT', *args, **kwargs)

    def delete(self, *args, **kwargs):
        """Proxies the request method specifically for http DELETE methods."""
        return self.request('DELETE', *args, **kwargs)
