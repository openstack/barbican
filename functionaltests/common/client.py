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
import logging
import os

import requests
from six.moves import urllib
from tempest_lib.common.utils import misc as misc_utils

from functionaltests.common import auth
from functionaltests.common import config

LOG = logging.getLogger(__name__)

CONF = config.get_config()


class BarbicanClient(object):

    def __init__(self, api_version='v1'):
        self.timeout = CONF.keymanager.timeout
        self.api_version = api_version
        self.default_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.region = CONF.identity.region
        self._default_user_name = CONF.identity.username
        self._auth = {}
        self._auth[CONF.identity.username] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.identity.username,
            password=CONF.identity.password,
            project_name=CONF.identity.project_name)
        self._auth[CONF.identity.service_admin] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.identity.service_admin,
            password=CONF.identity.service_admin_password,
            project_name=CONF.identity.service_admin_project)
        self._auth[CONF.rbac_users.admin_a] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.rbac_users.admin_a,
            password=CONF.rbac_users.admin_a_password,
            project_name=CONF.rbac_users.project_a)
        self._auth[CONF.rbac_users.creator_a] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.rbac_users.creator_a,
            password=CONF.rbac_users.creator_a_password,
            project_name=CONF.rbac_users.project_a)
        self._auth[CONF.rbac_users.observer_a] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.rbac_users.observer_a,
            password=CONF.rbac_users.observer_a_password,
            project_name=CONF.rbac_users.project_a)
        self._auth[CONF.rbac_users.auditor_a] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.rbac_users.auditor_a,
            password=CONF.rbac_users.auditor_a_password,
            project_name=CONF.rbac_users.project_a)
        self._auth[CONF.rbac_users.admin_b] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.rbac_users.admin_b,
            password=CONF.rbac_users.admin_b_password,
            project_name=CONF.rbac_users.project_b)
        self._auth[CONF.rbac_users.creator_b] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.rbac_users.creator_b,
            password=CONF.rbac_users.creator_b_password,
            project_name=CONF.rbac_users.project_b)
        self._auth[CONF.rbac_users.observer_b] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.rbac_users.observer_b,
            password=CONF.rbac_users.observer_b_password,
            project_name=CONF.rbac_users.project_b)
        self._auth[CONF.rbac_users.auditor_b] = auth.FunctionalTestAuth(
            endpoint=CONF.identity.uri,
            version=CONF.identity.version,
            username=CONF.rbac_users.auditor_b,
            password=CONF.rbac_users.auditor_b_password,
            project_name=CONF.rbac_users.project_b)

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

    def log_request(self, request_kwargs, response, user_name):
        test_name = misc_utils.find_test_caller()
        str_request = self.stringify_request(request_kwargs, response)
        if user_name is None:
            user_info = ''
        else:
            user_info = "(user={0})".format(user_name)
        LOG.info('Request %s (%s)\n %s',
                 user_info,
                 test_name,
                 str_request)

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

    def _get_url_w_trailing_slash(self, url):
        """Returns the given URL with a trailing slash

        Given a URL, this function will return it with a trailing slash. If
        there is already a trailing slash, then it will return the same URL
        that was given.

        Note that the instances where this is being used, actually need a
        trailing slash. Be careful not to use this when it's not needed.
        """
        # NOTE(jaosorior): The urljoin needs this in order to actually append
        # a URL to another. If a URL, say http://localhost/v1 doesn't have a
        # slash in the end, the last fragment will be replaced with the second
        # parameter given to urljoin; Which is not what we want.
        if url[-1] != "/":
            return url + "/"
        return url

    def _get_base_url_from_config(self, include_version):
        if include_version:
            base_url = urllib.parse.urljoin(
                CONF.keymanager.override_url,
                CONF.keymanager.override_url_version)
        else:
            base_url = CONF.keymanager.override_url
        return self._get_url_w_trailing_slash(base_url)

    def get_base_url(self, include_version=True):
        if CONF.keymanager.override_url:
            return self._get_base_url_from_config(include_version)

        auth = self._auth[self._default_user_name]
        endpoint = auth.service_catalog.get_endpoints(
            service_type=CONF.keymanager.service_type,
            service_name=CONF.keymanager.service_name,
            region_name=CONF.keymanager.region_name,
            endpoint_type=CONF.keymanager.endpoint_type)

        if auth.version.lower() == 'v2':
            base_url = endpoint['key-manager'][0].get('publicURL')
        else:
            base_url = endpoint['key-manager'][0].get('url')

        # Make sure we handle the edge cases around Keystone providing
        # endpoints with or without versions
        if include_version and self.api_version not in base_url:
            base_url = urllib.parse.urljoin(base_url, self.api_version)
        elif not include_version and self.api_version in base_url:
            base_url, _ = os.path.split(base_url)

        return self._get_url_w_trailing_slash(base_url)

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
            elif item in ('secrets', 'orders', 'containers',
                          'consumers', 'project_quotas'):
                for entity in item_list.get(item):
                    models.append(model_type(**entity))

        return models, next_ref, prev_ref

    def request(self, method, url, data=None, extra_headers=None,
                omit_headers=None,
                use_auth=True, response_model_type=None, request_model=None,
                params=None, user_name=None):
        """Prepares and sends http request through Requests."""
        if url and 'http' not in url:
            url = urllib.parse.urljoin(self.get_base_url(), url)

        # Duplicate Base headers and add extras (if needed)
        headers = {}
        headers.update(self.default_headers)
        if extra_headers:
            headers.update(extra_headers)

        if omit_headers:
            for header in omit_headers:
                try:
                    del headers[header]
                except KeyError:
                    # key error means we tried to delete a nonexistent
                    # entry - we don't care about that
                    pass

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
            if not user_name:
                user_name = self._default_user_name
            call_kwargs['auth'] = self._auth[user_name]

        response = requests.request(**call_kwargs)

        # Attempt to deserialize the response
        response.model = self.attempt_to_deserialize(response,
                                                     response_model_type)
        self.log_request(call_kwargs, response, user_name)
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

    def patch(self, *args, **kwargs):
        """Proxies the request method specifically for http PATCH methods."""
        return self.request('PATCH', *args, **kwargs)

    def get_user_id_from_name(self, user_name):
        if user_name and self._auth[user_name]:
            return self._auth[user_name].get_user_id()
        else:
            return None

    def get_project_id_from_name(self, user_name):
        if user_name and self._auth[user_name]:
            return self._auth[user_name].get_project_id()
        else:
            return None
