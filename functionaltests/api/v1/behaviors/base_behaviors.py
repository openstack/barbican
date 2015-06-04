"""
Copyright 2014-2015 Rackspace

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


class BaseBehaviors(object):

    def __init__(self, client):
        self.LOG = logging.getLogger(type(self).__name__)
        self.client = client
        self.created_entities = []

    def get_json(self, response):
        json_data = dict()

        try:
            json_data = response.json()
        except ValueError as e:
            self.LOG.exception(e)
            self.LOG.error("Error converting response to JSON: %s", e.message)
            self.LOG.error("Response Content: %s", response.content)

        return json_data

    def get_id_from_href(self, href):
        """Returns the id from reference.

        The id must be the last item in the href.

        :param href: The href containing the id.
        :returns the id portion of the href
        """

        item_id = None
        if href and len(href) > 0:
            base, item_id = os.path.split(href)
        return item_id

    def get_user_id_from_name(self, user_name):
        """From a configured user name, get the unique user id from keystone"""
        return self.client.get_user_id_from_name(user_name)

    def get_project_id_from_name(self, user_name):
        """From a configured user name, get the project id from keystone"""
        return self.client.get_project_id_from_name(user_name)
