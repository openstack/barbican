# -*- coding: utf-8 -*-
"""
    Barbican API testing 
    ~~~~~~~~~~~~

    The testing for Barbican API.

    DO NOT USE THIS IN PRODUCTION. IT IS NOT SECURE IN ANY WAY.
    YOU HAVE BEEN WARNED.

    :copyright: (c) 2013 by Jarret Raim
    :license: Apache 2.0, see LICENSE for details
"""

import uuid
import datetime
import requests
import json
from models import Event, Tenant, Key, Agent, Policy


class BarbicanAPITesting:
    def __init__(self, url="http://127.0.0.1:5000/api/"):
        self.url = url
        
    def add_agent(self, tenant_id):

        new_uuid = uuid.uuid4()
        self.agent_id = new_uuid
        pay_load = {"uuid": str(new_uuid)}
        the_url = self.url + str(tenant_id) + "/agents/"
        headers = {'content-type': 'application/json'}
        response = requests.post(the_url,data=json.dumps(pay_load), headers=headers)
        try:
            the_uuid = response.json["uuid"]
        except Exception as e:
            print e
        return the_uuid
    
    def add_policy(self, policy_name, tenant_id):
        policy_id = str(uuid.uuid4())
        key_id = str(uuid.uuid4())
        self.key_id = key_id
        payload = '''
        {
    "policies": [
        {
            "uuid": "%s",
            "name": "%s",
            "directory_name": "my-app-key",
            "max_key_accesses": 1,
            "time_available_after_reboot": 10,
            "keys": [
                {
                    "uuid": "%s",
                    "filename": "configuration_key",
                    "mime_type": "application/aes-256-cbc",
                    "expiration": "2014-02-28T19:14:44.180394",
                    "secret": "b7990b786ee9659b43e6b1cd6136de07d9c5aa06513afe5d091c04bde981b280",
                    "owner": "myapp",
                    "group": "myapp",
                    "cacheable": false
                }
            ]
        }
    ]
}
        '''  % (policy_id, policy_name, key_id)
        the_url = self.url + str(tenant_id) + "/policies/"
        headers = {'content-type': 'application/json'}
        response = requests.post(the_url,data=payload, headers=headers)
        return response.text
        
    def get_policy(self, tenant_id):
        the_url = self.url + str(tenant_id) + "/policies/"
        response = requests.get(the_url)
        return  response.text
        

    def get_agents(self, tenant_id):

        the_url = self.url + str(tenant_id) + "/agents/"
        response = requests.get(the_url)
        print response.json

    def add_log(self, tenant_id):
        payload = '''
        {
    "agent_id": "%s",
    "received_on": "%s",
    "severity": "INFO",
    "key_id": "%s",
    "message": "Key accessed by user 'apache'."
        }
        ''' % (self.agent_id, datetime.datetime.isoformat(datetime.datetime.now()),  self.key_id)
        the_url = self.url + str(tenant_id) + "/logs/"
        headers = {'content-type': 'application/json'}
        response = requests.post(the_url,data=payload, headers=headers)
        return response.text
    
    def get_log(self, tenant_id):
        the_url = self.url + str(tenant_id) + "/logs/"
        response = requests.get(the_url)
        return response.text
    
    def get_tenant(self, tenant_id):
        the_url = self.url + str(tenant_id) + "/"
        response = requests.get(the_url)
        return response.text
    
    def create_tenant(self, tenant_id):
        the_url = self.url + str(tenant_id) + "/"
        response = requests.post(the_url)
        return response.text
    
      
test1 = BarbicanAPITesting()
print test1.get_tenant(123)
print test1.get_tenant(1234)
print test1.create_tenant(123456)
print test1.create_tenant(2349)
print test1.add_agent(1234)
test1.get_agents(1234)

print test1.add_policy("Before start up", 1234)
print test1.get_policy(1234)

print test1.add_log(1234)
print test1.get_log(123)