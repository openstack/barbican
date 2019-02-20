#!/usr/bin/env python

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
Demonstrates the various Barbican API calls, against an unauthenticated local
Barbican server. This script is intended to be a lightweight way to demonstrate
and 'smoke test' the Barbican API via it's REST API, with no other dependencies
required including the Barbican Python client. Note that this script is not
intended to replace DevStack or Tempest style testing.
"""

import logging
import requests
import sys

from oslo_serialization import jsonutils as json


LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)
LOG.addHandler(logging.StreamHandler(sys.stdout))


# Project ID:
proj = '12345678'

# Endpoint:
end_point = 'http://localhost:9311'
version = 'v1'

# Basic header info:
hdrs = {'X-Project-Id': proj, 'content-type': 'application/json'}

# Consumer data.
payload_consumer = {
    'name': 'foo-service',
    'URL': 'https://www.fooservice.com/widgets/1234'
}


def demo_version():
    """Get version"""
    v = requests.get(end_point, headers=hdrs)
    LOG.info('Version: {0}\n'.format(v.text))


def demo_store_secret_one_step_text(suffix=None, suppress=False):
    """Store secret (1-step):"""
    ep_1step = '/'.join([end_point, version, 'secrets'])
    secret = 'my-secret-here'
    if suffix:
        secret = '-'.join([secret, suffix])

    # POST metadata:
    payload = {
        'payload': secret,
        'payload_content_type': 'text/plain'
    }
    pr = requests.post(ep_1step, data=json.dumps(payload), headers=hdrs)
    pr_j = pr.json()
    secret_ref = pr.json().get('secret_ref')

    # GET secret:
    hdrs_get = dict(hdrs)
    hdrs_get.update({
        'accept': 'text/plain'})
    gr = requests.get(secret_ref, headers=hdrs_get)
    if not suppress:
        LOG.info('Get secret 1-step (text): {0}\n'.format(gr.content))

    return secret_ref


def demo_store_secret_two_step_binary():
    """Store secret (2-step):"""
    secret = 'bXktc2VjcmV0LWhlcmU='  # base64 of 'my secret'
    ep_2step = '/'.join([end_point, version, 'secrets'])

    # POST metadata:
    payload = {}
    pr = requests.post(ep_2step, data=json.dumps(payload), headers=hdrs)
    pr_j = pr.json()
    secret_ref = pr_j.get('secret_ref')
    assert secret_ref

    # PUT data to store:
    hdrs_put = dict(hdrs)
    hdrs_put.update({
        'content-type': 'application/octet-stream',
        'content-encoding': 'base64'}
    )
    requests.put(secret_ref, data=secret, headers=hdrs_put)

    # GET secret:
    hdrs_get = dict(hdrs)
    hdrs_get.update({
        'accept': 'application/octet-stream'})
    gr = requests.get(secret_ref, headers=hdrs_get)
    LOG.info('Get secret 2-step (binary): {0}\n'.format(gr.content))

    return secret_ref


def demo_retrieve_secret_list():
    ep_list = '/'.join([end_point, version, 'secrets'])

    hdrs_get = dict(hdrs)
    gr = requests.get(ep_list, headers=hdrs_get)
    gr_j = gr.json()
    LOG.info('Get secret list:')
    for secret_info in gr_j.get('secrets'):
        LOG.info('    {0}'.format(secret_info.get('secret_ref')))
    LOG.info('\n')


def demo_store_container_rsa(suffix=None):
    """Store secret (2-step):"""
    ep_cont = '/'.join([end_point, version, 'containers'])
    secret_prk = demo_store_secret_one_step_text(suffix=suffix, suppress=True)
    secret_puk = demo_store_secret_one_step_text(suffix=suffix, suppress=True)
    secret_pp = demo_store_secret_one_step_text(suffix=suffix, suppress=True)

    # POST metadata:
    payload = {
        "name": "container name",
        "type": "rsa",
        "secret_refs": [{
            "name": "private_key",
            "secret_ref": secret_prk
        },
        {
            "name": "public_key",
            "secret_ref": secret_puk
        },
        {
            "name": "private_key_passphrase",
            "secret_ref": secret_pp
        }]
    }
    pr = requests.post(ep_cont, data=json.dumps(payload), headers=hdrs)
    pr_j = pr.json()
    container_ref = pr.json().get('container_ref')

    # GET container:
    hdrs_get = dict(hdrs)
    gr = requests.get(container_ref, headers=hdrs_get)
    LOG.info('Get RSA container: {0}\n'.format(gr.content))

    return container_ref


def demo_retrieve_container_list():
    ep_list = '/'.join([end_point, version, 'containers'])

    hdrs_get = dict(hdrs)
    gr = requests.get(ep_list, headers=hdrs_get)
    gr_j = gr.json()
    LOG.info('Get container list:')
    for secret_info in gr_j.get('containers'):
        LOG.info('    {0}'.format(secret_info.get('container_ref')))
    LOG.info('\n')


def demo_delete_secret(secret_ref):
    """Delete secret by its HATEOAS reference"""
    ep_delete = secret_ref

    # DELETE secret:
    dr = requests.delete(ep_delete, headers=hdrs)
    gr = requests.get(secret_ref, headers=hdrs)
    assert(404 == gr.status_code)
    LOG.info('...Deleted Secret: {0}\n'.format(secret_ref))


def demo_delete_container(container_ref):
    """Delete container by its HATEOAS reference"""
    ep_delete = container_ref

    # DELETE container:
    dr = requests.delete(ep_delete, headers=hdrs)
    gr = requests.get(container_ref, headers=hdrs)
    assert(404 == gr.status_code)
    LOG.info('...Deleted Container: {0}\n'.format(container_ref))


def demo_consumers_add(container_ref):
    """Add consumer to a container:"""
    ep_add = '/'.join([container_ref, 'consumers'])

    # POST metadata:
    pr = requests.post(ep_add, data=json.dumps(payload_consumer), headers=hdrs)
    pr_consumers = pr.json().get('consumers')
    assert pr_consumers
    assert(len(pr_consumers) == 1)
    LOG.info('...Consumer response: {0}'.format(pr_consumers))


def demo_consumers_delete(container_ref):
    """Delete consumer from a container:"""
    ep_delete = '/'.join([container_ref, 'consumers'])

    # POST metadata:
    pr = requests.delete(
        ep_delete, data=json.dumps(payload_consumer), headers=hdrs)
    pr_consumers = pr.json().get('consumers')
    assert(not pr_consumers)
    LOG.info('...Deleted Consumer from: {0}'.format(container_ref))


if __name__ == '__main__':
    demo_version()

    # Demonstrate secret actions:
    secret_ref = demo_store_secret_one_step_text()
    secret_ref2 = demo_store_secret_two_step_binary()

    demo_retrieve_secret_list()

    demo_delete_secret(secret_ref)
    demo_delete_secret(secret_ref2)

    # Demonstrate container and consumer actions:
    container_ref = demo_store_container_rsa(suffix='1')
    container_ref2 = demo_store_container_rsa(suffix='2')

    demo_retrieve_container_list()

    demo_consumers_add(container_ref)
    demo_consumers_add(container_ref)  # Should be idempotent
    demo_consumers_delete(container_ref)
    demo_consumers_add(container_ref)

    demo_delete_container(container_ref)
    demo_delete_container(container_ref2)
