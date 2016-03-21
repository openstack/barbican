"""
Copyright 2015 Rackspace

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

from oslo_config import cfg

TEST_CONF = None


def setup_config(config_file=''):
    global TEST_CONF
    TEST_CONF = cfg.ConfigOpts()

    identity_group = cfg.OptGroup(name='identity')
    identity_options = [
        cfg.StrOpt('uri', default='http://localhost:5000/v3'),
        cfg.StrOpt('version', default='v3'),
        cfg.StrOpt('username', default='admin'),
        cfg.StrOpt('password', default='secretadmin', secret=True),
        cfg.StrOpt('project_name', default='admin'),
        cfg.StrOpt('domain_name', default='Default'),
        cfg.StrOpt('region', default='RegionOne'),
        cfg.StrOpt('service_admin', default='service-admin'),
        cfg.StrOpt('service_admin_project', default='service'),
        cfg.StrOpt('service_admin_password', default='secretservice',
                   secret=True)]
    TEST_CONF.register_group(identity_group)
    TEST_CONF.register_opts(identity_options, group=identity_group)

    rbac_users_group = cfg.OptGroup(name='rbac_users')
    rbac_users_options = [
        cfg.StrOpt('project_a', default='project_a'),
        cfg.StrOpt('project_b', default='project_b'),
        cfg.StrOpt('admin_a', default='project_a_admin'),
        cfg.StrOpt('admin_a_password', default='barbican', secret=True),
        cfg.StrOpt('creator_a', default='project_a_creator'),
        cfg.StrOpt('creator_a_password', default='barbican', secret=True),
        cfg.StrOpt('observer_a', default='project_a_observer'),
        cfg.StrOpt('observer_a_password', default='barbican', secret=True),
        cfg.StrOpt('auditor_a', default='project_a_auditor'),
        cfg.StrOpt('auditor_a_password', default='barbican', secret=True),
        cfg.StrOpt('admin_b', default='project_b_admin'),
        cfg.StrOpt('admin_b_password', default='barbican', secret=True),
        cfg.StrOpt('creator_b', default='project_b_creator'),
        cfg.StrOpt('creator_b_password', default='barbican', secret=True),
        cfg.StrOpt('observer_b', default='project_b_observer'),
        cfg.StrOpt('observer_b_password', default='barbican', secret=True),
        cfg.StrOpt('auditor_b', default='project_b_auditor'),
        cfg.StrOpt('auditor_b_password', default='barbican', secret=True),
    ]
    TEST_CONF.register_group(rbac_users_group)
    TEST_CONF.register_opts(rbac_users_options, group=rbac_users_group)

    keymanager_group = cfg.OptGroup(name='keymanager')
    keymanager_options = [
        cfg.StrOpt('service_type', default='key-manager'),
        cfg.StrOpt('service_name', default='barbican'),
        cfg.StrOpt('region_name', default='RegionOne'),
        cfg.StrOpt('endpoint_type', default='public'),
        cfg.IntOpt('timeout', default=10),
        cfg.StrOpt('override_url', default=''),
        cfg.StrOpt('override_url_version', default='')
    ]
    TEST_CONF.register_group(keymanager_group)
    TEST_CONF.register_opts(keymanager_options, group=keymanager_group)

    quotas_group = cfg.OptGroup(name='quotas')
    quotas_options = [
        cfg.IntOpt('quota_secrets', default=-1),
        cfg.IntOpt('quota_orders', default=-1),
        cfg.IntOpt('quota_containers', default=-1),
        cfg.IntOpt('quota_consumers', default=-1),
        cfg.IntOpt('quota_cas', default=-1)
    ]
    TEST_CONF.register_group(quotas_group)
    TEST_CONF.register_opts(quotas_options, group=quotas_group)

    # Figure out which config to load
    config_to_load = []
    local_config = './etc/barbican/barbican-functional.conf'
    if os.path.isfile(config_file):
        config_to_load.append(config_file)
    elif os.path.isfile(local_config):
        config_to_load.append(local_config)
    else:
        config_to_load.append('/etc/barbican/barbican-functional.conf')

    # Actually parse config
    TEST_CONF(
        (),  # Required to load a anonymous config
        default_config_files=config_to_load
    )


def get_config():
    if not TEST_CONF:
        setup_config()
    return TEST_CONF
