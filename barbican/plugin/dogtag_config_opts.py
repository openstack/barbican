# Copyright (c) 2014 Red Hat, Inc.
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

from oslo_config import cfg

from barbican.common import config
from barbican import i18n as u

import barbican.plugin.interface.certificate_manager as cm

CONF = config.new_config()

dogtag_plugin_group = cfg.OptGroup(name='dogtag_plugin',
                                   title="Dogtag Plugin Options")
dogtag_plugin_opts = [
    cfg.StrOpt('pem_path',
               default='/etc/barbican/kra_admin_cert.pem',
               help=u._('Path to PEM file for authentication')),
    cfg.StrOpt('dogtag_host',
               default="localhost",
               help=u._('Hostname for the Dogtag instance')),
    cfg.PortOpt('dogtag_port',
                default=8443,
                help=u._('Port for the Dogtag instance')),
    cfg.StrOpt('nss_db_path',
               default='/etc/barbican/alias',
               help=u._('Path to the NSS certificate database')),
    cfg.StrOpt('nss_password',
               help=u._('Password for the NSS certificate databases'),
               secret=True),
    cfg.StrOpt('simple_cmc_profile',
               default='caOtherCert',
               help=u._('Profile for simple CMC requests')),
    cfg.StrOpt('auto_approved_profiles',
               default="caServerCert",
               help=u._('List of automatically approved enrollment profiles')),
    cfg.IntOpt('ca_expiration_time',
               default=cm.CA_INFO_DEFAULT_EXPIRATION_DAYS,
               help=u._('Time in days for CA entries to expire')),
    cfg.StrOpt('plugin_working_dir',
               default='/etc/barbican/dogtag',
               help=u._('Working directory for Dogtag plugin')),
    cfg.StrOpt('plugin_name',
               help=u._('User friendly plugin name'),
               default='Dogtag KRA'),
    cfg.IntOpt('retries',
               help=u._('Retries when storing or generating secrets'),
               default=3)
]

CONF.register_group(dogtag_plugin_group)
CONF.register_opts(dogtag_plugin_opts, group=dogtag_plugin_group)
config.parse_args(CONF)


def list_opts():
    yield dogtag_plugin_group, dogtag_plugin_opts
