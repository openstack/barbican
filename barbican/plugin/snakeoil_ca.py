# Copyright 2014 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import os
import uuid

from OpenSSL import crypto
from oslo_config import cfg

from barbican.common import config
from barbican.common import utils
from barbican.openstack.common import gettextutils as u
import barbican.plugin.interface.certificate_manager as cert_manager

CONF = config.new_config()
LOG = utils.getLogger(__name__)


snakeoil_ca_plugin_group = cfg.OptGroup(name='snakeoil_ca_plugin',
                                        title="Snakeoil CA Plugin Options")

snakeoil_ca_plugin_opts = [
    cfg.StrOpt('ca_cert_path',
               help=u._('Path to CA certicate file')),
    cfg.StrOpt('ca_cert_key_path',
               help=u._('Path to CA certificate key file')),
]

CONF.register_group(snakeoil_ca_plugin_group)
CONF.register_opts(snakeoil_ca_plugin_opts, group=snakeoil_ca_plugin_group)
config.parse_args(CONF)


class SnakeoilCA(object):

    def __init__(self, cert_path=None, key_path=None, serial=1,
                 key_size=2048, expiry_days=10 * 365, x509_version=2,
                 subject_c='XX', subject_st='Unset', subject_l='Unset',
                 subject_o='Unset', subject_cn='Snakeoil Certificate'):
        self.cert_path = cert_path
        self.key_path = key_path
        self.serial = serial
        self.key_size = key_size
        self.expiry_days = expiry_days
        self.x509_version = x509_version

        self.subject_c = subject_c
        self.subject_st = subject_st
        self.subject_l = subject_l
        self.subject_o = subject_o
        self.subject_cn = subject_cn

        self._cert_val = None
        self._key_val = None

    @property
    def cert(self):
        self.ensure_exists()
        if self.cert_path:
            with open(self.cert_path) as cert_fh:
                return crypto.load_certificate(crypto.FILETYPE_PEM,
                                               cert_fh.read())
        else:
            return crypto.load_certificate(crypto.FILETYPE_PEM, self._cert_val)

    @cert.setter
    def cert(self, val):
        if self.cert_path:
            with open(self.cert_path, 'w') as cert_fh:
                cert_fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                      val))
        else:
            self._cert_val = crypto.dump_certificate(crypto.FILETYPE_PEM, val)

    @property
    def key(self):
        self.ensure_exists()
        if self.key_path:
            with open(self.key_path) as key_fh:
                return crypto.load_privatekey(crypto.FILETYPE_PEM,
                                              key_fh.read())
        else:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, self._key_val)

    @key.setter
    def key(self, val):
        if self.key_path:
            with open(self.key_path, 'w') as key_fh:
                key_fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, val))
        else:
            self._key_val = crypto.dump_privatekey(crypto.FILETYPE_PEM, val)

    @property
    def exists(self):
        cert_exists = self._cert_val is not None
        key_exists = self._key_val is not None

        if self.cert_path is not None:
            cert_exists = os.path.isfile(self.cert_path)

        if self.key_path is not None:
            key_exists = os.path.isfile(self.key_path)

        return cert_exists and key_exists

    def set_subject(self, subject):
        subject.C = self.subject_c
        subject.ST = self.subject_st
        subject.L = self.subject_l
        subject.O = self.subject_o
        subject.CN = self.subject_cn

    def ensure_exists(self):
        if not self.exists:
            LOG.debug('Keypair not found, creating new cert/key')
            self.cert, self.key = self.create_keypair()

    def create_keypair(self, **subject_params):
        LOG.debug('Generating Snakeoil CA')
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, self.key_size)

        cert = crypto.X509()
        cert.set_version(self.x509_version)
        cert.set_serial_number(self.serial)
        subject = cert.get_subject()
        self.set_subject(subject)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.expiry_days)
        cert.set_issuer(subject)
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True,
                                 b"CA:TRUE, pathlen:0"),
        ])
        cert.sign(key, 'sha256')
        LOG.debug('Snakeoil CA cert/key generated')

        return cert, key


class CertManager(object):

    def __init__(self, ca):
        self.ca = ca

    def get_new_serial(self):
        return uuid.uuid4().int

    def make_certificate(self, csr, expires=2 * 365):
        cert = crypto.X509()
        cert.set_serial_number(self.get_new_serial())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(expires)
        cert.set_issuer(self.ca.cert.get_subject())
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.sign(self.ca.key, 'sha256')
        return cert


class SnakeoilCACertificatePlugin(cert_manager.CertificatePluginBase):
    """Snakeoil CA certificate plugin.

    This is used for easily generating certificates which are not useful in a
    production environment.
    """

    def __init__(self, conf=CONF):
        self.ca = SnakeoilCA(conf.snakeoil_ca_plugin.ca_cert_path,
                             conf.snakeoil_ca_plugin.ca_cert_key_path)
        self.cert_manager = CertManager(self.ca)

    def get_default_ca_name(self):
        return "Snakeoil CA"

    def get_default_signing_cert(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self.ca.cert)

    def get_default_intermediates(self):
        return None

    def supported_request_types(self):
        return [cert_manager.CertificateRequestType.CUSTOM_REQUEST,
                cert_manager.CertificateRequestType.STORED_KEY_REQUEST]

    def issue_certificate_request(self, order_id, order_meta, plugin_meta,
                                  barbican_meta_dto):
        if barbican_meta_dto.generated_csr is not None:
            encoded_csr = barbican_meta_dto.generated_csr
        else:
            try:
                encoded_csr = order_meta['request_data']
            except KeyError:
                return cert_manager.ResultDTO(
                    cert_manager.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                    status_message="No request_data specified")
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, encoded_csr)
        cert = self.cert_manager.make_certificate(csr)
        cert_enc = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        ca_enc = crypto.dump_certificate(crypto.FILETYPE_PEM, self.ca.cert)

        return cert_manager.ResultDTO(
            cert_manager.CertificateStatus.CERTIFICATE_GENERATED,
            certificate=base64.b64encode(cert_enc),
            intermediates=base64.b64encode(ca_enc))

    def modify_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        raise NotImplementedError

    def cancel_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        raise NotImplementedError

    def check_certificate_status(self, order_id, order_meta, plugin_meta,
                                 barbican_meta_dto):
        raise NotImplementedError

    def supports(self, certificate_spec):
        request_type = certificate_spec.get(
            cert_manager.REQUEST_TYPE,
            cert_manager.CertificateRequestType.CUSTOM_REQUEST)
        return request_type in self.supported_request_types()
