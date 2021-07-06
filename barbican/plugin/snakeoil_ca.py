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
import datetime
import fnmatch
import os
import re
import subprocess  # nosec
from tempfile import mkstemp
import uuid

from OpenSSL import crypto
from oslo_config import cfg
from oslo_utils import uuidutils

from barbican.common import config
from barbican.common import utils
from barbican import i18n as u
import barbican.plugin.interface.certificate_manager as cert_manager

CONF = config.new_config()
LOG = utils.getLogger(__name__)


snakeoil_ca_plugin_group = cfg.OptGroup(name='snakeoil_ca_plugin',
                                        title="Snakeoil CA Plugin Options")

snakeoil_ca_plugin_opts = [
    cfg.StrOpt('ca_cert_path',
               help=u._('Path to CA certificate file')),
    cfg.StrOpt('ca_cert_key_path',
               help=u._('Path to CA certificate key file')),
    cfg.StrOpt('ca_cert_chain_path',
               help=u._('Path to CA certificate chain file')),
    cfg.StrOpt('ca_cert_pkcs7_path',
               help=u._('Path to CA chain pkcs7 file')),
    cfg.StrOpt('subca_cert_key_directory',
               default='/etc/barbican/snakeoil-cas',
               help=u._('Directory in which to store certs/keys for subcas')),
]

CONF.register_group(snakeoil_ca_plugin_group)
CONF.register_opts(snakeoil_ca_plugin_opts, group=snakeoil_ca_plugin_group)
config.parse_args(CONF)


def list_opts():
    yield snakeoil_ca_plugin_group, snakeoil_ca_plugin_opts


def set_subject_X509Name(target, dn):
    """Set target X509Name object with parsed dn.

    This is very basic and should certainly be replaced by something using
    cryptography for instance, but will do for a basic test CA
    """

    # TODO(alee) Figure out why C (country) is not working
    fields = dn.split(',')
    for field in fields:
        m = re.search(r"(\w+)\s*=\s*(.+)", field.strip())
        name = m.group(1)
        value = m.group(2)
        if name.lower() == 'ou':
            target.OU = value
        elif name.lower() == 'st':
            target.ST = value
        elif name.lower() == 'cn':
            target.CN = value
        elif name.lower() == 'l':
            target.L = value
        elif name.lower() == 'o':
            target.O = value  # noqa: E741
    return target


class SnakeoilCA(object):

    def __init__(self, cert_path=None, key_path=None, chain_path=None,
                 pkcs7_path=None, name=None, serial=1,
                 key_size=2048, expiry_days=10 * 365, x509_version=2,
                 subject_dn=None, signing_dn=None, signing_key=None,
                 parent_chain_path=None):
        self.cert_path = cert_path
        self.key_path = key_path
        self.chain_path = chain_path
        self.pkcs7_path = pkcs7_path
        self.name = name
        self.serial = serial
        self.key_size = key_size
        self.expiry_days = expiry_days
        self.x509_version = x509_version

        self.subject_dn = subject_dn

        if signing_dn is not None:
            self.signing_dn = signing_dn
        else:
            self.signing_dn = subject_dn    # self-signed

        self.signing_key = signing_key
        self.parent_chain_path = parent_chain_path

        self._cert_val = None
        self._key_val = None
        self._chain_val = None
        self._pkcs7_val = None

    @property
    def cert(self):
        self.ensure_exists()
        if self.cert_path:
            with open(self.cert_path, 'rb') as cert_fh:
                return crypto.load_certificate(crypto.FILETYPE_PEM,
                                               cert_fh.read())
        else:
            return crypto.load_certificate(crypto.FILETYPE_PEM, self._cert_val)

    @cert.setter
    def cert(self, val):
        if self.cert_path:
            with open(self.cert_path, 'wb') as cert_fh:
                cert_fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                      val))
        else:
            self._cert_val = crypto.dump_certificate(crypto.FILETYPE_PEM, val)

    @property
    def key(self):
        self.ensure_exists()
        if self.key_path:
            with open(self.key_path, 'rb') as key_fh:
                return crypto.load_privatekey(crypto.FILETYPE_PEM,
                                              key_fh.read())
        else:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, self._key_val)

    @key.setter
    def key(self, val):
        if self.key_path:
            with open(self.key_path, 'wb') as key_fh:
                key_fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, val))
        else:
            self._key_val = crypto.dump_privatekey(crypto.FILETYPE_PEM, val)

    @property
    def chain(self):
        self.ensure_exists()
        if self.chain_path:
            with open(self.chain_path, 'rb') as chain_fh:
                return chain_fh.read()
        else:
            return self._chain_val

    @chain.setter
    def chain(self, val):
        if self.chain_path:
            with open(self.chain_path, 'wb') as chain_fh:
                chain_fh.write(val)
        else:
            self._chain_val = val

    @property
    def pkcs7(self):
        self.ensure_exists()
        if self.pkcs7_path:
            with open(self.pkcs7_path, 'rb') as pkcs7_fh:
                return pkcs7_fh.read()
        else:
            return self._pkcs7_val

    @pkcs7.setter
    def pkcs7(self, val):
        if self.pkcs7_path:
            with open(self.pkcs7_path, 'wb') as pkcs7_fh:
                pkcs7_fh.write(val)
        else:
            self._pkcs7_val = val

    @property
    def exists(self):
        if self.cert_path is not None:
            cert_exists = os.path.isfile(self.cert_path)
        else:
            cert_exists = self._cert_val is not None

        if self.key_path is not None:
            key_exists = os.path.isfile(self.key_path)
        else:
            key_exists = self._key_val is not None

        if self.chain_path is not None:
            chain_exists = os.path.isfile(self.chain_path)
        else:
            chain_exists = self._chain_val is not None

        if self.pkcs7_path is not None:
            pkcs7_exists = os.path.isfile(self.pkcs7_path)
        else:
            pkcs7_exists = self._pkcs7_val is not None

        return (cert_exists and key_exists and
                pkcs7_exists and chain_exists)

    def ensure_exists(self):
        if not self.exists:
            LOG.debug('Keypair not found, creating new cert/key')
            self.cert, self.key, self.chain, self.pkcs7 = (
                self.create_keypair())

    def create_keypair(self):
        LOG.debug('Generating Snakeoil CA')
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, self.key_size)

        cert = crypto.X509()
        cert.set_version(self.x509_version)
        cert.set_serial_number(self.serial)
        subject = cert.get_subject()
        set_subject_X509Name(subject, self.subject_dn)
        cert.set_subject(subject)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.expiry_days)
        cert.set_issuer(set_subject_X509Name(
            cert.get_issuer(), self.signing_dn))
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True,
                                 b"CA:TRUE, pathlen:5"),
        ])
        if not self.signing_key:
            self.signing_key = key  # self-signed

        cert.sign(self.signing_key, 'sha256')

        LOG.debug('Snakeoil CA cert/key generated')

        chain = b''
        if self.parent_chain_path:
            with open(self.parent_chain_path, 'rb') as fh:
                chain = fh.read()
        chain += crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

        pkcs7 = self._generate_pkcs7(chain)
        return cert, key, chain, pkcs7

    def _generate_pkcs7(self, chain):
        fin, temp_in = mkstemp()
        os.write(fin, chain)
        os.close(fin)

        fout, temp_out = mkstemp()
        os.close(fout)

        subprocess.call(['/usr/bin/openssl', 'crl2pkcs7', '-nocrl',  # nosec
                         '-out', temp_out, '-certfile', temp_in], shell=False)
        with open(temp_out, 'rb') as pkcs7_fh:
            pkcs7 = pkcs7_fh.read()

        os.remove(temp_in)
        os.remove(temp_out)
        return pkcs7


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
        self.cas = {}
        self.ca = SnakeoilCA(
            cert_path=conf.snakeoil_ca_plugin.ca_cert_path,
            key_path=conf.snakeoil_ca_plugin.ca_cert_key_path,
            chain_path=conf.snakeoil_ca_plugin.ca_cert_chain_path,
            pkcs7_path=conf.snakeoil_ca_plugin.ca_cert_pkcs7_path,
            name=self.get_default_ca_name(),
            subject_dn="cn=Snakeoil Certificate,o=example.com"
        )

        self.cas[self.get_default_ca_name()] = self.ca

        self.subca_directory = conf.snakeoil_ca_plugin.subca_cert_key_directory
        if self.subca_directory:
            if not os.path.exists(self.subca_directory):
                os.makedirs(self.subca_directory)    # pragma: no cover
            else:
                self._reload_previously_created_subcas()

        self.cert_manager = CertManager(self.ca)

    def _reload_previously_created_subcas(self):
        for file in os.listdir(self.subca_directory):
            if fnmatch.fnmatch(file, '*.key'):
                ca_id, _ext = os.path.splitext(file)
                self.cas[ca_id] = SnakeoilCA(
                    cert_path=os.path.join(self.subca_directory,
                                           ca_id + ".cert"),
                    key_path=os.path.join(self.subca_directory, file),
                    chain_path=os.path.join(self.subca_directory,
                                            ca_id + ".chain"),
                    pkcs7_path=os.path.join(self.subca_directory,
                                            ca_id + ".p7b")
                )

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
                encoded_csr = base64.b64decode(order_meta['request_data'])
            except KeyError:
                return cert_manager.ResultDTO(
                    cert_manager.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                    status_message=u._("No request_data specified"))
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, encoded_csr)

        ca_id = barbican_meta_dto.plugin_ca_id
        if ca_id:
            ca = self.cas.get(ca_id)
            if ca is None:
                raise cert_manager.CertificateGeneralException(
                    "Invalid ca_id passed into snake oil plugin:" + ca_id)
        else:
            ca = self.ca

        cert_mgr = CertManager(ca)
        cert = cert_mgr.make_certificate(csr)
        cert_enc = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

        return cert_manager.ResultDTO(
            cert_manager.CertificateStatus.CERTIFICATE_GENERATED,
            certificate=base64.b64encode(cert_enc),
            intermediates=base64.b64encode(ca.pkcs7))

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

    def supports_create_ca(self):
        return True

    def create_ca(self, ca_create_dto):
        # get the parent CA from the ca list, return error if not on list
        parent_ca_id = ca_create_dto.parent_ca_id
        if not parent_ca_id:
            raise cert_manager.CertificateGeneralException(
                "No parent id passed to snake oil plugin on create_ca")

        parent_ca = self.cas.get(parent_ca_id)
        if not parent_ca:
            raise cert_manager.CertificateGeneralException(
                "Invalid parent id passed to snake oil plugin:" + parent_ca_id)

        # create a new ca, passing in key and issuer from the parent
        new_ca_id = uuidutils.generate_uuid()
        new_cert_path = os.path.join(self.subca_directory, new_ca_id + ".cert")
        new_key_path = os.path.join(self.subca_directory, new_ca_id + ".key")
        new_chain_path = os.path.join(self.subca_directory,
                                      new_ca_id + ".chain")
        new_pkcs7_path = os.path.join(self.subca_directory,
                                      new_ca_id + ".p7b")
        parent_chain_path = parent_ca.chain_path

        new_ca = SnakeoilCA(cert_path=new_cert_path,
                            key_path=new_key_path,
                            chain_path=new_chain_path,
                            pkcs7_path=new_pkcs7_path,
                            name=ca_create_dto.name,
                            subject_dn=ca_create_dto.subject_dn,
                            signing_dn=parent_ca.subject_dn,
                            signing_key=parent_ca.key,
                            parent_chain_path=parent_chain_path)

        self.cas[new_ca_id] = new_ca

        expiration = (datetime.datetime.utcnow() + datetime.timedelta(
            days=cert_manager.CA_INFO_DEFAULT_EXPIRATION_DAYS))

        return {
            cert_manager.INFO_NAME: new_ca.name,
            cert_manager.INFO_CA_SIGNING_CERT: crypto.dump_certificate(
                crypto.FILETYPE_PEM, new_ca.cert),
            cert_manager.INFO_EXPIRATION: expiration.isoformat(),
            cert_manager.INFO_INTERMEDIATES: new_ca.pkcs7,
            cert_manager.PLUGIN_CA_ID: new_ca_id
        }

    def get_ca_info(self):
        expiration = (datetime.datetime.utcnow() + datetime.timedelta(
            days=cert_manager.CA_INFO_DEFAULT_EXPIRATION_DAYS))

        ret = {}
        for ca_id, ca in self.cas.items():
            ca_info = {
                cert_manager.INFO_NAME: ca.name,
                cert_manager.INFO_CA_SIGNING_CERT: crypto.dump_certificate(
                    crypto.FILETYPE_PEM, ca.cert),
                cert_manager.INFO_INTERMEDIATES: ca.pkcs7,
                cert_manager.INFO_EXPIRATION: expiration.isoformat()
            }
            ret[ca_id] = ca_info

        return ret

    def delete_ca(self, ca_id):
        self.cas.pop(ca_id)

        ca_files = [os.path.join(self.subca_directory, ca_id + ".cert"),
                    os.path.join(self.subca_directory, ca_id + ".key"),
                    os.path.join(self.subca_directory, ca_id + ".chain"),
                    os.path.join(self.subca_directory, ca_id + ".p7b")]

        for ca_file in ca_files:
            if os.path.exists(ca_file):
                os.remove(ca_file)
