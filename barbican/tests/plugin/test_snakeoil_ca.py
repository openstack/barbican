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

from Crypto.Util import asn1
import fixtures
import mock
from OpenSSL import crypto
from oslo_config import fixture as oslo_fixture

import barbican.plugin.interface.certificate_manager as cm
from barbican.plugin import snakeoil_ca
from barbican.tests import certificate_utils
from barbican.tests import utils


class BaseTestCase(utils.BaseTestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.conf = self.useFixture(oslo_fixture.Config(
            conf=snakeoil_ca.CONF)).conf
        self.tmp_dir = self.useFixture(fixtures.TempDir()).path

    def tearDown(self):
        super(BaseTestCase, self).tearDown()


class CaTestCase(BaseTestCase):

    def test_gen_cacert_no_file_storage(self):
        subject_dn = (
            'cn=Test CN,o=Test O,L=Test L,st=Test ST,ou=Test OU'
        )
        ca = snakeoil_ca.SnakeoilCA(cert_path=None, key_path=None,
                                    key_size=512, subject_dn=subject_dn)
        subject = ca.cert.get_subject()
        self.assertNotEqual(ca.key, None)
        self.assertEqual("Test ST", subject.ST)
        self.assertEqual("Test L", subject.L)
        self.assertEqual("Test O", subject.O)
        self.assertEqual("Test CN", subject.CN)
        self.assertEqual("Test OU", subject.OU)
        self.assertEqual(
            ca.chain,
            crypto.dump_certificate(crypto.FILETYPE_PEM, ca.cert))

    def test_gen_cacert_with_file_storage(self):
        cert_path = self.tmp_dir + 'cert.pem'
        key_path = self.tmp_dir + 'key.pem'
        chain_path = self.tmp_dir + 'cert.chain'
        pkcs7_path = self.tmp_dir + 'cert.p7b'

        subject_dn = 'cn=Test CN,o=Test O,L=Test L,st=Test ST'
        ca = snakeoil_ca.SnakeoilCA(
            cert_path=cert_path,
            key_path=key_path,
            chain_path=chain_path,
            pkcs7_path=pkcs7_path,
            key_size=2048,
            subject_dn=subject_dn)

        subject = ca.cert.get_subject()
        self.assertEqual(
            ca.chain,
            crypto.dump_certificate(crypto.FILETYPE_PEM, ca.cert))
        self.assertNotEqual(None, ca.key)
        self.assertEqual("Test ST", subject.ST)
        self.assertEqual("Test L", subject.L)
        self.assertEqual("Test O", subject.O)
        self.assertEqual("Test CN", subject.CN)

        # Make sure we preserve existing keypairs
        ca = snakeoil_ca.SnakeoilCA(
            cert_path=cert_path,
            key_path=key_path,
            chain_path=chain_path,
            pkcs7_path=pkcs7_path
        )
        subject = ca.cert.get_subject()
        self.assertEqual("Test ST", subject.ST)
        self.assertEqual("Test L", subject.L)
        self.assertEqual("Test O", subject.O)
        self.assertEqual("Test CN", subject.CN)

    def test_gen_sub_cacert_with_file_storage(self):
        cert_path = self.tmp_dir + 'cert.pem'
        key_path = self.tmp_dir + 'key.pem'
        chain_path = self.tmp_dir + 'cert.chain'
        pkcs7_path = self.tmp_dir + 'cert.p7b'

        subject_dn = 'cn=Test CN,o=Test O,L=Test L,st=Test ST'
        parent_ca = snakeoil_ca.SnakeoilCA(
            cert_path=cert_path,
            key_path=key_path,
            chain_path=chain_path,
            pkcs7_path=pkcs7_path,
            key_size=2048,
            subject_dn=subject_dn)
        self.assertIsNotNone(parent_ca)

        # create a sub-ca
        subject_dn = 'cn=Sub CA Test CN,o=Test O,L=Test L,st=Test ST'
        cert_path = self.tmp_dir + 'sub_cert.pem'
        key_path = self.tmp_dir + 'sub_key.pem'
        chain_path = self.tmp_dir + 'sub_cert.chain'
        pkcs7_path = self.tmp_dir + 'sub_cert.p7b'

        sub_ca = snakeoil_ca.SnakeoilCA(
            cert_path=cert_path,
            key_path=key_path,
            chain_path=chain_path,
            pkcs7_path=pkcs7_path,
            key_size=2048,
            subject_dn=subject_dn,
            parent_chain_path=parent_ca.chain_path,
            signing_dn=parent_ca.subject_dn,
            signing_key=parent_ca.key
        )

        subject = sub_ca.cert.get_subject()
        self.assertEqual("Test ST", subject.ST)
        self.assertEqual("Test L", subject.L)
        self.assertEqual("Test O", subject.O)
        self.assertEqual("Sub CA Test CN", subject.CN)


class CertManagerTestCase(BaseTestCase):

    def setUp(self):
        super(CertManagerTestCase, self).setUp()
        subject_dn = 'cn=Test CN,o=Test O,L=Test L,st=Test ST'
        self.ca = snakeoil_ca.SnakeoilCA(cert_path=None, key_path=None,
                                         key_size=512, subject_dn=subject_dn)

    def verify_sig(self, encoded_cert):
        der = asn1.DerSequence()
        der.decode(encoded_cert)
        der_sig = asn1.DerObject()
        der_sig.decode(der[2])
        sig = der_sig.payload
        self.assertIs('\x00', sig[0])
        crypto.verify(self.ca.cert, sig[1:], der[0], 'sha256')

    def test_gen_cert_no_file_storage(self):
        req = certificate_utils.get_valid_csr_object()

        cm = snakeoil_ca.CertManager(self.ca)
        cert = cm.make_certificate(req)
        first_serial = cert.get_serial_number()
        cert_enc = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        self.verify_sig(cert_enc)

        cert = cm.make_certificate(req)
        self.assertNotEqual(first_serial, cert.get_serial_number())
        self.verify_sig(cert_enc)

        cm = snakeoil_ca.CertManager(self.ca)
        cert = cm.make_certificate(req)

    def test_gen_cert_with_file_storage(self):
        req = certificate_utils.get_valid_csr_object()

        cm = snakeoil_ca.CertManager(self.ca)
        cert = cm.make_certificate(req)
        cert_enc = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        first_serial = cert.get_serial_number()
        self.verify_sig(cert_enc)

        cm = snakeoil_ca.CertManager(self.ca)
        cert = cm.make_certificate(req)
        self.assertNotEqual(first_serial, cert.get_serial_number())


class SnakeoilCAPluginTestCase(BaseTestCase):

    def setUp(self):
        super(SnakeoilCAPluginTestCase, self).setUp()
        self.ca_cert_path = os.path.join(self.tmp_dir, 'ca.cert')
        self.ca_key_path = os.path.join(self.tmp_dir, 'ca.key')
        self.ca_chain_path = os.path.join(self.tmp_dir, 'ca.chain')
        self.ca_pkcs7_path = os.path.join(self.tmp_dir, 'ca.pkcs7')
        self.db_dir = self.tmp_dir

        self.conf.snakeoil_ca_plugin.subca_cert_key_directory = os.path.join(
            self.tmp_dir, 'subca_cert_key_dir')
        self.subca_cert_key_directory = (
            self.conf.snakeoil_ca_plugin.subca_cert_key_directory)

        self.plugin = snakeoil_ca.SnakeoilCACertificatePlugin(
            self.conf)
        self.order_id = mock.MagicMock()
        self.barbican_meta_dto = cm.BarbicanMetaDTO()

    def test_issue_certificate_request(self):
        req = certificate_utils.get_valid_csr_object()

        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        req_enc = base64.b64encode(req_enc)
        order_meta = {'request_data': req_enc}
        resp = self.plugin.issue_certificate_request(self.order_id,
                                                     order_meta, {},
                                                     self.barbican_meta_dto)
        crypto.load_certificate(
            crypto.FILETYPE_PEM, resp.certificate.decode('base64'))

    def test_issue_certificate_request_with_ca_id(self):
        req = certificate_utils.get_valid_csr_object()

        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        req_enc = base64.b64encode(req_enc)
        order_meta = {'request_data': req_enc}
        plugin_meta = {'plugin_ca_id': self.plugin.get_default_ca_name()}
        self.barbican_meta_dto.plugin_ca_id = self.plugin.get_default_ca_name()
        resp = self.plugin.issue_certificate_request(self.order_id,
                                                     order_meta,
                                                     plugin_meta,
                                                     self.barbican_meta_dto)
        crypto.load_certificate(
            crypto.FILETYPE_PEM, resp.certificate.decode('base64'))

    def test_issue_raises_with_invalid_ca_id(self):
        req = certificate_utils.get_valid_csr_object()

        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        req_enc = base64.b64encode(req_enc)
        order_meta = {'request_data': req_enc}
        plugin_meta = {'plugin_ca_id': "invalid_ca_id"}
        self.barbican_meta_dto.plugin_ca_id = "invalid_ca_id"
        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.issue_certificate_request,
            self.order_id,
            order_meta,
            plugin_meta,
            self.barbican_meta_dto)

    def test_issue_certificate_request_set_subject(self):
        req = certificate_utils.get_valid_csr_object()

        subj = req.get_subject()
        subj.countryName = 'US'
        subj.stateOrProvinceName = 'OR'
        subj.localityName = 'Testlandia'
        subj.organizationName = 'Testers Anon'
        subj.organizationalUnitName = 'Testers OU'
        subj.commonName = 'Testing'

        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        req_enc = base64.b64encode(req_enc)
        order_meta = {'request_data': req_enc}
        resp = self.plugin.issue_certificate_request(self.order_id,
                                                     order_meta, {},
                                                     self.barbican_meta_dto)
        cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, resp.certificate.decode('base64'))
        cert_subj = cert.get_subject()
        self.assertEqual('US', cert_subj.C)
        self.assertEqual('OR', cert_subj.ST)
        self.assertEqual('Testlandia', cert_subj.L)
        self.assertEqual('Testers Anon', cert_subj.O)
        self.assertEqual('Testers OU', cert_subj.OU)
        self.assertEqual('Testing', cert_subj.CN)

    def test_issue_certificate_request_stored_key(self):
        req = certificate_utils.get_valid_csr_object()

        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        self.barbican_meta_dto.generated_csr = req_enc
        resp = self.plugin.issue_certificate_request(
            self.order_id, {}, {}, self.barbican_meta_dto)
        crypto.load_certificate(
            crypto.FILETYPE_PEM, resp.certificate.decode('base64'))

    def test_no_request_data(self):
        res = self.plugin.issue_certificate_request(
            self.order_id, {}, {}, self.barbican_meta_dto)
        self.assertIs(cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                      res.status)
        self.assertEqual("No request_data specified", res.status_message)

    def test_get_default_ca_name(self):
        self.assertEqual("Snakeoil CA", self.plugin.get_default_ca_name())

    def test_get_default_signing_cert(self):
        ca_cert = self.plugin.get_default_signing_cert()
        self.assertEqual(
            crypto.dump_certificate(crypto.FILETYPE_PEM, self.plugin.ca.cert),
            ca_cert)

    def test_get_default_intermediates_none(self):
        intermediates = self.plugin.get_default_intermediates()
        self.assertIsNone(intermediates)

    def test_not_implemented(self):
        self.assertRaises(NotImplementedError,
                          self.plugin.modify_certificate_request,
                          '', {}, {}, {})
        self.assertRaises(NotImplementedError,
                          self.plugin.cancel_certificate_request,
                          '', {}, {}, {})
        self.assertRaises(NotImplementedError,
                          self.plugin.check_certificate_status,
                          '', {}, {}, {})

    def test_support_request_types(self):
        manager = cm.CertificatePluginManager()
        manager.extensions = [mock.MagicMock(obj=self.plugin)]
        cert_spec = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.CUSTOM_REQUEST}
        self.assertEqual(self.plugin, manager.get_plugin(cert_spec))
        self.assertTrue(self.plugin.supports(cert_spec))
        cert_spec = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.STORED_KEY_REQUEST}
        self.assertEqual(self.plugin, manager.get_plugin(cert_spec))
        self.assertTrue(self.plugin.supports(cert_spec))
        cert_spec = {
            cm.REQUEST_TYPE: cm.CertificateRequestType.FULL_CMC_REQUEST}
        self.assertRaises(cm.CertificatePluginNotFound,
                          manager.get_plugin, cert_spec)
        self.assertFalse(self.plugin.supports(cert_spec))

    def test_supports_create_ca(self):
        self.assertTrue(self.plugin.supports_create_ca())

    def _create_subca(self):
        create_ca_dto = cm.CACreateDTO(
            name="sub ca1",
            description="subordinate ca",
            subject_dn="cn=subordinate ca signing cert, o=example.com",
            parent_ca_id=self.plugin.get_default_ca_name()
        )
        return self.plugin.create_ca(create_ca_dto)

    def test_create_ca(self):
        subca_dict = self._create_subca()
        self.assertEqual("sub ca1", subca_dict.get(cm.INFO_NAME))
        self.assertIsNotNone(subca_dict.get(cm.INFO_EXPIRATION))
        self.assertIsNotNone(subca_dict.get(cm.PLUGIN_CA_ID))
        ca_cert = subca_dict.get(cm.INFO_CA_SIGNING_CERT)
        self.assertIsNotNone(ca_cert)

        intermediates = subca_dict.get(cm.INFO_INTERMEDIATES)
        self.assertIsNotNone(intermediates)

        cacert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert)
        subject = cacert.get_subject()
        self.assertEqual(
            "subordinate ca signing cert",
            subject.CN)

        pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, intermediates)
        self.assertTrue(pkcs7.type_is_signed())

        # TODO(alee) Verify that ca cert is signed by parent CA

    def test_issue_certificate_request_with_subca_id(self):
        subca_dict = self._create_subca()
        req = certificate_utils.get_valid_csr_object()

        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        req_enc = base64.b64encode(req_enc)
        order_meta = {'request_data': req_enc}
        plugin_meta = {'plugin_ca_id': subca_dict.get(cm.PLUGIN_CA_ID)}
        self.barbican_meta_dto.plugin_ca_id = subca_dict.get(cm.PLUGIN_CA_ID)
        resp = self.plugin.issue_certificate_request(self.order_id,
                                                     order_meta,
                                                     plugin_meta,
                                                     self.barbican_meta_dto)
        new_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, resp.certificate.decode('base64'))
        signing_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, subca_dict['ca_signing_certificate'])

        self.assertEqual(signing_cert.get_subject(), new_cert.get_issuer())

    def test_delete_ca(self):
        subca_dict = self._create_subca()
        ca_id = subca_dict.get(cm.PLUGIN_CA_ID)
        self.assertIsNotNone(ca_id)

        cert_path = os.path.join(self.subca_cert_key_directory,
                                 ca_id + ".cert")
        key_path = os.path.join(self.subca_cert_key_directory,
                                ca_id + ".key")
        self.assertTrue(os.path.exists(cert_path))
        self.assertTrue(os.path.exists(key_path))

        self.plugin.delete_ca(ca_id)
        self.assertFalse(os.path.exists(cert_path))
        self.assertFalse(os.path.exists(key_path))

        cas = self.plugin.get_ca_info()
        self.assertNotIn(ca_id, cas.keys())

    def test_raises_no_parent_id_passed_in(self):
        create_ca_dto = cm.CACreateDTO(
            name="sub ca1",
            description="subordinate ca",
            subject_dn="cn=subordinate ca signing cert, o=example.com",
        )

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.create_ca,
            create_ca_dto
        )

    def test_raises_invalid_parent_id_passed_in(self):
        create_ca_dto = cm.CACreateDTO(
            name="sub ca1",
            description="subordinate ca",
            subject_dn="cn=subordinate ca signing cert, o=example.com",
            parent_ca_id="foo"
        )

        self.assertRaises(
            cm.CertificateGeneralException,
            self.plugin.create_ca,
            create_ca_dto
        )

    def test_get_ca_info(self):
        ca_info = self.plugin.get_ca_info()
        ca_dict = ca_info.get(self.plugin.ca.name)
        self.assertIsNotNone(ca_dict)
        self.assertEqual(self.plugin.ca.name, ca_dict.get(cm.INFO_NAME))
        self.assertIsNotNone(ca_dict.get(cm.INFO_CA_SIGNING_CERT))
        self.assertEqual(str, type(ca_dict.get(cm.INFO_EXPIRATION)))

    def test_get_ca_info_with_subca(self):
        subca_dict = self._create_subca()
        subca_id = subca_dict.get(cm.PLUGIN_CA_ID)
        ca_info = self.plugin.get_ca_info()
        self.assertIn(subca_id, ca_info.keys())
        self.assertIn(self.plugin.get_default_ca_name(), ca_info.keys())
        self.assertEqual(str, type(subca_dict.get(cm.INFO_EXPIRATION)))
