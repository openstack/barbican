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

    def test_gen_cacert_with_file_storage(self):
        cert_path = self.tmp_dir + 'cert.pem'
        key_path = self.tmp_dir + 'key.pem'
        subject_dn = 'cn=Test CN,o=Test O,L=Test L,st=Test ST'
        ca = snakeoil_ca.SnakeoilCA(cert_path=cert_path, key_path=key_path,
                                    key_size=512, subject_dn=subject_dn)
        subject = ca.cert.get_subject()
        self.assertNotEqual(ca.key, None)
        self.assertEqual("Test ST", subject.ST)
        self.assertEqual("Test L", subject.L)
        self.assertEqual("Test O", subject.O)
        self.assertEqual("Test CN", subject.CN)

        # Make sure we preserve existing keypairs
        ca = snakeoil_ca.SnakeoilCA(cert_path=cert_path, key_path=key_path)
        subject = ca.cert.get_subject()
        self.assertEqual("Test ST", subject.ST)
        self.assertEqual("Test L", subject.L)
        self.assertEqual("Test O", subject.O)
        self.assertEqual("Test CN", subject.CN)


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
        order_meta = {'request_data': req_enc}
        resp = self.plugin.issue_certificate_request(self.order_id,
                                                     order_meta, {},
                                                     self.barbican_meta_dto)
        crypto.load_certificate(
            crypto.FILETYPE_PEM, resp.certificate.decode('base64'))

    def test_issue_certificate_request_with_ca_id(self):
        req = certificate_utils.get_valid_csr_object()

        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        order_meta = {'request_data': req_enc}
        plugin_meta = {'plugin_ca_id': self.plugin.get_default_ca_name()}
        resp = self.plugin.issue_certificate_request(self.order_id,
                                                     order_meta,
                                                     plugin_meta,
                                                     self.barbican_meta_dto)
        crypto.load_certificate(
            crypto.FILETYPE_PEM, resp.certificate.decode('base64'))

    def test_issue_raises_with_invalid_ca_id(self):
        req = certificate_utils.get_valid_csr_object()

        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        order_meta = {'request_data': req_enc}
        plugin_meta = {'plugin_ca_id': "invalid_ca_id"}
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
        order_meta = {'request_data': req_enc}
        resp = self.plugin.issue_certificate_request(self.order_id,
                                                     order_meta, {},
                                                     self.barbican_meta_dto)
        cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, resp.certificate.decode('base64'))
        cert_subj = cert.get_subject()
        self.assertEqual(cert_subj.C, 'US')
        self.assertEqual(cert_subj.ST, 'OR')
        self.assertEqual(cert_subj.L, 'Testlandia')
        self.assertEqual(cert_subj.O, 'Testers Anon')
        self.assertEqual(cert_subj.OU, 'Testers OU')
        self.assertEqual(cert_subj.CN, 'Testing')

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
        self.assertEqual(self.plugin.get_default_ca_name(), "Snakeoil CA")

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

        # TODO(alee) Verify that the ca cert has correct subject name
        # TODO(alee) Verify that ca cert is signed by parent CA

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

    def test_get_ca_info_with_subca(self):
        subca_dict = self._create_subca()
        subca_id = subca_dict.get(cm.PLUGIN_CA_ID)
        ca_info = self.plugin.get_ca_info()
        self.assertIn(subca_id, ca_info.keys())
        self.assertIn(self.plugin.get_default_ca_name(), ca_info.keys())
