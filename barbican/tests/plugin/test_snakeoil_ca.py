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
from oslo.config import fixture as oslo_fixture

import barbican.plugin.interface.certificate_manager as cm
from barbican.plugin import snakeoil_ca
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
        ca = snakeoil_ca.SnakeoilCA(cert_path=None, key_path=None,
                                    key_size=512, subject_st='Test ST',
                                    subject_l='Test L', subject_o='Test O',
                                    subject_cn='Test CN')
        subject = ca.cert.get_subject()
        self.assertNotEqual(ca.key, None)
        self.assertEqual("Test ST", subject.ST)
        self.assertEqual("Test L", subject.L)
        self.assertEqual("Test O", subject.O)
        self.assertEqual("Test CN", subject.CN)

    def test_gen_cacert_with_file_storage(self):
        cert_path = self.tmp_dir + 'cert.pem'
        key_path = self.tmp_dir + 'key.pem'
        ca = snakeoil_ca.SnakeoilCA(cert_path=cert_path, key_path=key_path,
                                    key_size=512, subject_st='Test ST',
                                    subject_l='Test L', subject_o='Test O',
                                    subject_cn='Test CN')
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
        self.ca = snakeoil_ca.SnakeoilCA(cert_path=None, key_path=None,
                                         key_size=512, subject_st='Test ST',
                                         subject_l='Test L',
                                         subject_o='Test O',
                                         subject_cn='Test CN')

    def verify_sig(self, encoded_cert):
        der = asn1.DerSequence()
        der.decode(encoded_cert)
        der_sig = asn1.DerObject()
        der_sig.decode(der[2])
        sig = der_sig.payload
        self.assertIs('\x00', sig[0])
        crypto.verify(self.ca.cert, sig[1:], der[0], 'sha256')

    def test_gen_cert_no_file_storage(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 512)
        req = crypto.X509Req()
        req.set_pubkey(key)
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
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 512)
        req = crypto.X509Req()
        req.set_pubkey(key)
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
        self.ca_cert_path = os.path.join(self.tmp_dir, 'ca.pem')
        self.ca_key_path = os.path.join(self.tmp_dir, 'ca.pem')
        self.db_dir = self.tmp_dir
        self.plugin = snakeoil_ca.SnakeoilCACertificatePlugin(
            self.conf.snakeoil_ca_plugin)
        self.order_id = mock.MagicMock()

    def test_issue_certificate_request(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 512)
        req = crypto.X509Req()
        req.set_pubkey(key)
        req_enc = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        order_meta = {'request_data': req_enc}
        resp = self.plugin.issue_certificate_request(self.order_id,
                                                     order_meta, {}, {})
        crypto.load_certificate(crypto.FILETYPE_PEM, resp.certificate)

    def test_issue_certificate_request_set_subject(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 512)
        req = crypto.X509Req()
        req.set_pubkey(key)
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
                                                     order_meta, {}, {})
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, resp.certificate)
        cert_subj = cert.get_subject()
        self.assertEqual(cert_subj.C, 'US')
        self.assertEqual(cert_subj.ST, 'OR')
        self.assertEqual(cert_subj.L, 'Testlandia')
        self.assertEqual(cert_subj.O, 'Testers Anon')
        self.assertEqual(cert_subj.OU, 'Testers OU')
        self.assertEqual(cert_subj.CN, 'Testing')

    def test_no_request_data(self):
        res = self.plugin.issue_certificate_request(self.order_id, {}, {}, {})
        self.assertIs(cm.CertificateStatus.CLIENT_DATA_ISSUE_SEEN,
                      res.status)
        self.assertEqual("No request_data specified", res.status_message)

    def test_get_default_ca_name(self):
        self.assertEqual(self.plugin.get_default_ca_name(), "Snakeoil CA")

    def test_get_default_signing_cert(self):
        ca_cert = self.plugin.get_default_signing_cert()
        self.assertEqual(self.plugin.ca._cert_val, ca_cert)

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
        self.assertRaises(NotImplementedError,
                          self.plugin.supports, '')
