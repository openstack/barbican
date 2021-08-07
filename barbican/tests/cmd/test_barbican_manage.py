# Copyright (c) 2015 Rackspace, Inc.
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
from unittest import mock

import fixtures

from barbican.cmd import barbican_manage as manager
from barbican.tests import utils


class TestBarbicanManageBase(utils.BaseTestCase):
    def setUp(self):
        super(TestBarbicanManageBase, self).setUp()

        def clear_conf():
            manager.CONF.reset()
            manager.CONF.unregister_opt(manager.category_opt)
        clear_conf()
        self.addCleanup(clear_conf)

        manager.CONF.set_override('sql_connection', 'mockdburl')

    def _main_test_helper(self, argv, func_name=None, *exp_args, **exp_kwargs):
        self.useFixture(fixtures.MonkeyPatch('sys.argv', argv))
        manager.main()
        func_name.assert_called_once_with(*exp_args, **exp_kwargs)


class TestBarbicanManage(TestBarbicanManageBase):
    """Test barbican-manage functionality."""

    @mock.patch('barbican.model.migration.commands.generate')
    def test_db_revision(self, mock_generate):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'revision', '--db-url',
             'mockdb', '--message', 'mockmsg'], mock_generate,
            autogenerate=False, message='mockmsg', sql_url='mockdb')

    @mock.patch('barbican.model.migration.commands.generate')
    def test_db_revision_autogenerate(self, mock_generate):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'revision', '--db-url',
             'mockdb', '--message', 'mockmsg', '--autogenerate'],
            mock_generate, autogenerate=True, message='mockmsg',
            sql_url='mockdb')

    @mock.patch('barbican.model.migration.commands.generate')
    def test_db_revision_no_dburl(self, mock_generate):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'revision', '--message',
             'mockmsg'], mock_generate, autogenerate=False, message='mockmsg',
            sql_url='mockdburl')

    @mock.patch('barbican.model.migration.commands.upgrade')
    def test_db_upgrade(self, mock_upgrade):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'upgrade', '--db-url',
             'mockdb'], mock_upgrade, to_version='head', sql_url='mockdb')

    @mock.patch('barbican.model.migration.commands.upgrade')
    def test_db_upgrade_no_dburl(self, mock_upgrade):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'upgrade'], mock_upgrade,
            to_version='head', sql_url='mockdburl')

    @mock.patch('barbican.model.migration.commands.history')
    def test_db_history(self, mock_history):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'history', '--db-url',
             'mockdb'], mock_history, False, sql_url='mockdb')

    @mock.patch('barbican.model.migration.commands.history')
    def test_db_history_no_dburl(self, mock_history):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'history'], mock_history,
            False, sql_url='mockdburl')

    @mock.patch('barbican.model.clean.clean_command')
    def test_db_clean_no_args(self, mock_clean_command):
        manager.CONF.set_override('log_file', 'mock_log_file')
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'clean'],
            func_name=mock_clean_command,
            sql_url='mockdburl',
            min_num_days=90,
            do_clean_unassociated_projects=False,
            do_soft_delete_expired_secrets=False,
            verbose=False,
            log_file='mock_log_file')
        manager.CONF.clear_override('log_file')

    @mock.patch('barbican.model.clean.clean_command')
    def test_db_clean_with_args(self, mock_clean_command):
        manager.CONF.set_override('log_file', 'mock_log_file')
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'clean',
             '--db-url', 'somewhere', '--min-days', '180',
             '--clean-unassociated-projects', '--soft-delete-expired-secrets',
             '--verbose', '--log-file', '/tmp/whatevs'],
            func_name=mock_clean_command,
            sql_url='somewhere',
            min_num_days=180,
            do_clean_unassociated_projects=True,
            do_soft_delete_expired_secrets=True,
            verbose=True,
            log_file='/tmp/whatevs')
        manager.CONF.clear_override('log_file')

    @mock.patch('barbican.model.sync.sync_secret_stores')
    def test_db_sync_secret_stores_no_args(self, mock_sync_command):
        manager.CONF.set_override('log_file', 'mock_log_file')
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'sync_secret_stores'],
            func_name=mock_sync_command,
            sql_url='mockdburl',
            verbose=False,
            log_file='mock_log_file')
        manager.CONF.clear_override('log_file')

    @mock.patch('barbican.model.sync.sync_secret_stores')
    def test_db_sync_secret_stores_with_args(self, mock_sync_command):
        manager.CONF.set_override('log_file', 'mock_log_file')
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'sync_secret_stores',
             '--db-url', 'somewhere',
             '--verbose',
             '--log-file', '/tmp/whatevs'],
            func_name=mock_sync_command,
            sql_url='somewhere',
            verbose=True,
            log_file='/tmp/whatevs')
        manager.CONF.clear_override('log_file')

    @mock.patch('barbican.model.migration.commands.current')
    def test_db_current(self, mock_current):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'current', '--db-url',
             'mockdb'], mock_current, False, sql_url='mockdb')

    @mock.patch('barbican.model.migration.commands.current')
    def test_db_current_no_dburl(self, mock_current):
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'db', 'current'], mock_current,
            False, sql_url='mockdburl')

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_check_mkek(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = 1
        mock_getkey = mock_pkcs11.return_value.get_key_handle
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'check_mkek',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd',
             '--slot', '0', '--label', 'mocklabel'], mock_getkey, 'CKK_AES',
            'mocklabel', 1)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_check_mkek_no_label(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = 1
        mock_getkey = mock_pkcs11.return_value.get_key_handle
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'check_mkek',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd'],
            mock_getkey, 'CKK_AES', None, 1)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_check_mkek_defaults(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = 1
        mock_getkey = mock_pkcs11.return_value.get_key_handle
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'check_mkek'],
            mock_getkey, 'CKK_AES', None, 1)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    @mock.patch('sys.exit')
    def test_hsm_check_mkek_not_found(self, mock_exit, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = None
        mock_getkey = mock_pkcs11.return_value.get_key_handle
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'check_mkek',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd',
             '--label', 'mocklabel'], mock_getkey, 'CKK_AES', 'mocklabel', 1)
        mock_exit.assert_called_once_with(1)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_gen_mkek(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = None
        mock_pkcs11.return_value.generate_key.return_value = 0
        mock_genkey = mock_pkcs11.return_value.generate_key
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'gen_mkek',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd',
             '--label', 'mocklabel'], mock_genkey, 'CKK_AES',
            32, 'CKM_AES_KEY_GEN', 1, 'mocklabel', encrypt=True, wrap=True,
            master_key=True)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_gen_mkek_default_label(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = None
        mock_pkcs11.return_value.generate_key.return_value = 0
        mock_genkey = mock_pkcs11.return_value.generate_key
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'gen_mkek',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd'],
            mock_genkey, 'CKK_AES',
            32, 'CKM_AES_KEY_GEN', 1, 'primarymkek', encrypt=True, wrap=True,
            master_key=True)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_gen_hmac(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = None
        mock_pkcs11.return_value.generate_key.return_value = 0
        mock_genkey = mock_pkcs11.return_value.generate_key
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'gen_hmac',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd',
             '--label', 'mocklabel'], mock_genkey, 'CKK_AES',
            32, 'CKM_AES_KEY_GEN', 1, 'mocklabel', sign=True, master_key=True)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_gen_mkek_non_default_length(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = None
        mock_pkcs11.return_value.generate_key.return_value = 0
        mock_genkey = mock_pkcs11.return_value.generate_key
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'gen_mkek',
             '--length', '48', '--library-path', 'mocklib',
             '--passphrase', 'mockpassewd', '--label', 'mocklabel'],
            mock_genkey, 'CKK_AES', 48, 'CKM_AES_KEY_GEN', 1, 'mocklabel',
            encrypt=True, wrap=True, master_key=True)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_check_hmac(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = 1
        mock_getkey = mock_pkcs11.return_value.get_key_handle
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'check_hmac',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd',
             '--label', 'mocklabel'], mock_getkey, 'CKK_AES', 'mocklabel', 1)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_check_hmac_no_label(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = 1
        mock_getkey = mock_pkcs11.return_value.get_key_handle
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'check_hmac',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd'],
            mock_getkey, 'CKK_AES', None, 1)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    @mock.patch('sys.exit')
    def test_hsm_check_hmac_not_found(self, mock_exit, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = None
        mock_getkey = mock_pkcs11.return_value.get_key_handle
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'check_hmac',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd',
             '--label', 'mocklabel'], mock_getkey, 'CKK_AES', 'mocklabel', 1)
        mock_exit.assert_called_once_with(1)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_gen_hmac_non_default_length(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = None
        mock_pkcs11.return_value.generate_key.return_value = 0
        mock_genkey = mock_pkcs11.return_value.generate_key
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'gen_hmac',
             '--length', '48', '--library-path', 'mocklib',
             '--passphrase', 'mockpassewd', '--label', 'mocklabel'],
            mock_genkey, 'CKK_AES', 48, 'CKM_AES_KEY_GEN', 1, 'mocklabel',
            sign=True, master_key=True)

    @mock.patch('barbican.plugin.crypto.pkcs11.PKCS11')
    def test_hsm_gen_hmac_default_label(self, mock_pkcs11):
        mock_pkcs11.return_value.get_session.return_value = 1
        mock_pkcs11.return_value.get_key_handle.return_value = None
        mock_pkcs11.return_value.generate_key.return_value = 0
        mock_genkey = mock_pkcs11.return_value.generate_key
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'gen_hmac',
             '--library-path', 'mocklib', '--passphrase', 'mockpassewd'],
            mock_genkey, 'CKK_AES',
            32, 'CKM_AES_KEY_GEN', 1, 'primaryhmac', sign=True,
            master_key=True)

    @mock.patch('barbican.cmd.barbican_manage.pkcs11_rewrap')
    def test_rewrap_pkek(self, mock_rewrap):
        mock_execute = mock_rewrap.KekRewrap.return_value.execute
        self._main_test_helper(
            ['barbican.cmd.barbican_manage', 'hsm', 'rewrap_pkek',
             '--dry-run'], mock_execute, True)
