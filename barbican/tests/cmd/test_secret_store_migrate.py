# Copyright 2026 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
from datetime import timedelta
import io
import json
import os
import tempfile
from unittest import mock

from oslo_utils import timeutils
from oslo_utils import uuidutils

from barbican.cmd import secret_store_migrate as migrate_cmd
from barbican.common import config
from barbican.common import exception as barbican_exc
from barbican.model import models
from barbican.model import repositories as repos
from barbican.tests import database_utils
from barbican.tests import utils


STORE_DEST = 'dc22fcf8-d97f-4c40-a8eb-bc3e3608eb1f'
STORE_SRC = 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb'
PROJECT_A = '11111111-1111-1111-1111-111111111111'
PROJECT_B = '22222222-2222-2222-2222-222222222222'
SECRET_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
SECRET_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
SECRET_C = 'cccccccc-cccc-cccc-cccc-cccccccccccc'


class FakeStore(object):
    def __init__(self, store_id):
        self.id = store_id


class WhenTestingSecretStoreMigrateCommand(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingSecretStoreMigrateCommand, self).setUp()
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def _argv(self, extra):
        return ['--dest-store-id', STORE_DEST] + extra

    def _run(self, argv, targets, rewrap_side_effect=None):
        args = migrate_cmd.parse_args(argv)
        with mock.patch.object(
                migrate_cmd, 'discover_targets',
                autospec=True, return_value=targets), \
                mock.patch.object(
                    migrate_cmd, '_rewrap_secret_by_id',
                    autospec=True,
                    side_effect=rewrap_side_effect) as mock_rewrap, \
                mock.patch.object(
                    migrate_cmd.repos, 'rollback',
                    autospec=True), \
                mock.patch('sys.stdout', self.stdout), \
                mock.patch('sys.stderr', self.stderr):
            rc = migrate_cmd.run(args)
        return rc, mock_rewrap

    def test_rewrap_commits_session(self):
        secret = mock.Mock()
        secret.project = mock.Mock()
        store = mock.Mock()
        with mock.patch.object(
                migrate_cmd.repos, 'get_secret_repository',
                autospec=True) as mock_secret_repo, \
                mock.patch.object(
                    migrate_cmd, '_require_store',
                    autospec=True, return_value=store), \
                mock.patch.object(
                    migrate_cmd.plugin, 'rewrap_secret',
                    autospec=True) as mock_rewrap, \
                mock.patch.object(
                    migrate_cmd.repos, 'commit',
                    autospec=True) as mock_commit:
            mock_secret_repo.return_value.get_secret_by_id.return_value = (
                secret)
            migrate_cmd._rewrap_secret_by_id(SECRET_A, STORE_DEST)
        mock_rewrap.assert_called_once_with(
            secret, secret.project, store)
        mock_commit.assert_called_once_with()

    def test_secret_id_from_href(self):
        href = 'http://host/key-manager/v1/secrets/' + SECRET_A
        self.assertEqual(
            SECRET_A, migrate_cmd.secret_id_from_value(href))
        self.assertEqual(
            SECRET_A, migrate_cmd.secret_id_from_value(SECRET_A))

    def test_secret_id_rejects_garbage(self):
        self.assertRaises(
            ValueError,
            migrate_cmd.secret_id_from_value,
            'not-a-uuid')

    def test_ids_from_file_skips_comments(self):
        with tempfile.NamedTemporaryFile(
                'w', delete=False, encoding='utf-8') as handle:
            handle.write('# comment\n')
            handle.write('\n')
            handle.write(SECRET_A + '\n')
            handle.write(
                'http://h/v1/secrets/%s\n' % SECRET_B)
            path = handle.name
        try:
            ids = migrate_cmd.ids_from_file(path)
        finally:
            os.unlink(path)
        self.assertEqual([SECRET_A, SECRET_B], ids)

    def test_migrate_one_secret(self):
        target = migrate_cmd.Target(
            SECRET_A, PROJECT_A, name='one')
        rc, mock_rewrap = self._run(
            self._argv(['--secret-id', SECRET_A]),
            [target])
        self.assertEqual(0, rc)
        mock_rewrap.assert_called_once_with(SECRET_A, STORE_DEST)
        self.assertIn('Summary: ok=1 skipped=0 failed=0 total=1',
                      self.stdout.getvalue())

    def test_migrate_list_continues_after_error(self):
        def rewrap(secret_id, dest_store_id):
            if secret_id == SECRET_B:
                raise barbican_exc.BarbicanException(
                    'Secret has no stored payload to migrate.')

        targets = [
            migrate_cmd.Target(SECRET_A, PROJECT_A),
            migrate_cmd.Target(SECRET_B, PROJECT_A),
            migrate_cmd.Target(SECRET_C, PROJECT_A),
        ]
        with tempfile.NamedTemporaryFile(
                'w', delete=False, encoding='utf-8') as err:
            err_path = err.name
        try:
            rc, mock_rewrap = self._run(
                self._argv([
                    '--secret-id', SECRET_A,
                    '--secret-id', SECRET_B,
                    '--secret-id', SECRET_C,
                    '--error-file', err_path,
                ]),
                targets,
                rewrap_side_effect=rewrap)
            self.assertEqual(1, rc)
            self.assertEqual(3, mock_rewrap.call_count)
            self.assertIn('Summary: ok=2 skipped=0 failed=1 total=3',
                          self.stdout.getvalue())
            self.assertIn('FAIL', self.stderr.getvalue())
            rows = [
                json.loads(line) for line in
                open(err_path, encoding='utf-8') if line.strip()
            ]
        finally:
            os.unlink(err_path)
        self.assertEqual(1, len(rows))
        self.assertEqual(SECRET_B, rows[0]['secret_id'])
        self.assertEqual(PROJECT_A, rows[0]['project_id'])
        self.assertIn('no stored payload', rows[0]['error'])
        self.assertNotIn('http_status', rows[0])
        self.assertNotIn('payload', rows[0])

    def test_rewrap_failure_rolls_back_session(self):
        targets = [
            migrate_cmd.Target(SECRET_A, PROJECT_A),
            migrate_cmd.Target(SECRET_B, PROJECT_A),
        ]
        args = migrate_cmd.parse_args(
            self._argv([
                '--secret-id', SECRET_A,
                '--secret-id', SECRET_B,
            ]))
        with mock.patch.object(
                migrate_cmd, 'discover_targets',
                autospec=True, return_value=targets), \
                mock.patch.object(
                    migrate_cmd, '_rewrap_secret_by_id',
                    autospec=True,
                    side_effect=[
                        barbican_exc.BarbicanException('boom'),
                        None,
                    ]) as mock_rewrap, \
                mock.patch.object(
                    migrate_cmd.repos, 'rollback',
                    autospec=True) as mock_rollback, \
                mock.patch('sys.stdout', self.stdout), \
                mock.patch('sys.stderr', self.stderr):
            rc = migrate_cmd.run(args)
        self.assertEqual(1, rc)
        self.assertEqual(2, mock_rewrap.call_count)
        mock_rollback.assert_called_once_with()

    def test_dry_run_does_not_rewrap(self):
        target = migrate_cmd.Target(SECRET_A, PROJECT_A)
        rc, mock_rewrap = self._run(
            self._argv(['--secret-id', SECRET_A, '--dry-run']),
            [target])
        self.assertEqual(0, rc)
        mock_rewrap.assert_not_called()
        self.assertIn('would migrate', self.stdout.getvalue())
        self.assertIn(PROJECT_A, self.stdout.getvalue())

    def test_dry_run_records_discover_errors_but_exits_zero(self):
        targets = [
            migrate_cmd.Target(SECRET_A, PROJECT_A),
            migrate_cmd.Target(
                SECRET_B, PROJECT_A,
                error='Could not resolve the secret store'),
        ]
        with tempfile.NamedTemporaryFile(
                'w', delete=False, encoding='utf-8') as err:
            err_path = err.name
        try:
            rc, mock_rewrap = self._run(
                self._argv([
                    '--secret-id', SECRET_A,
                    '--secret-id', SECRET_B,
                    '--dry-run',
                    '--error-file', err_path,
                ]),
                targets)
            self.assertEqual(0, rc)
            mock_rewrap.assert_not_called()
            self.assertIn('would migrate', self.stdout.getvalue())
            self.assertIn('FAIL', self.stderr.getvalue())
            self.assertIn(
                'Summary: ok=1 skipped=0 failed=1 total=2',
                self.stdout.getvalue())
            row = json.loads(open(err_path, encoding='utf-8').read())
        finally:
            os.unlink(err_path)
        self.assertEqual(SECRET_B, row['secret_id'])
        self.assertIn('resolve', row['error'])

    def test_bulk_parse_allows_without_yes(self):
        args = migrate_cmd.parse_args(
            self._argv(['--project-id', PROJECT_A]))
        self.assertEqual(PROJECT_A, args.project_id)
        self.assertFalse(args.yes)

    def test_source_and_dest_must_differ(self):
        self.assertRaises(
            SystemExit,
            migrate_cmd.parse_args,
            self._argv([
                '--source-store-id', STORE_DEST,
                '--project-id', PROJECT_A,
            ]))

    def test_cannot_mix_explicit_ids_with_bulk(self):
        self.assertRaises(
            SystemExit,
            migrate_cmd.parse_args,
            self._argv([
                '--project-id', PROJECT_A,
                '--secret-id', SECRET_A,
            ]))

    def test_missing_selector_is_usage_error(self):
        self.assertRaises(
            SystemExit,
            migrate_cmd.parse_args,
            ['--dest-store-id', STORE_DEST])

    def test_secret_store_id_alias_removed(self):
        self.assertRaises(
            SystemExit,
            migrate_cmd.parse_args,
            ['--secret-store-id', STORE_DEST,
             '--secret-id', SECRET_A])

    def test_bulk_live_prompts_without_yes(self):
        target = migrate_cmd.Target(SECRET_A, PROJECT_A)
        args = migrate_cmd.parse_args(
            self._argv(['--project-id', PROJECT_A]))
        with mock.patch.object(
                migrate_cmd, 'discover_targets',
                autospec=True, return_value=[target]), \
                mock.patch.object(
                    migrate_cmd, '_rewrap_secret_by_id',
                    autospec=True) as mock_rewrap, \
                mock.patch.object(
                    migrate_cmd, 'confirm_bulk_migrate',
                    autospec=True, return_value=False) as mock_confirm, \
                mock.patch('sys.stdout', self.stdout), \
                mock.patch('sys.stderr', self.stderr):
            rc = migrate_cmd.run(args)
        self.assertEqual(2, rc)
        mock_confirm.assert_called_once_with(args, 1)
        mock_rewrap.assert_not_called()

    def test_bulk_live_yes_skips_prompt(self):
        target = migrate_cmd.Target(SECRET_A, PROJECT_A)
        rc, mock_rewrap = self._run(
            self._argv(['--project-id', PROJECT_A, '--yes']),
            [target])
        self.assertEqual(0, rc)
        mock_rewrap.assert_called_once_with(SECRET_A, STORE_DEST)

    def test_confirm_bulk_non_tty_requires_yes(self):
        args = migrate_cmd.parse_args(
            self._argv(['--project-id', PROJECT_A]))
        with mock.patch('sys.stdin') as mock_stdin, \
                mock.patch('sys.stderr', self.stderr):
            mock_stdin.isatty.return_value = False
            confirmed = migrate_cmd.confirm_bulk_migrate(args, 3)
        self.assertFalse(confirmed)
        self.assertIn('--yes', self.stderr.getvalue())

    def test_confirm_bulk_accepts_yes_answer(self):
        args = migrate_cmd.parse_args(
            self._argv(['--project-id', PROJECT_A]))
        with mock.patch('sys.stdin') as mock_stdin, \
                mock.patch('sys.stdout', self.stdout):
            mock_stdin.isatty.return_value = True
            mock_stdin.readline.return_value = 'yes\n'
            confirmed = migrate_cmd.confirm_bulk_migrate(args, 2)
        self.assertTrue(confirmed)
        self.assertIn('Migrate 2 secret(s)', self.stdout.getvalue())

    def test_rewrap_exception_is_recorded(self):
        with tempfile.NamedTemporaryFile(
                'w', delete=False, encoding='utf-8') as err:
            err_path = err.name
        try:
            rc, _mock_rewrap = self._run(
                self._argv([
                    '--secret-id', SECRET_A,
                    '--error-file', err_path,
                ]),
                [migrate_cmd.Target(SECRET_A, PROJECT_A)],
                rewrap_side_effect=RuntimeError('plugin down'))
            self.assertEqual(1, rc)
            row = json.loads(open(err_path, encoding='utf-8').read())
        finally:
            os.unlink(err_path)
        self.assertIn('plugin down', row['error'])

    def test_discover_error_is_setup_failure(self):
        args = migrate_cmd.parse_args(
            self._argv(['--secret-id', SECRET_A]))
        with mock.patch.object(
                migrate_cmd, 'discover_targets',
                autospec=True,
                side_effect=RuntimeError('db down')), \
                mock.patch('sys.stdout', self.stdout), \
                mock.patch('sys.stderr', self.stderr):
            rc = migrate_cmd.run(args)
        self.assertEqual(2, rc)
        self.assertIn('db down', self.stderr.getvalue())

    def test_nil_uuid_store_is_accepted_as_uuid(self):
        nil_id = '00000000-0000-0000-0000-000000000000'
        self.assertTrue(uuidutils.is_uuid_like(nil_id))
        args = migrate_cmd.parse_args(
            ['--dest-store-id', nil_id, '--secret-id', SECRET_A])
        self.assertEqual(nil_id, args.dest_store_id)


class WhenTestingDiscoverTargets(database_utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingDiscoverTargets, self).setUp()
        ss_conf = config.get_module_config('secretstore')
        ss_conf.set_override(
            'enable_multiple_secret_stores', True,
            group='secretstore')
        self.dest = self._create_store('dest')
        self.src = self._create_store('src')
        self.proj_a = database_utils.create_project(external_id=PROJECT_A)
        self.proj_b = database_utils.create_project(external_id=PROJECT_B)
        self.secret_a = database_utils.create_secret(project=self.proj_a)
        self.secret_b = database_utils.create_secret(project=self.proj_a)
        self.secret_c = database_utils.create_secret(project=self.proj_b)
        self.stores = {
            self.secret_a.id: FakeStore(self.src.id),
            self.secret_b.id: FakeStore(self.dest.id),
            self.secret_c.id: FakeStore(self.src.id),
        }
        resolve_patcher = mock.patch.object(
            migrate_cmd.plugin, 'resolve_secret_store_for_secret',
            autospec=True, side_effect=self._resolve)
        resolve_patcher.start()
        self.addCleanup(resolve_patcher.stop)

    def _create_store(self, name):
        store = models.SecretStores(
            name=name + '-' + uuidutils.generate_uuid(),
            store_plugin='plugin-' + name)
        return repos.get_secret_stores_repository().create_from(store)

    def _resolve(self, secret):
        store = self.stores.get(secret.id)
        if store is False:
            raise barbican_exc.SecretStoreNotResolved(
                secret_id=secret.id)
        return store

    def _args(self, **kwargs):
        ns = argparse.Namespace(
            dest_store_id=self.dest.id,
            source_store_id=None,
            project_id=None,
            secret_id=[],
            secret_ids_file=None)
        for key, value in kwargs.items():
            setattr(ns, key, value)
        return ns

    def test_project_filter(self):
        targets = migrate_cmd.discover_targets(
            self._args(project_id=PROJECT_A))
        # secret_b is already on dest — recorded as skip, not migrate
        migrateable = [t for t in targets if not t.skip_reason]
        ids = [t.secret_id for t in migrateable]
        self.assertEqual([self.secret_a.id], ids)
        self.assertTrue(all(t.project_id == PROJECT_A for t in migrateable))

    def test_skips_secrets_already_on_dest(self):
        targets = migrate_cmd.discover_targets(
            self._args(project_id=PROJECT_A))
        skipped = [t for t in targets if t.skip_reason]
        migrateable = [t for t in targets if not t.skip_reason]
        self.assertEqual([self.secret_b.id], [t.secret_id for t in skipped])
        self.assertIn('already on destination', skipped[0].skip_reason)
        self.assertEqual([self.secret_a.id],
                         [t.secret_id for t in migrateable])

    def test_explicit_id_already_on_dest_is_reported(self):
        targets = migrate_cmd.discover_targets(
            self._args(secret_id=[self.secret_b.id]))
        self.assertEqual(1, len(targets))
        self.assertEqual(self.secret_b.id, targets[0].secret_id)
        self.assertIn('already on destination', targets[0].skip_reason)

    def test_excludes_expired_secrets(self):
        expired = database_utils.create_secret(project=self.proj_a)
        expired.expiration = timeutils.utcnow() - timedelta(hours=1)
        repos.get_secret_repository().save(expired)
        self.stores[expired.id] = FakeStore(self.src.id)
        targets = migrate_cmd.discover_targets(
            self._args(project_id=PROJECT_A))
        self.assertNotIn(expired.id, [t.secret_id for t in targets])

    def test_source_store_filter_across_projects(self):
        targets = migrate_cmd.discover_targets(
            self._args(source_store_id=self.src.id))
        ids = sorted(t.secret_id for t in targets)
        self.assertEqual(
            sorted([self.secret_a.id, self.secret_c.id]), ids)
        projects = {t.project_id for t in targets}
        self.assertEqual({PROJECT_A, PROJECT_B}, projects)

    def test_project_and_source_store_combined(self):
        targets = migrate_cmd.discover_targets(
            self._args(project_id=PROJECT_A,
                       source_store_id=self.src.id))
        self.assertEqual(1, len(targets))
        self.assertEqual(self.secret_a.id, targets[0].secret_id)

    def test_skips_secrets_without_payload(self):
        self.stores[self.secret_a.id] = None
        self.stores[self.secret_b.id] = FakeStore(self.src.id)
        targets = migrate_cmd.discover_targets(
            self._args(project_id=PROJECT_A))
        ids = [t.secret_id for t in targets]
        self.assertNotIn(self.secret_a.id, ids)
        self.assertIn(self.secret_b.id, ids)

    def test_explicit_id_without_payload_is_error_target(self):
        self.stores[self.secret_a.id] = None
        targets = migrate_cmd.discover_targets(
            self._args(secret_id=[self.secret_a.id],
                       dest_store_id=self.dest.id))
        self.assertEqual(1, len(targets))
        self.assertIn('no payload', targets[0].error)

    def test_unresolved_store_omitted_in_bulk(self):
        self.stores[self.secret_a.id] = False
        targets = migrate_cmd.discover_targets(
            self._args(project_id=PROJECT_A))
        ids = [t.secret_id for t in targets]
        self.assertNotIn(self.secret_a.id, ids)
        self.assertIn(self.secret_b.id, ids)

    def test_explicit_id_unresolved_store_is_error_target(self):
        self.stores[self.secret_a.id] = False
        targets = migrate_cmd.discover_targets(
            self._args(secret_id=[self.secret_a.id]))
        self.assertEqual(1, len(targets))
        self.assertEqual(self.secret_a.id, targets[0].secret_id)
        self.assertTrue(targets[0].error)

    def test_unknown_dest_store_raises(self):
        self.assertRaises(
            RuntimeError,
            migrate_cmd.discover_targets,
            self._args(project_id=PROJECT_A,
                       dest_store_id=uuidutils.generate_uuid()))

    def test_unknown_project_raises(self):
        self.assertRaises(
            RuntimeError,
            migrate_cmd.discover_targets,
            self._args(project_id=uuidutils.generate_uuid()))

    def test_missing_explicit_secret_is_error_target(self):
        missing = uuidutils.generate_uuid()
        targets = migrate_cmd.discover_targets(
            self._args(secret_id=[missing]))
        self.assertEqual(1, len(targets))
        self.assertIn('not found', targets[0].error)
