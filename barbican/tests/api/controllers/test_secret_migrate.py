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

from oslo_utils import uuidutils

from barbican.api import controllers
from barbican.common import config
from barbican.common import exception
from barbican import context
from barbican.model import models
from barbican.model import repositories as repos
from barbican.plugin import resources as plugin
from barbican.tests.api.controllers import test_secrets
from barbican.tests.api.controllers.test_secretstores import SecretStoresMixin
from barbican.tests.api import test_resources_policy as test_policy
from barbican.tests import utils


class WhenTestingSecretMigrateStore(utils.BarbicanAPIBaseTestCase):

    def setUp(self):
        super(WhenTestingSecretMigrateStore, self).setUp()
        utils.set_version(self.app, '1.3')
        self.secret_stores_repo = repos.get_secret_stores_repository()

    def _create_store(self, name=None):
        suffix = uuidutils.generate_uuid()
        name = name or ('store-' + suffix)
        store = models.SecretStores(
            name=name,
            store_plugin='plugin-' + suffix)
        return self.secret_stores_repo.create_from(store)

    def _create_secret_with_payload(self):
        resp, secret_uuid = test_secrets.create_secret(
            self.app,
            payload='migrate-me',
            content_type='text/plain')
        self.assertEqual(201, resp.status_int)
        return secret_uuid

    def _put_migrate(self, secret_uuid, store_id, expect_errors=False,
                     multiple_backends=True, headers=None):
        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=multiple_backends):
            return self.app.put(
                '/secrets/{0}/secret-store/{1}'.format(
                    secret_uuid, store_id),
                headers=headers,
                expect_errors=expect_errors)

    def _owner_from_rewrap(self, mock_rewrap):
        captured = {}

        def _capture(secret, project, store):
            captured['external_id'] = project.external_id

        mock_rewrap.side_effect = _capture
        return captured

    @mock.patch('barbican.plugin.resources.rewrap_secret', autospec=True)
    def test_migrate_with_store_id_returns_204(self, mock_rewrap):
        captured = self._owner_from_rewrap(mock_rewrap)
        secret_uuid = self._create_secret_with_payload()
        store = self._create_store()

        resp = self._put_migrate(secret_uuid, store.id)

        self.assertEqual(204, resp.status_int)
        self.assertTrue(mock_rewrap.called)
        self.assertEqual(self.project_id, captured['external_id'])

    @mock.patch('barbican.plugin.resources.rewrap_secret', autospec=True)
    def test_migrate_uses_secret_owner_project_not_token(
            self, mock_rewrap):
        captured = self._owner_from_rewrap(mock_rewrap)
        secret_uuid = self._create_secret_with_payload()
        store = self._create_store()
        other_project = utils.generate_test_valid_uuid()
        self.app.extra_environ['barbican.context'] = self._build_context(
            other_project)

        resp = self._put_migrate(secret_uuid, store.id)

        self.assertEqual(204, resp.status_int)
        self.assertEqual(self.project_id, captured['external_id'])
        self.assertNotEqual(other_project, captured['external_id'])

    @mock.patch('barbican.plugin.resources.rewrap_secret', autospec=True)
    def test_migrate_accepts_any_accept_header(self, mock_rewrap):
        # Empty 204 responses still go through Accept negotiation; allow all
        # content types so clients sending text/plain (or other) do not 406.
        secret_uuid = self._create_secret_with_payload()
        store = self._create_store()

        resp = self._put_migrate(
            secret_uuid, store.id,
            headers={'Accept': 'text/plain'})

        self.assertEqual(204, resp.status_int)
        self.assertTrue(mock_rewrap.called)

    def test_migrate_with_invalid_uuid_returns_400(self):
        secret_uuid = self._create_secret_with_payload()
        resp = self._put_migrate(
            secret_uuid, 'not-a-uuid', expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_migrate_with_nil_uuid_returns_404(self):
        secret_uuid = self._create_secret_with_payload()
        resp = self._put_migrate(
            secret_uuid,
            '00000000-0000-0000-0000-000000000000',
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_migrate_with_unknown_store_returns_404(self):
        secret_uuid = self._create_secret_with_payload()
        resp = self._put_migrate(
            secret_uuid,
            uuidutils.generate_uuid(),
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_migrate_without_multiple_backends_returns_400(self):
        secret_uuid = self._create_secret_with_payload()
        store = self._create_store()
        resp = self._put_migrate(
            secret_uuid,
            store.id,
            expect_errors=True,
            multiple_backends=False)
        self.assertEqual(400, resp.status_int)

    @mock.patch(
        'barbican.plugin.resources.rewrap_secret',
        autospec=True,
        side_effect=exception.SecretPayloadNotFound())
    def test_migrate_metadata_only_secret_returns_400(self, _mock_rewrap):
        secret_uuid = self._create_secret_with_payload()
        store = self._create_store()
        resp = self._put_migrate(
            secret_uuid,
            store.id,
            expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_migrate_without_microversion_returns_404(self):
        utils.set_version(self.app, '1.2')
        secret_uuid = self._create_secret_with_payload()
        store = self._create_store()
        resp = self._put_migrate(
            secret_uuid,
            store.id,
            expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_migrate_without_store_id_returns_404(self):
        secret_uuid = self._create_secret_with_payload()
        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=True):
            resp = self.app.put(
                '/secrets/{0}/secret-store'.format(secret_uuid),
                expect_errors=True)
        self.assertEqual(404, resp.status_int)


class WhenTestingComputedSecretStoreFields(utils.BarbicanAPIBaseTestCase):

    def setUp(self):
        super(WhenTestingComputedSecretStoreFields, self).setUp()
        utils.set_version(self.app, '1.3')

    def _get_secret(self, secret_uuid, multiple_backends=True,
                    expect_errors=False):
        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=multiple_backends):
            return self.app.get(
                '/secrets/{0}'.format(secret_uuid),
                expect_errors=expect_errors)

    def test_get_includes_null_store_fields_when_backends_disabled(self):
        resp, secret_uuid = test_secrets.create_secret(
            self.app, payload='payload', content_type='text/plain')
        self.assertEqual(201, resp.status_int)

        resp = self._get_secret(secret_uuid, multiple_backends=False)

        self.assertEqual(200, resp.status_int)
        self.assertIn('secret_store_id', resp.json)
        self.assertIn('secret_store_ref', resp.json)
        self.assertIsNone(resp.json['secret_store_id'])
        self.assertIsNone(resp.json['secret_store_ref'])

    def test_get_includes_null_store_fields_for_metadata_only_secret(self):
        resp, secret_uuid = test_secrets.create_secret(
            self.app, name='metadata-only')
        self.assertEqual(201, resp.status_int)

        resp = self._get_secret(secret_uuid, multiple_backends=True)

        self.assertEqual(200, resp.status_int)
        self.assertIsNone(resp.json['secret_store_id'])
        self.assertIsNone(resp.json['secret_store_ref'])

    @mock.patch(
        'barbican.plugin.resources.resolve_secret_store_for_secret',
        autospec=True)
    def test_get_includes_resolved_store_fields(self, mock_resolve):
        store = mock.MagicMock()
        store.id = '93869b0f-60eb-4830-adb9-e2f7154a080b'
        mock_resolve.return_value = store
        resp, secret_uuid = test_secrets.create_secret(
            self.app, payload='payload', content_type='text/plain')
        self.assertEqual(201, resp.status_int)

        resp = self._get_secret(secret_uuid, multiple_backends=True)

        self.assertEqual(200, resp.status_int)
        self.assertEqual(store.id, resp.json['secret_store_id'])
        self.assertIn(store.id, resp.json['secret_store_ref'])

    @mock.patch(
        'barbican.plugin.resources.resolve_secret_store_for_secret',
        autospec=True,
        side_effect=exception.SecretStoreNotResolved(
            secret_id='ignored'))
    def test_get_returns_500_when_store_unresolved(self, _mock_resolve):
        resp, secret_uuid = test_secrets.create_secret(
            self.app, payload='payload', content_type='text/plain')
        self.assertEqual(201, resp.status_int)

        resp = self._get_secret(
            secret_uuid, multiple_backends=True, expect_errors=True)

        self.assertEqual(500, resp.status_int)

    def test_get_omits_store_fields_on_microversion_1_2(self):
        utils.set_version(self.app, '1.2')
        resp, secret_uuid = test_secrets.create_secret(
            self.app, payload='payload', content_type='text/plain')
        self.assertEqual(201, resp.status_int)

        resp = self._get_secret(secret_uuid, multiple_backends=True)

        self.assertEqual(200, resp.status_int)
        self.assertNotIn('secret_store_id', resp.json)
        self.assertNotIn('secret_store_ref', resp.json)

    def test_list_includes_store_fields(self):
        resp, secret_uuid = test_secrets.create_secret(
            self.app, payload='payload', content_type='text/plain')
        self.assertEqual(201, resp.status_int)

        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=False):
            resp = self.app.get('/secrets/')

        self.assertEqual(200, resp.status_int)
        listed = resp.json['secrets']
        self.assertGreater(len(listed), 0)
        self.assertIn('secret_store_id', listed[0])
        self.assertIn('secret_store_ref', listed[0])
        self.assertIsNone(listed[0]['secret_store_id'])

    def test_consumer_post_includes_store_fields(self):
        resp, secret_uuid = test_secrets.create_secret(
            self.app, payload='payload', content_type='text/plain')
        self.assertEqual(201, resp.status_int)

        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=False):
            consumer_resp, _ = test_secrets.create_secret_consumer(
                self.app,
                secret_id=secret_uuid,
                service='cinder',
                resource_type='volume',
                resource_id='vol-1')

        self.assertEqual(200, consumer_resp.status_int)
        self.assertIn('secret_store_id', consumer_resp.json)
        self.assertIn('secret_store_ref', consumer_resp.json)
        self.assertIsNone(consumer_resp.json['secret_store_id'])
        self.assertIn('consumers', consumer_resp.json)


class WhenTestingEffectiveSecretStoreId(utils.BaseTestCase):

    def test_returns_project_preferred_store_id(self):
        project = mock.MagicMock()
        project.id = 'proj-id'
        preferred = mock.MagicMock()
        preferred.id = 'preferred-uuid'
        project_store = mock.MagicMock()
        project_store.secret_store = preferred
        proj_repo = mock.MagicMock()
        proj_repo.get_secret_store_for_project.return_value = project_store
        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=True), mock.patch(
                    'barbican.plugin.resources.repos.'
                    'get_project_secret_store_repository',
                    return_value=proj_repo):
            store_id = plugin.get_effective_secret_store_id_for_project(
                project)
        self.assertEqual('preferred-uuid', store_id)

    def test_falls_back_to_global_default_store_id(self):
        project = mock.MagicMock()
        project.id = 'proj-id'
        proj_repo = mock.MagicMock()
        proj_repo.get_secret_store_for_project.return_value = None
        default_store = mock.MagicMock()
        default_store.id = 'global-default-uuid'
        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=True), mock.patch(
                    'barbican.plugin.resources.repos.'
                    'get_project_secret_store_repository',
                    return_value=proj_repo), mock.patch(
                        'barbican.plugin.util.multiple_backends.'
                        'get_global_default_secret_store',
                        return_value=default_store):
            store_id = plugin.get_effective_secret_store_id_for_project(
                project)
        self.assertEqual('global-default-uuid', store_id)

    def test_returns_none_without_preferred_or_global_default(self):
        project = mock.MagicMock()
        project.id = 'proj-id'
        proj_repo = mock.MagicMock()
        proj_repo.get_secret_store_for_project.return_value = None
        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=True), mock.patch(
                    'barbican.plugin.resources.repos.'
                    'get_project_secret_store_repository',
                    return_value=proj_repo), mock.patch(
                        'barbican.plugin.util.multiple_backends.'
                        'get_global_default_secret_store',
                        return_value=None):
            store_id = plugin.get_effective_secret_store_id_for_project(
                project)
        self.assertIsNone(store_id)

    def test_returns_none_when_multiple_backends_disabled(self):
        project = mock.MagicMock()
        with mock.patch(
                'barbican.common.utils.is_multiple_backends_enabled',
                autospec=True,
                return_value=False):
            store_id = plugin.get_effective_secret_store_id_for_project(
                project)
        self.assertIsNone(store_id)


class WhenTestingCredentialsForPolicy(utils.BaseTestCase):

    def test_migrate_copies_path_store_id_onto_creds(self):
        ctx = context.RequestContext(
            policy_enforcer=mock.Mock(),
            user_id='user-1',
            project_id='proj-1',
            roles=['member'])
        dest = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        creds = controllers._credentials_for_policy(
            ctx, 'secret:migrate_secretstore',
            {'req_secret_store_id': dest})
        self.assertEqual(dest, creds['secret_store_id'])
        self.assertIsNot(creds, ctx)
        self.assertNotIn('secret_store_id', ctx.to_policy_values())

    def test_other_actions_leave_context_unchanged(self):
        ctx = context.RequestContext(
            policy_enforcer=mock.Mock(),
            user_id='user-1',
            project_id='proj-1',
            roles=['member'])
        creds = controllers._credentials_for_policy(
            ctx, 'secret:get',
            {'req_secret_store_id': 'ignored'})
        self.assertIs(creds, ctx)


class WhenTestingSecretMigrateMemberPolicy(
        utils.BarbicanAPIBaseTestCase,
        SecretStoresMixin,
        test_policy.BaseTestCase):

    def setUp(self):
        super(WhenTestingSecretMigrateMemberPolicy, self).setUp()
        config.CONF.set_override(
            'enforce_new_defaults', True, group='oslo_policy')
        utils.set_version(self.app, '1.3')
        self.secret_stores_repo = repos.get_secret_stores_repository()
        self.proj_store_repo = repos.get_project_secret_store_repository()

    def _create_secret_for_member_policy(self):
        return test_secrets.create_secret(
            self.app,
            payload='migrate-me',
            content_type='text/plain')[1]

    def _enable_multiple_backends(self):
        self._init_multiple_backends(global_default_index=1)
        self.secret_stores_repo = repos.get_secret_stores_repository()

    def _member_environ(self):
        return {
            'barbican.context': self._build_context(
                self.project_id,
                roles=['member'],
                user_id='member-user',
                is_admin=False,
                policy_enforcer=self.policy_enforcer),
            'key-manager.microversion': '1.3',
        }

    def _put_migrate_as_member(self, secret_uuid, store_id,
                               expect_errors=False):
        self.app.extra_environ = self._member_environ()
        return self.app.put(
            '/secrets/{0}/secret-store/{1}'.format(secret_uuid, store_id),
            expect_errors=expect_errors)

    @mock.patch('barbican.plugin.resources.rewrap_secret', autospec=True)
    def test_member_migrate_to_preferred_store_returns_204(
            self, mock_rewrap):
        secret_uuid = self._create_secret_for_member_policy()
        self._enable_multiple_backends()
        stores = self.secret_stores_repo.get_all()
        preferred_id = stores[0].id
        other_id = stores[2].id
        project = repos.get_secret_repository().get(
            secret_uuid, self.project_id).project
        self._create_project_store(project.id, preferred_id)

        resp = self._put_migrate_as_member(secret_uuid, preferred_id)
        self.assertEqual(204, resp.status_int)
        self.assertTrue(mock_rewrap.called)

        resp = self._put_migrate_as_member(
            secret_uuid, other_id, expect_errors=True)
        self.assertEqual(403, resp.status_int)

    @mock.patch('barbican.plugin.resources.rewrap_secret', autospec=True)
    def test_member_migrate_to_global_default_when_no_preferred(
            self, mock_rewrap):
        secret_uuid = self._create_secret_for_member_policy()
        self._enable_multiple_backends()
        stores = self.secret_stores_repo.get_all()
        global_default_id = next(s.id for s in stores if s.global_default)
        other_id = next(s.id for s in stores if not s.global_default)

        resp = self._put_migrate_as_member(secret_uuid, global_default_id)
        self.assertEqual(204, resp.status_int)

        resp = self._put_migrate_as_member(
            secret_uuid, other_id, expect_errors=True)
        self.assertEqual(403, resp.status_int)

    @mock.patch('barbican.plugin.resources.rewrap_secret', autospec=True)
    def test_member_migrate_denied_when_no_preferred_or_default(
            self, _mock_rewrap):
        secret_uuid = self._create_secret_for_member_policy()
        self._enable_multiple_backends()
        store = self.secret_stores_repo.get_all()[0]
        with mock.patch(
                'barbican.plugin.resources.'
                'get_effective_secret_store_id_for_project',
                autospec=True,
                return_value=None):
            resp = self._put_migrate_as_member(
                secret_uuid, store.id, expect_errors=True)
        self.assertEqual(403, resp.status_int)
