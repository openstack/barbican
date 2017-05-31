# Copyright (c) 2016 Rackspace, Inc.
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

import os
import time

from testtools import testcase

from barbican.common import config as barbican_config
from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config
from oslo_db.sqlalchemy import session

# Import and configure logging.
BCONF = barbican_config.CONF
CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
admin_b = CONF.rbac_users.admin_b


class DBManageTestCase(base.TestCase):

    def setUp(self):
        super(DBManageTestCase, self).setUp()
        self.sbehaviors = secret_behaviors.SecretBehaviors(self.client)
        self.cbehaviors = container_behaviors.ContainerBehaviors(self.client)

        db_url = BCONF.sql_connection

        time.sleep(5)
        # Setup session for tests to query DB
        engine = session.create_engine(db_url)
        self.conn = engine.connect()

    def tearDown(self):
        super(DBManageTestCase, self).tearDown()
        self.conn.close()
        self.sbehaviors.delete_all_created_secrets()
        self.cbehaviors.delete_all_created_containers()

    def _create_secret_list(self,
                            user,
                            delete=False,
                            expiration="2050-02-28T19:14:44.180394"):

        secret_defaults_data = {
            "name": "AES key",
            "expiration": expiration,
            "algorithm": "aes",
            "bit_length": 256,
            "mode": "cbc",
            "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
            "payload_content_type": "application/octet-stream",
            "payload_content_encoding": "base64",
        }

        secret_list = []

        for i in range(0, 5):
            secret_model = secret_models.SecretModel(**secret_defaults_data)
            resp, secret_ref = self.sbehaviors.create_secret(secret_model,
                                                             user_name=user)

            self.assertEqual(resp.status_code, 201)
            self.assertIsNotNone(secret_ref)

            secret_list.append(secret_ref)

        if delete is True:
            self._delete_secret_list(secret_list, user)

        return secret_list

    def _create_container_uuid_list(
            self,
            user,
            secret_expiration="2050-02-28T19:14:44.180394",
            delete_secret=False,
            delete_container=False):

        secret_list = self._create_secret_list(
            user=user,
            expiration=secret_expiration
        )

        container_data = {
            "name": "containername",
            "type": "generic",
            "secret_refs": [
                {
                    "name": "secret",
                    "secret_ref": secret_list[0]
                }
            ]
        }
        container_list = []

        for i in range(0, 5):
            container_model = container_models.ContainerModel(**container_data)
            post_container_resp, c_ref = self.cbehaviors.create_container(
                container_model,
                user_name=user)

            self.assertEqual(post_container_resp.status_code, 201)
            self.assertIsNotNone(c_ref)

            container_list.append(c_ref)

        if delete_container is True:
            self._delete_container_list(container_list, user)

        if delete_secret is True:
            self._delete_secret_list(secret_list)

        return container_list

    def _delete_secret_list(self, secret_list, user):

        for secret in secret_list:
            del_resp = self.sbehaviors.delete_secret(secret, user_name=user)
            self.assertEqual(del_resp.status_code, 204)

    def _delete_container_list(self, container_list, user):
        for container in container_list:
            del_resp = self.cbehaviors.delete_container(container,
                                                        user_name=user)
            self.assertEqual(del_resp.status_code, 204)

    def _get_uuid(self, ref):
        uuid = ref.split('/')[-1]

        return uuid

    @testcase.attr('positive')
    def test_active_secret_not_deleted(self):
        """Verify that active secrets are not removed"""
        project_a_secrets = self._create_secret_list(user=admin_a)
        project_b_secrets = self._create_secret_list(user=admin_b)

        os.system("python barbican/cmd/db_manage.py clean -m 0 -p -e")

        results = self.conn.execute("select * from secrets")
        secret_list = []
        for row in results:
            secret_list.append(str(row[0]))

        for secret in project_a_secrets:
            secret_uuid = self._get_uuid(secret)
            self.assertIn(secret_uuid, secret_list)

        for secret in project_b_secrets:
            secret_uuid = self._get_uuid(secret)
            self.assertIn(secret_uuid, secret_list)

    @testcase.attr('positive')
    def test_soft_deleted_secrets_are_removed(self):
        """Test that soft deleted secrets are removed"""

        project_a_secrets = self._create_secret_list(user=admin_a,
                                                     delete=True)
        project_b_secrets = self._create_secret_list(user=admin_b,
                                                     delete=True)

        os.system("python barbican/cmd/db_manage.py clean -m 0 -p -e")

        results = self.conn.execute("select * from secrets")
        secret_list = []
        for row in results:
            secret_list.append(str(row[0]))

        for secret in project_a_secrets:
            secret_uuid = self._get_uuid(secret)
            self.assertNotIn(secret_uuid, secret_list)

        for secret in project_b_secrets:
            secret_uuid = self._get_uuid(secret)
            self.assertNotIn(secret_uuid, secret_list)

    @testcase.attr('positive')
    def test_expired_secrets_are_not_removed_from_db(self):
        """Test expired secrests are left in soft deleted state.

        Currently this clean will set the threshold at the start
        of the test. Expired secrets will be deleted and the
        deleted at date will now be later then the threshold
        date.
        """

        current_time = utils.create_timestamp_w_tz_and_offset(seconds=10)
        project_a_secrets = self._create_secret_list(user=admin_a,
                                                     expiration=current_time)
        project_b_secrets = self._create_secret_list(user=admin_b,
                                                     expiration=current_time)

        time.sleep(10)

        os.system("python barbican/cmd/db_manage.py clean -m 0 -p -e")

        results = self.conn.execute("select * from secrets")
        secret_list = []
        for row in results:
            secret_list.append(str(row[0]))

        for secret in project_a_secrets:
            secret_uuid = self._get_uuid(secret)
            self.assertIn(secret_uuid, secret_list)

        for secret in project_b_secrets:
            secret_uuid = self._get_uuid(secret)
            self.assertIn(secret_uuid, secret_list)

    @testcase.attr('positive')
    def test_no_soft_deleted_secrets_in_db(self):
        """Test that no soft deleted secrets are in db"""
        os.system("python barbican/cmd/db_manage.py clean -m 0 -p -e")

        results = self.conn.execute("select * from secrets where deleted=1")
        secret_list = []
        for row in results:
            secret_list.append(str(row[0]))

        self.assertEqual(len(secret_list), 0)

    @testcase.attr('positive')
    def test_active_containers_not_deleted(self):
        """Active containers are not deleted"""
        project_a_containers = self._create_container_uuid_list(
            user=admin_a)
        project_b_containers = self._create_container_uuid_list(
            user=admin_b)

        os.system("python barbican/cmd/db_manage.py clean -m 0 -p -e")

        results = self.conn.execute("select * from containers")
        container_list = []
        for row in results:
            container_list.append(str(row[0]))

        for container in project_a_containers:
            container_uuid = self._get_uuid(container)
            self.assertIn(container_uuid, container_list)

        for container in project_b_containers:
            container_uuid = self._get_uuid(container)
            self.assertIn(container_uuid, container_list)

    @testcase.attr('positive')
    def test_cleanup_soft_deleted_containers(self):
        """Soft deleted containers are deleted"""
        project_a_delete_containers = self._create_container_uuid_list(
            user=admin_a,
            delete_container=True)
        project_b_delete_containers = self._create_container_uuid_list(
            user=admin_b,
            delete_container=True)

        os.system("python barbican/cmd/db_manage.py clean -m 0 -p -e")

        results = self.conn.execute("select * from containers")
        container_list = []
        for row in results:
            container_list.append(str(row[0]))

        for container in project_a_delete_containers:
            container_uuid = self._get_uuid(container)
            self.assertNotIn(container_uuid, container_list)

        for container in project_b_delete_containers:
            container_uuid = self._get_uuid(container)
            self.assertNotIn(container_uuid, container_list)

    @testcase.attr('positive')
    def test_containers_with_expired_secrets_are_deleted(self):
        """Containers with expired secrets are deleted"""
        current_time = utils.create_timestamp_w_tz_and_offset(seconds=10)

        project_a_delete_containers = self._create_container_uuid_list(
            user=admin_a,
            delete_container=True,
            secret_expiration=current_time)
        project_b_delete_containers = self._create_container_uuid_list(
            user=admin_b,
            delete_container=True,
            secret_expiration=current_time)

        time.sleep(10)

        os.system("python barbican/cmd/db_manage.py clean -m 0 -p -e")

        results = self.conn.execute("select * from containers")
        container_list = []
        for row in results:
            container_list.append(str(row[0]))

        for container in project_a_delete_containers:
            container_uuid = self._get_uuid(container)
            self.assertNotIn(container_uuid, container_list)

        for container in project_b_delete_containers:
            container_uuid = self._get_uuid(container)
            self.assertNotIn(container_uuid, container_list)
