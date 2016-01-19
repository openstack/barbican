# Copyright (c) 2016 IBM
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

from barbican.model import clean
from barbican.model import models
from barbican.model import repositories as repos
from barbican.tests import database_utils as utils
from sqlalchemy.exc import IntegrityError


def _create_project(project_name):
    """Wrapper to create a project and clean"""
    def project_decorator(test_func):
        def project_wrapper(self, *args, **kwargs):
            project = utils.create_project(external_id=project_name)
            kwargs['project'] = project
            test_result = test_func(self, *args, **kwargs)
            project.delete()
            return test_result
        return project_wrapper
    return project_decorator


def _entry_exists(entry):
    """Check to see if entry should exist in the database"""
    model = entry.__class__
    entry_id = entry.id
    session = repos.get_session()
    query = session.query(model).filter(model.id == entry_id)
    count = query.count()
    return count >= 1


def _setup_entry(name, *args, **kwargs):
    func_name = "create_" + name
    if not hasattr(utils, func_name):
        raise Exception("Cannot create an entry called %s", name)
    func = getattr(utils, func_name)
    kwargs['session'] = repos.get_session()
    entry = func(*args, **kwargs)
    return entry


class WhenTestingDBCleanUpCommand(utils.RepositoryTestCase):

    def setUp(self):
        super(WhenTestingDBCleanUpCommand, self).setUp()

    def tearDown(self):
        super(WhenTestingDBCleanUpCommand, self).tearDown()
        repos.rollback()

    @_create_project("my keystone id")
    def test_soft_deleted_secret_orders(self, project):
        """Test that secrets without child order get deleted"""
        # Create a secret tied to an order and one secret that is not
        secret1 = _setup_entry('secret', project=project)
        secret2 = _setup_entry('secret', project=project)
        order = _setup_entry('order', project=project, secret=secret1)

        # Delete secrets
        secret1.delete()
        secret2.delete()
        clean.cleanup_parent_with_no_child(models.Secret, models.Order)
        # Assert that only secret2 is removed
        self.assertTrue(_entry_exists(secret1))
        self.assertFalse(_entry_exists(secret2))

        # delete order and secret
        order.delete()
        clean.cleanup_all()

        self.assertFalse(_entry_exists(order))
        self.assertFalse(_entry_exists(secret2))

    def test_cleanup_soft_deletes_transport_keys(self):
        """Test Cleaning up soft deleted transport keys"""
        # create transport key
        transport_key = _setup_entry('transport_key')

        # delete transport key
        transport_key.delete()
        clean.cleanup_all()
        self.assertFalse(_entry_exists(transport_key))

    @_create_project("my keystone id")
    def test_cleanup_soft_deletes_secrets(self, project):
        """Test cleaning up secrets and secret_meta"""
        # create secret and secret_meta
        secret = _setup_entry('secret', project=project)
        secret_metadatum = _setup_entry('secret_metadatum', secret=secret)
        kek_datum = _setup_entry('kek_datum', project=project)
        enc_datum = _setup_entry('encrypted_datum', secret=secret,
                                 kek_datum=kek_datum)
        # delete secret, it should automatically delete
        # secret_meta and enc_datum
        # kek_datum should still exist
        secret.delete()
        clean.cleanup_all()
        self.assertFalse(_entry_exists(secret))
        self.assertFalse(_entry_exists(secret_metadatum))
        self.assertFalse(_entry_exists(enc_datum))
        self.assertTrue(_entry_exists(kek_datum))

    @_create_project("my keystone id")
    def test_cleanup_soft_deletes_containers(self, project):
        """Test cleaning up containers and secrets"""
        # create container, secret, and container_secret
        container = _setup_entry('container', project=project)
        secret = _setup_entry('secret', project=project)
        container_secret = _setup_entry('container_secret',
                                        container=container, secret=secret)

        # delete container secret and container
        container.delete()
        clean.cleanup_all()

        # check that container secret and container are deleted
        # but secret still exists
        self.assertFalse(_entry_exists(container_secret))
        self.assertFalse(_entry_exists(container))
        self.assertTrue(_entry_exists(secret))

        # cleanup secrets
        secret.delete()
        clean.cleanup_all()
        self.assertFalse(_entry_exists(secret))

    @_create_project("my keystone id")
    def test_cleanup_container_with_order_child(self, project):
        container = _setup_entry('container', project=project)
        secret = _setup_entry('secret', project=project)
        secret_container = _setup_entry('container_secret',
                                        container=container, secret=secret)
        order = _setup_entry('order', project=project, secret=secret,
                             container=container)

        container.delete()
        clean.cleanup_all()

        # only the secret_container should be removed from the database
        # since it is a child of the container
        self.assertFalse(_entry_exists(secret_container))
        self.assertTrue(_entry_exists(secret))
        self.assertTrue(_entry_exists(order))
        # container should still exist since child order still exists
        self.assertTrue(_entry_exists(container))

        order.delete()
        clean.cleanup_all()

        # assert that only the secret exists
        self.assertFalse(_entry_exists(order))
        self.assertFalse(_entry_exists(container))
        self.assertTrue(_entry_exists(secret))

        secret.delete()
        clean.cleanup_all()
        # the secret should now be able to be removed
        self.assertFalse(_entry_exists(secret))

    @_create_project("my clean order keystone id")
    def test_cleanup_orders(self, project):
        """Test cleaning up an order and it's children"""
        # create order, order meta, and plugin meta, and retry task
        order = _setup_entry('order', project=project)
        order_barbican_meta_data = _setup_entry('order_meta_datum',
                                                order=order)
        order_plugin_metadata = _setup_entry('order_plugin_metadatum',
                                             order=order)
        order_retry_task = _setup_entry('order_retry', order=order)

        # soft delete order and retry task,
        # it should automatically delete the children
        order.delete()
        order_retry_task.delete()
        clean.cleanup_all()

        # assert everything has been cleaned up
        self.assertFalse(_entry_exists(order))
        self.assertFalse(_entry_exists(order_plugin_metadata))
        self.assertFalse(_entry_exists(order_retry_task))
        self.assertFalse(_entry_exists(order_barbican_meta_data))

    @_create_project("my clean order with child keystone id")
    def test_cleanup_order_with_child(self, project):
        """Test cleaning up an order with a child"""
        # create order and retry task
        order = _setup_entry('order', project=project)
        order_retry_task = _setup_entry('order_retry', order=order)

        # soft delete order and retry task,
        #  it should automatically delete the children
        order.delete()
        clean.cleanup_all()

        # assert that the order was not cleaned due to child
        self.assertTrue(_entry_exists(order))
        self.assertTrue(_entry_exists(order_retry_task))

        order_retry_task.delete()
        clean.cleanup_all()

        # assert everything has been cleaned up
        self.assertFalse(_entry_exists(order))
        self.assertFalse(_entry_exists(order_retry_task))

    @_create_project("my integrity error keystone id")
    def test_db_cleanup_raise_integrity_error(self, project):
        """Test that an integrity error is thrown

        This test tests the invalid scenario where
        the secret meta was not marked for deletion during the secret deletion.
        We want to make sure an integrity error is thrown during clean up.
        """
        # create secret
        secret = _setup_entry('secret', project=project)
        secret_metadatum = _setup_entry('secret_metadatum', secret=secret)

        # delete parent but not child and assert integrity error
        secret.deleted = True
        secret_metadatum.deleted = False

        self.assertRaises(IntegrityError, clean.cleanup_all)
