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

from barbican.plugin.util import utils as plugin_utils
from barbican.tests import utils as test_utils


class ExtensionStub(object):

    def __init__(self):
        self.name = 'my_name'
        self.plugin_instance = 'my_instance'
        self.obj = None
        self.exc = None
        self.args = None
        self.kwargs = None

    def plugin(self, *args, **kwargs):
        if self.exc:
            raise self.exc

        self.args = args
        self.kwargs = kwargs
        return self.plugin_instance

    def set_raise_exception(self, exc):
        self.exc = exc


class ManagerStub(object):
    def __init__(self, extensions):
        self.extensions = extensions


class WhenInvokingInstantiatePlugins(test_utils.BaseTestCase):
    def setUp(self):
        super(WhenInvokingInstantiatePlugins, self).setUp()

        self.extension = ExtensionStub()
        self.manager = ManagerStub([self.extension])

    def test_creates_plugin_instance(self):
        args = ('foo', 'bar')
        kwargs = {'foo': 1}

        plugin_utils.instantiate_plugins(
            self.manager, invoke_args=args, invoke_kwargs=kwargs)

        self.assertEqual('my_instance', self.extension.obj)
        self.assertEqual(args, self.extension.args)
        self.assertEqual(kwargs, self.extension.kwargs)

    def test_does_not_create_plugin_instance_due_to_error(self):
        self.extension.set_raise_exception(ValueError())

        plugin_utils.instantiate_plugins(self.manager)

        self.assertIsNone(self.extension.obj)
