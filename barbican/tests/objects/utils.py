#    Copyright 2018 Fujitsu.
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
import mock


class MockObjectMixin(object):
    """Class for setting up the objects factory mocks"""

    def _setup_object_fuction_mock(self, object_name, function_name,
                                   return_value, side_effect):
        path_function = 'barbican.objects.{}.{}'.format(object_name,
                                                        function_name)
        patcher_obj = mock.patch(path_function,
                                 return_value=return_value,
                                 side_effect=side_effect)
        patcher_obj.start()
        self.addCleanup(patcher_obj.stop)

    def mock_container_obj_function(self, func_name,
                                    return_value=None, side_effect=None):
        self._setup_object_fuction_mock(object_name='Container',
                                        function_name=func_name,
                                        return_value=return_value,
                                        side_effect=side_effect)

    def mock_secret_obj_function(self, func_name,
                                 return_value=None, side_effect=None):
        self._setup_object_fuction_mock(object_name='Secret',
                                        function_name=func_name,
                                        return_value=return_value,
                                        side_effect=side_effect)

    def mock_container_acl_obj_function(self, func_name,
                                        return_value=None, side_effect=None):
        self._setup_object_fuction_mock(object_name='ContainerACL',
                                        function_name=func_name,
                                        return_value=return_value,
                                        side_effect=side_effect)

    def mock_order_obj_function(self, func_name,
                                return_value=None, side_effect=None):
        self._setup_object_fuction_mock(object_name='Order',
                                        function_name=func_name,
                                        return_value=return_value,
                                        side_effect=side_effect)

    def mock_con_con_obj_function(self, func_name,
                                  return_value=None, side_effect=None):
        self._setup_object_fuction_mock(
            object_name='ContainerConsumerMetadatum',
            function_name=func_name,
            return_value=return_value,
            side_effect=side_effect)
