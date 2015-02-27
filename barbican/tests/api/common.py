# Copyright (c) 2015 Ericsson AB.
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

import mock


class MockModelRepositoryMixin(object):
    """Class for setting up the repo factory mocks

    This class has the purpose of setting up the mocks for the model repository
    factory functions. This is because the are intended to be singletons, and
    thus called inside the code-base, and not really passed around as
    arguments. Thus, this kind of approach is needed.

    The functions assume that the class that inherits from this is a test case
    fixture class. This is because as a side-effect patcher objects will be
    added to the class, and also the cleanup of these patcher objects will be
    added to the tear-down of the respective classes.
    """

    def setup_container_consumer_repository_mock(
            self, mock_container_consumer_repo=mock.MagicMock()):
        """Mocks the container consumer repository factory function

        :param mock_container_consumer_repo: The pre-configured mock
                                             container consumer repo to be
                                             returned.
        """
        self.mock_container_consumer_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_container_consumer_repository',
            mock_repo_obj=mock_container_consumer_repo,
            patcher_obj=self.mock_container_consumer_repo_patcher)

    def setup_container_repository_mock(self,
                                        mock_container_repo=mock.MagicMock()):
        """Mocks the container repository factory function

        :param mock_container_repo: The pre-configured mock
                                             container repo to be returned.
        """
        self.mock_container_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_container_repository',
            mock_repo_obj=mock_container_repo,
            patcher_obj=self.mock_container_repo_patcher)

    def setup_encrypted_datum_repository_mock(
            self, mock_encrypted_datum_repo=mock.MagicMock()):
        """Mocks the encrypted datum repository factory function

        :param mock_encrypted_datum_repo: The pre-configured mock
                                          encrypted datum repo to be returned.
        """
        self.mock_encrypted_datum_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_encrypted_datum_repository',
            mock_repo_obj=mock_encrypted_datum_repo,
            patcher_obj=self.mock_encrypted_datum_repo_patcher)

    def setup_kek_datum_repository_mock(self,
                                        mock_kek_datum_repo=mock.MagicMock()):
        """Mocks the kek datum repository factory function

        :param mock_kek_datum_repo: The pre-configured mock kek-datum repo to
                                    be returned.
        """
        self.mock_kek_datum_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_kek_datum_repository',
            mock_repo_obj=mock_kek_datum_repo,
            patcher_obj=self.mock_kek_datum_repo_patcher)

    def setup_order_repository_mock(self, mock_order_repo=mock.MagicMock()):
        """Mocks the order repository factory function

        :param mock_order_repo: The pre-configured mock order repo to be
                                returned.
        """
        self.mock_order_repo_patcher = None
        self._setup_repository_mock(repo_factory='get_order_repository',
                                    mock_repo_obj=mock_order_repo,
                                    patcher_obj=self.mock_order_repo_patcher)

    def setup_project_repository_mock(self,
                                      mock_project_repo=mock.MagicMock()):
        """Mocks the project repository factory function

        :param mock_project_repo: The pre-configured mock project repo to be
                                  returned.
        """
        self.mock_project_repo_patcher = None
        self._setup_repository_mock(repo_factory='get_project_repository',
                                    mock_repo_obj=mock_project_repo,
                                    patcher_obj=self.mock_project_repo_patcher)

    def setup_project_secret_repository_mock(
            self, mock_project_secret_repo=mock.MagicMock()):
        """Mocks the project-secret repository factory function

        :param mock_project_secret_repo: The pre-configured mock project-secret
                                         repo to be returned.
        """
        self.mock_project_secret_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_project_secret_repository',
            mock_repo_obj=mock_project_secret_repo,
            patcher_obj=self.mock_project_secret_repo_patcher)

    def setup_secret_meta_repository_mock(
            self, mock_secret_meta_repo=mock.MagicMock()):
        """Mocks the secret-meta repository factory function

        :param mock_secret_meta_repo: The pre-configured mock secret-meta repo
                                      to be returned.
        """
        self.mock_secret_meta_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_secret_meta_repository',
            mock_repo_obj=mock_secret_meta_repo,
            patcher_obj=self.mock_secret_meta_repo_patcher)

    def setup_secret_repository_mock(self, mock_secret_repo=mock.MagicMock()):
        """Mocks the secret repository factory function

        :param mock_secret_repo: The pre-configured mock secret repo to be
                                 returned.
        """
        self.mock_secret_repo_patcher = None
        self._setup_repository_mock(repo_factory='get_secret_repository',
                                    mock_repo_obj=mock_secret_repo,
                                    patcher_obj=self.mock_secret_repo_patcher)

    def setup_transport_key_repository_mock(
            self, mock_transport_key_repo=mock.MagicMock()):
        """Mocks the transport-key repository factory function

        :param mock_transport_key_repo: The pre-configured mock transport_key
                                        repo to be returned.
        """
        self.mock_transport_key_repo_patcher = None
        self._setup_repository_mock(
            repo_factory='get_transport_key_repository',
            mock_repo_obj=mock_transport_key_repo,
            patcher_obj=self.mock_transport_key_repo_patcher)

    def _setup_repository_mock(self, repo_factory, mock_repo_obj, patcher_obj):
        patcher_obj = mock.patch(
            'barbican.model.repositories.' + repo_factory,
            return_value=mock_repo_obj
        )
        patcher_obj.start()
        self.addCleanup(patcher_obj.stop)
