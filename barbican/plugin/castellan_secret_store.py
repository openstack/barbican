# Copyright (c) 2018 Red Hat Inc.
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

import abc
import six

from castellan.common.objects import opaque_data
from castellan import key_manager
from oslo_context import context
from oslo_log import log

from barbican.plugin.interface import secret_store as ss

LOG = log.getLogger(__name__)


class CastellanSecretStore(ss.SecretStoreBase, metaclass=abc.ABCMeta):

    KEY_ID = "key_id"
    ALG = "alg"
    BIT_LENGTH = "bit_length"

    def _set_params(self, conf):
        self.key_manager = key_manager.API(conf)
        self.context = context.get_current()

    @abc.abstractmethod
    def get_conf(self, conf):
        """Get plugin configuration

        This method is supposed to be implemented by the relevant
        subclass.  This method reads in the config for the plugin
        in barbican.conf -- which should look like the way other
        barbican plugins are configured, and convert them to the
        proper oslo.config object to be passed to the keymanager
        API. (keymanager.API(conf)

        @returns oslo.config object
        """
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def get_plugin_name(self):
        """Get plugin name

        This method is implemented by the subclass.
        Note that this name must be unique across the deployment.
        """
        raise NotImplementedError  # pragma: no cover

    def get_secret(self, secret_type, secret_metadata):
        secret_ref = secret_metadata[CastellanSecretStore.KEY_ID]
        try:
            secret = self.key_manager.get(
                self.context,
                secret_ref)

            return ss.SecretDTO(secret_type, secret.get_encoded(),
                                ss.KeySpec(), secret_metadata['content_type'])
        except Exception as e:
            LOG.exception("Error retrieving secret {}: {}".format(
                secret_ref, six.text_type(e)))
            raise ss.SecretGeneralException(e)

    def store_secret(self, secret_dto):
        if not self.store_secret_supports(secret_dto.key_spec):
            raise ss.SecretAlgorithmNotSupportedException(
                secret_dto.key_spec.alg)

        try:
            secret_ref = self.key_manager.store(
                self.context,
                opaque_data.OpaqueData(secret_dto.secret)
            )
            return {CastellanSecretStore.KEY_ID: secret_ref}
        except Exception as e:
            LOG.exception("Error storing secret: {}".format(
                six.text_type(e)))
            raise ss.SecretGeneralException(e)

    def delete_secret(self, secret_metadata):
        secret_ref = secret_metadata[CastellanSecretStore.KEY_ID]
        try:
            self.key_manager.delete(
                self.context,
                secret_ref)
        except KeyError:
            LOG.warning("Attempting to delete a non-existent secret {}".format(
                secret_ref))
        except Exception as e:
            LOG.exception("Error deleting secret: {}".format(
                six.text_type(e)))
            raise ss.SecretGeneralException(e)

    def generate_symmetric_key(self, key_spec):
        if not self.generate_supports(key_spec):
            raise ss.SecretAlgorithmNotSupportedException(
                key_spec.alg)
        try:
            secret_ref = self.key_manager.create_key(
                self.context,
                key_spec.alg,
                key_spec.bit_length
            )
            return {CastellanSecretStore.KEY_ID: secret_ref}
        except Exception as e:
            LOG.exception("Error generating symmetric key: {}".format(
                six.text_type(e)))
            raise ss.SecretGeneralException(e)

    def generate_asymmetric_key(self, key_spec):
        if not self.generate_supports(key_spec):
            raise ss.SecretAlgorithmNotSupportedException(
                key_spec.alg)

        if key_spec.passphrase:
            raise ss.GeneratePassphraseNotSupportedException()

        try:
            private_ref, public_ref = self.key_manager.create_key_pair(
                self.context,
                key_spec.alg,
                key_spec.bit_length
            )

            private_key_metadata = {
                CastellanSecretStore.ALG: key_spec.alg,
                CastellanSecretStore.BIT_LENGTH: key_spec.bit_length,
                CastellanSecretStore.KEY_ID: private_ref
            }

            public_key_metadata = {
                CastellanSecretStore.ALG: key_spec.alg,
                CastellanSecretStore.BIT_LENGTH: key_spec.bit_length,
                CastellanSecretStore.KEY_ID: public_ref
            }

            return ss.AsymmetricKeyMetadataDTO(
                private_key_metadata,
                public_key_metadata,
                None
            )
        except Exception as e:
            LOG.exception("Error generating asymmetric key: {}".format(
                six.text_type(e)))
            raise ss.SecretGeneralException(e)

    @abc.abstractmethod
    def store_secret_supports(self, key_spec):
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def generate_supports(self, key_spec):
        raise NotImplementedError  # pragma: no cover
