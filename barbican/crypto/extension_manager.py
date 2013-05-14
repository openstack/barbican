# Copyright (c) 2013 Rackspace, Inc.
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

from stevedore import named

from barbican.common.exception import BarbicanException
from barbican.openstack.common.gettextutils import _


class CryptoMimeTypeNotSupportedException(BarbicanException):
    """Raised when support for requested mime type is
    not available in any active plugin."""
    def __init__(self, mime_type):
        super(CryptoMimeTypeNotSupportedException, self).__init__(
            _('Crypto Mime Type not supported {0}'.format(mime_type))
        )


class CryptoAccpetNotSupportedException(BarbicanException):
    """Raised when requested decripted format is not
    available in any active plugin."""
    def __init__(self, accept):
        super(CryptoAccpetNotSupportedException, self).__init__(
            _('Crypto Accept not supported {0}'.format(accept))
        )


class CryptoExtensionManager(named.NamedExtensionManager):
    def __init__(self, namespace, names,
                 invoke_on_load=True, invoke_args=(), invoke_kwargs={}):
        super(CryptoExtensionManager, self).__init__(
            namespace,
            names,
            invoke_on_load=invoke_on_load,
            invoke_args=invoke_args,
            invoke_kwds=invoke_kwargs
        )

    def encrypt(self, unencrypted, secret, tenant):
        """Delegates encryption to active plugins."""
        for ext in self.extensions:
            if ext.obj.supports(secret.mime_type):
                return ext.obj.encrypt(unencrypted, secret, tenant)
        else:
            raise CryptoMimeTypeNotSupportedException(secret.mime_type)

    def decrypt(self, accept, secret, tenant):
        """Delegates decryption to active plugins."""
        for ext in self.extensions:
            if ext.obj.supports(accept):
                return ext.obj.decrypt(accept, secret, tenant)
        else:
            raise CryptoAccpetNotSupportedException(accept)
