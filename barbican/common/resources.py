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

"""
Shared business logic.
"""
from sys import getsizeof
from oslo.config import cfg
from barbican.common import exception
from barbican.model import models
from barbican.common import utils

LOG = utils.getLogger(__name__)


DEFAULT_MAX_SECRET_BYTES = 10000
common_opts = [
    cfg.IntOpt('max_allowed_secret_in_bytes',
               default=DEFAULT_MAX_SECRET_BYTES),
]

CONF = cfg.CONF
CONF.register_opts(common_opts)


def get_or_create_tenant(keystone_id, tenant_repo):
    """
    Returns tenant with matching keystone_id.  Creates it if it does
    not exist.
    """
    tenant = tenant_repo.find_by_keystone_id(keystone_id,
                                             suppress_exception=True)
    if not tenant:
        LOG.debug('Creating tenant for {0}'.format(keystone_id))
        tenant = models.Tenant()
        tenant.keystone_id = keystone_id
        tenant.status = models.States.ACTIVE
        tenant_repo.create_from(tenant)
    return tenant


def create_secret(data, tenant, crypto_manager,
                  secret_repo, tenant_secret_repo, datum_repo,
                  ok_to_generate=False):
    """
    Common business logic to create a secret.
    """
    new_secret = models.Secret(data)
    new_datum = None

    if 'plain_text' in data:

        plain_text = data['plain_text']

        if not plain_text:
            raise exception.NoDataToProcess()

        if getsizeof(plain_text) > CONF.max_allowed_secret_in_bytes:
            raise exception.LimitExceeded()

        LOG.debug('Encrypting plain_text secret...')
        new_datum = crypto_manager.encrypt(data['plain_text'],
                                           new_secret,
                                           tenant)
    elif ok_to_generate:
        LOG.debug('Generating new secret...')

        # TODO: Generate a good key
        new_datum = crypto_manager.generate_data_encryption_key(new_secret,
                                                                tenant)
    else:
        LOG.debug('Creating metadata only for the new secret. '
                  'A subsequent PUT is required')
        crypto_manager.supports(new_secret, tenant)

    # Create Secret entities in datastore.
    secret_repo.create_from(new_secret)
    new_assoc = models.TenantSecret()
    new_assoc.tenant_id = tenant.id
    new_assoc.secret_id = new_secret.id
    new_assoc.role = "admin"
    new_assoc.status = models.States.ACTIVE
    tenant_secret_repo.create_from(new_assoc)
    if new_datum:
        new_datum.secret_id = new_secret.id
        datum_repo.create_from(new_datum)

    return new_secret


def create_encrypted_datum(secret, plain_text, tenant, crypto_manager,
                           tenant_secret_repo, datum_repo):
    """
    Modifies the secret to add the plain_text secret information.

    :param secret: the secret entity to associate the secret data to
    :param plain_text: plain-text of the secret data to store
    :param tenant: the tenant (entity) who owns the secret
    :param crypto_manager: the crypto plugin manager
    :param tenant_secret_repo: the tenant/secret association repository
    :param datum_repo: the encrypted datum repository
    :retval The response body, None if N/A
    """
    if not plain_text:
        raise exception.NoDataToProcess()

    if getsizeof(plain_text) > CONF.max_allowed_secret_in_bytes:
        raise exception.LimitExceeded()

    if secret.encrypted_data:
        raise ValueError('Secret already has encrypted data stored for it.')

    fields = secret.to_dict_fields()
    fields['plain_text'] = plain_text

    # Encrypt plain_text
    LOG.debug('Encrypting plain_text secret')
    new_datum = crypto_manager.encrypt(plain_text,
                                       secret,
                                       tenant)
    datum_repo.create_from(new_datum)

    # Create Tenant/Secret entity.
    new_assoc = models.TenantSecret()
    new_assoc.tenant_id = tenant.id
    new_assoc.secret_id = secret.id
    new_assoc.role = "admin"
    new_assoc.status = models.States.ACTIVE
    tenant_secret_repo.create_from(new_assoc)

    return new_datum
