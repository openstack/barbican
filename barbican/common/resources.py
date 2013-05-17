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
from barbican.crypto.extension_manager import (
    CryptoMimeTypeNotSupportedException
)
from barbican.model.models import (Tenant, Secret, TenantSecret, States)
from barbican.common import utils

LOG = utils.getLogger(__name__)


def get_or_create_tenant(tenant_id, tenant_repo):
    """Returns tenant with matching tenant_id.  Creates it if it does
    not exist."""
    tenant = tenant_repo.get(tenant_id, suppress_exception=True)
    if not tenant:
        LOG.debug('Creating tenant for {0}'.format(tenant_id))
        tenant = Tenant()
        tenant.keystone_id = tenant_id
        tenant.status = States.ACTIVE
        tenant_repo.create_from(tenant)
    return tenant


def create_secret(data, tenant, crypto_manager,
                  secret_repo, tenant_secret_repo, datum_repo,
                  ok_to_generate=False):

    # TODO: revisit ok_to_generate

    # TODO: What if any criteria to restrict new secrets vs existing ones?
    # Verify secret doesn't already exist.
    #
    #name = data['name']
    #LOG.debug('Secret name is {0}'.format(name))
    #secret = secret_repo.find_by_name(name=name,
    #                                       suppress_exception=True)
    #if secret:
    #    abort(falcon.HTTP_400, 'Secret with name {0} '
    #                           'already exists'.format(name))

    new_secret = Secret(data)
    secret_repo.create_from(new_secret)

    # Create Tenant/Secret entity.
    new_assoc = TenantSecret()
    new_assoc.tenant_id = tenant.id
    new_assoc.secret_id = new_secret.id
    new_assoc.role = "admin"
    new_assoc.status = States.ACTIVE
    tenant_secret_repo.create_from(new_assoc)

    if 'plain_text' in data:
        LOG.debug('Encrypting plain_text secret...')
        new_datum = crypto_manager.encrypt(data['plain_text'],
                                           new_secret,
                                           tenant)
        datum_repo.create_from(new_datum)
    elif ok_to_generate:
        LOG.debug('Generating new secret...')

        # TODO: Generate a good key
        new_datum = crypto_manager.generate_data_encryption_key(new_secret,
                                                                tenant)
        datum_repo.create_from(new_datum)
    else:
        LOG.debug('Creating metadata only for the new secret. '
                  'A subsequent PUT is required')
        crypto_manager.supports(new_secret, tenant)

    return new_secret


def create_encrypted_datum(secret, plain_text, tenant, crypto_manager,
                           tenant_secret_repo, datum_repo):
    """
    Modifies the secret to add the plain_text secret information.

    :param secret: the secret entity to associate the secret data to
    :param plain_text: plain-text of the secret data to store
    :param tenant: the tenant who owns the secret
    :param crypto_manager: the crypto plugin manager
    :param tenant_secret_repo: the tenant/secret association repository
    :param datum_repo: the encrypted datum repository
    :retval The response body, None if N/A
    """
    if not plain_text:
        raise ValueError('Must provide plain-text to encrypt.')

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
    new_assoc = TenantSecret()
    new_assoc.tenant_id = tenant
    new_assoc.secret_id = secret.id
    new_assoc.role = "admin"
    new_assoc.status = States.ACTIVE
    tenant_secret_repo.create_from(new_assoc)

    return new_datum
