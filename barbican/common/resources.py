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

from barbican.model.models import (Tenant, Secret, TenantSecret,
                                   EncryptedDatum, Order, States)
from barbican.model.repositories import (TenantRepo, SecretRepo,
                                         OrderRepo, TenantSecretRepo,
                                         EncryptedDatumRepo)
from barbican.crypto.fields import encrypt, decrypt
from barbican.openstack.common import timeutils
from barbican.openstack.common.gettextutils import _
from barbican.openstack.common import jsonutils as json
from barbican.queue import get_queue_api
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


def create_secret(data, tenant_id, tenant_repo,
                  secret_repo, tenant_secret_repo,
                  datum_repo, ok_to_generate=False):
    # Create a Secret and a single EncryptedDatum for that Secret. Create
    #   a Tenant if one doesn't already exist.
    tenant = get_or_create_tenant(tenant_id, tenant_repo)

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

    # Encrypt fields.
    encrypt(data, ok_to_generate)
    LOG.debug('Post-encrypted fields...{0}'.format(data))
    secret_value = data['cypher_text'] if 'cypher_text' in data else None
    LOG.debug('Encrypted secret is {0}'.format(secret_value))

    # Create Secret entity.
    new_secret = Secret(data)

    # encrypt(new_secret)

    secret_repo.create_from(new_secret)

    # Create Tenant/Secret entity.
    new_assoc = TenantSecret()
    new_assoc.tenant_id = tenant.id
    new_assoc.secret_id = new_secret.id
    new_assoc.role = "admin"
    new_assoc.status = States.ACTIVE
    tenant_secret_repo.create_from(new_assoc)

    # Create EncryptedDatum entity if plain-text provided with secret request.
    if secret_value:
        new_datum = EncryptedDatum()
        new_datum.secret_id = new_secret.id
        new_datum.mime_type = data['mime_type']
        new_datum.cypher_text = secret_value
        new_datum.kek_metadata = data['kek_metadata']
        new_datum.status = States.ACTIVE
        datum_repo.create_from(new_datum)

    return new_secret


def create_encrypted_datum(secret, plain_text,
                           tenant_id, tenant_secret_repo, datum_repo):
    """
    Modifies the secret to add the plain_text secret information.

    :param secret: the secret entity to associate the secret data to
    :param plain_text: plain-text of the secret data to store
    :param tenant_id: the tenant's id
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

    # Encrypt fields.
    encrypt(fields)
    LOG.debug('Post-encrypted fields...{0}'.format(fields))
    if 'cypher_text' not in fields:
        raise ValueError('Could not encrypt information '
                         'and store in Barbican')
    secret_value = fields['cypher_text']
    LOG.debug('Encrypted secret is {0}'.format(secret_value))

    # Create Tenant/Secret entity.
    new_assoc = TenantSecret()
    new_assoc.tenant_id = tenant_id
    new_assoc.secret_id = secret.id
    new_assoc.role = "admin"
    new_assoc.status = States.ACTIVE
    tenant_secret_repo.create_from(new_assoc)

    # Create EncryptedDatum entity.
    new_datum = EncryptedDatum()
    new_datum.secret_id = secret.id
    new_datum.mime_type = fields['mime_type']
    new_datum.cypher_text = secret_value
    new_datum.kek_metadata = fields['kek_metadata']
    new_datum.status = States.ACTIVE
    datum_repo.create_from(new_datum)

    return new_datum
