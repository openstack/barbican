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
import base64

from barbican.common import exception, validators
from barbican.model import models
from barbican.common import utils
from barbican.crypto import mime_types


LOG = utils.getLogger(__name__)


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
    time_keeper = utils.TimeKeeper('Create Secret Resource')
    new_secret = models.Secret(data)
    time_keeper.mark('after Secret model create')
    new_datum = None

    if 'payload' in data:
        payload = data.get('payload')
        content_type = data.get('payload_content_type')
        content_encoding = data.get('payload_content_encoding')
        if not payload:
            raise exception.NoDataToProcess()

        LOG.debug('Pre-processing payload...')
        if content_type in mime_types.PLAIN_TEXT:
            LOG.debug('Plain text payload.  No pre-processing needed.')
        elif content_type in mime_types.BINARY:
            # payload has to be decoded
            if content_encoding not in ['base64']:
                raise exception.InvalidContentEncoding(content_encoding)
            try:
                payload = base64.b64decode(payload)
            except TypeError:
                raise exception.PayloadDecodingError()
        else:
            raise exception.InvalidContentType()

        time_keeper.mark('after pre-processing')

        LOG.debug('Encrypting payload...')
        new_datum = crypto_manager.encrypt(payload,
                                           content_type,
                                           new_secret,
                                           tenant)
        time_keeper.mark('after encrypt')

    elif ok_to_generate:
        LOG.debug('Generating new secret...')
        new_datum = crypto_manager.generate_data_encryption_key(new_secret,
                                                                tenant)
        time_keeper.mark('after secret generate')

    else:
        LOG.debug('Creating metadata only for the new secret. '
                  'A subsequent PUT is required')

    # Create Secret entities in datastore.
    secret_repo.create_from(new_secret)
    time_keeper.mark('after Secret datastore create')
    new_assoc = models.TenantSecret()
    time_keeper.mark('after TenantSecret model create')
    new_assoc.tenant_id = tenant.id
    new_assoc.secret_id = new_secret.id
    new_assoc.role = "admin"
    new_assoc.status = models.States.ACTIVE
    tenant_secret_repo.create_from(new_assoc)
    time_keeper.mark('after TenantSecret datastore create')
    if new_datum:
        new_datum.secret_id = new_secret.id
        datum_repo.create_from(new_datum)
        time_keeper.mark('after Datum datastore create')

    time_keeper.dump()

    return new_secret


def create_encrypted_datum(secret, payload,
                           content_type, content_encoding,
                           tenant, crypto_manager,
                           tenant_secret_repo, datum_repo):
    """
    Modifies the secret to add the plain_text secret information.

    :param secret: the secret entity to associate the secret data to
    :param payload: secret data to store
    :param content_type: payload content mime type
    :param content_encoding: payload content encoding
    :param tenant: the tenant (entity) who owns the secret
    :param crypto_manager: the crypto plugin manager
    :param tenant_secret_repo: the tenant/secret association repository
    :param datum_repo: the encrypted datum repository
    :retval The response body, None if N/A
    """
    if not payload:
        raise exception.NoDataToProcess()

    if validators.secret_too_big(payload):
        raise exception.LimitExceeded()

    if secret.encrypted_data:
        raise ValueError('Secret already has encrypted data stored for it.')

    fields = secret.to_dict_fields()
    fields['payload'] = payload

    # Encrypt payload
    LOG.debug('Encrypting secret payload...')
    new_datum = crypto_manager.encrypt(payload,
                                       content_type,
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
