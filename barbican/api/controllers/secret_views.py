#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

"""Shared secret HTTP helpers used by more than one controller.

Kept out of secrets.py so consumers.py can build secret responses without
importing the secrets controller (which would be a circular import).
"""

import pecan

from barbican.api.controllers import versions
from barbican.common import hrefs
from barbican.common import utils
from barbican import i18n as u
from barbican.plugin import resources as plugin
from barbican.plugin.util import mime_types


def secret_not_found():
    """Throw exception indicating secret not found."""
    pecan.abort(404, u._('Secret not found.'))


def secret_to_response(secret, request, transport_key_id=None):
    """Build a secret HTTP body for the request microversion.

    Centralizes content-types, hrefs, consumers (1.1), and computed
    secret-store fields (1.3) so every return path uses one helper.
    """
    fields = mime_types.augment_fields_with_content_types(secret)
    if transport_key_id:
        fields['transport_key_id'] = transport_key_id
    resp = hrefs.convert_to_hrefs(fields)
    if versions.is_supported(request, max_version='1.0'):
        resp.pop('consumers', None)
    if versions.is_supported(request, min_version='1.3'):
        store = None
        if utils.is_multiple_backends_enabled():
            store = plugin.resolve_secret_store_for_secret(secret)
        if store is None:
            resp['secret_store_id'] = None
            resp['secret_store_ref'] = None
        else:
            resp['secret_store_id'] = store.id
            resp['secret_store_ref'] = hrefs.convert_secret_stores_to_href(
                store.id)
    return resp
