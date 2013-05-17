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
Barbican defined mime-types
"""

# Maps mime-types used to specify secret data formats to the types that can
#   be requested for secrets via GET calls.
CTYPES_PLAIN = {'default': 'text/plain'}
CTYPES_BINARY = {'default': 'application/octet-stream'}
CTYPES_AES = {'default': 'application/aes'}
CTYPES_MAPPINGS = {'text/plain': CTYPES_PLAIN,
                   'application/octet-stream': CTYPES_BINARY,
                   'application/aes': CTYPES_AES}


def augment_fields_with_content_types(secret):
    """Generate a dict of content types based on the data associated
    with the specified secret."""

    fields = secret.to_dict_fields()

    if not secret.encrypted_data:
        return fields

    # TODO: How deal with merging more than one datum instance?
    for datum in secret.encrypted_data:
        if datum.mime_type in CTYPES_MAPPINGS:
            fields.update({'content_types': CTYPES_MAPPINGS[datum.mime_type]})
            break

    return fields
