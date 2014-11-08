# Copyright (c) 2013-2014 Rackspace, Inc.
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

from barbican.common import utils


# Supported content types
#   Note: These types may be provided by clients.
PLAIN_TEXT = ['text/plain',
              'text/plain;charset=utf-8',
              'text/plain; charset=utf-8']
PLAIN_TEXT_CHARSETS = ['utf-8']
BINARY = ['application/octet-stream']
SUPPORTED = PLAIN_TEXT + BINARY

# Normalizes client types to internal types.
INTERNAL_CTYPES = {'text/plain': 'text/plain',
                   'text/plain;charset=utf-8': 'text/plain',
                   'text/plain; charset=utf-8': 'text/plain',
                   'application/octet-stream': 'application/octet-stream',
                   'application/aes': 'application/aes'}

# Maps mime-types used to specify secret data formats to the types that can
#   be requested for secrets via GET calls.
#   Note: Raw client types are converted into the 'INTERNAL_CTYPES' types
#   which are then used as the keys to the 'CTYPES_MAPPINGS' below.
CTYPES_PLAIN = {'default': 'text/plain'}
CTYPES_BINARY = {'default': 'application/octet-stream'}
CTYPES_AES = {'default': 'application/aes'}
CTYPES_MAPPINGS = {'text/plain': CTYPES_PLAIN,
                   'application/octet-stream': CTYPES_BINARY,
                   'application/aes': CTYPES_AES}

# Supported encodings
ENCODINGS = ['base64']

# Maps normalized content-types to supported encoding(s)
CTYPES_TO_ENCODINGS = {'text/plain': None,
                       'application/octet-stream': ['base64', 'binary'],
                       'application/aes': None}


def normalize_content_type(mime_type):
    """Normalize the supplied content-type to an internal form."""
    stripped = map(lambda x: x.strip(), mime_type.split(';'))
    mime = stripped[0].lower()
    if len(stripped) > 1:
        # mime type includes charset
        charset_type = stripped[1].lower()
        if '=' not in charset_type:
            # charset is malformed
            return mime_type
        else:
            charset = map(lambda x: x.strip(), charset_type.split('='))[1]
            if charset not in PLAIN_TEXT_CHARSETS:
                # unsupported charset
                return mime_type
    return INTERNAL_CTYPES.get(mime, mime_type)


def is_supported(mime_type):
    return mime_type in SUPPORTED


def is_base64_encoding_supported(mime_type):
    if is_supported(mime_type):
        encodings = CTYPES_TO_ENCODINGS[INTERNAL_CTYPES[mime_type]]
        return encodings and ('base64' in encodings)
    return False


def is_base64_processing_needed(content_type, content_encoding):
    content_encodings = utils.get_accepted_encodings_direct(content_encoding)
    if content_encodings:
        if 'base64' not in content_encodings:
            return False
        if is_supported(content_type):
            encodings = CTYPES_TO_ENCODINGS[INTERNAL_CTYPES[content_type]]
            return encodings and 'base64' in encodings
    return False


def use_binary_content_as_is(content_type, content_encoding):
    """Checks if headers are valid to allow binary content as-is."""
    content_encodings = utils.get_accepted_encodings_direct(content_encoding)
    if content_encodings:
        if 'binary' not in content_encodings:
            return False
        if is_supported(content_type):
            encodings = CTYPES_TO_ENCODINGS[INTERNAL_CTYPES.get(content_type)]
            return encodings and 'binary' in encodings
    return INTERNAL_CTYPES.get(content_type) in BINARY


def augment_fields_with_content_types(secret):
    """Add content-types and encodings information to a Secret's fields.

    Generate a dict of content types based on the data associated
    with the specified secret.

    :param secret: The models.Secret instance to add 'content_types' to.
    """

    fields = secret.to_dict_fields()

    if not secret.encrypted_data:
        return fields

    # TODO(jwood): How deal with merging more than one datum instance?
    for datum in secret.encrypted_data:
        if datum.content_type in CTYPES_MAPPINGS:
            fields.update(
                {'content_types': CTYPES_MAPPINGS[datum.content_type]}
            )
            break

    return fields
