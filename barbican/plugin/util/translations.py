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

import base64

from barbican.plugin.interface import secret_store as s
from barbican.plugin.util import mime_types


def normalize_before_encryption(unencrypted, content_type, content_encoding,
                                secret_type, enforce_text_only=False):
    """Normalize unencrypted prior to plugin encryption processing.

    This normalizes the secrets before they are handed off to the SecretStore
    for storage. This converts all data to Base64 data. If the data is plain
    text then it encoded using utf-8 first and then Base64 encoded. Binary
    data is simply converted to Base64. In addition if the secret type is
    one of private, public, or certificate then the PEM headers are added
    to the Base64 encoding.
    """
    if not unencrypted:
        raise s.SecretNoPayloadProvidedException()

    # Validate and normalize content-type.
    normalized_mime = normalize_content_type(content_type)

    # Process plain-text type.
    if normalized_mime in mime_types.PLAIN_TEXT:
        # normalize text to binary and then base64 encode it
        unencrypted = unencrypted.encode('utf-8')
        unencrypted = base64.b64encode(unencrypted)

    # Process binary type.
    else:
        if content_encoding:
            content_encoding = content_encoding.lower()
        if content_encoding == 'base64':
            b64payload = unencrypted
            if is_pem_payload(unencrypted):
                pem_components = get_pem_components(unencrypted)
                b64payload = pem_components[1]
            try:
                base64.b64decode(b64payload)
            except TypeError:
                raise s.SecretPayloadDecodingError()
        elif mime_types.use_binary_content_as_is(content_type,
                                                 content_encoding):
            if (secret_type == s.SecretType.PRIVATE or
                    secret_type == s.SecretType.PUBLIC or
                    secret_type == s.SecretType.CERTIFICATE):
                unencrypted = to_pem(secret_type, unencrypted)
            else:
                unencrypted = base64.b64encode(unencrypted)
        elif enforce_text_only:
            # For text-based protocols (such as the one-step secret POST),
            #   only 'base64' encoding is possible/supported.
            raise s.SecretContentEncodingMustBeBase64()
        elif content_encoding:
            # Unsupported content-encoding request.
            raise s.SecretContentEncodingNotSupportedException(
                content_encoding
            )

    return unencrypted, normalized_mime


def normalize_content_type(content_type):
    """Normalize the content type and validate that it is supported."""
    normalized_mime = mime_types.normalize_content_type(content_type)
    if not mime_types.is_supported(normalized_mime):
        raise s.SecretContentTypeNotSupportedException(content_type)
    return normalized_mime


def analyze_before_decryption(content_type):
    """Determine support for desired content type."""
    if not mime_types.is_supported(content_type):
        raise s.SecretAcceptNotSupportedException(content_type)


def denormalize_after_decryption(unencrypted, content_type):
    """Translate the decrypted data into the desired content type.

    This is called when the raw keys are requested by the user. The secret
    returned from the SecretStore is the unencrypted parameter. This
    'denormalizes' the data back to its binary format.
    """
    # Process plain-text type.
    if content_type in mime_types.PLAIN_TEXT:
        # normalize text to binary string
        try:
            unencrypted = base64.b64decode(unencrypted)
            unencrypted = unencrypted.decode('utf-8')
        except UnicodeDecodeError:
            raise s.SecretAcceptNotSupportedException(content_type)

    # Process binary type.
    elif content_type in mime_types.BINARY:
        if is_pem_payload(unencrypted):
            unencrypted = get_pem_components(unencrypted)[1]
        unencrypted = base64.b64decode(unencrypted)
    else:
        raise s.SecretContentTypeNotSupportedException(content_type)

    return unencrypted


def get_pem_components(pem):
    """Returns the PEM content, header, and footer.

    This parses the PEM string and returns the PEM header, content, and footer.
    The content is the base64 encoded bytes without the header and footer. This
    is returned as a list. The order of the list is header, content, footer.
    """
    delim = "-----"
    splits = pem.split(delim)
    if len(splits) != 5 or splits[0] != "" or splits[4] != "":
        raise s.SecretPayloadDecodingError()
    header = delim + splits[1] + delim
    content = splits[2]
    footer = delim + splits[3] + delim
    return (header, content, footer)


def is_pem_payload(payload):
    """Tests whether payload is in PEM format.

    This parses the payload for the PEM header and footer strings. If it finds
    the header and footer strings then it is assumed to be a PEM payload.
    """
    delim = "-----"
    splits = payload.split(delim)
    if len(splits) != 5 or splits[0] != "" or splits[4] != "":
        return False
    else:
        return True


def to_pem(secret_type, payload, payload_encoded=False):
    """Converts payload to PEM format.

    This converts the payload to Base 64 encoding if payload_encoded is False
    and then adds PEM headers. This uses the secret_type to determined the PEM
    header.
    """
    pem = payload
    if payload_encoded:
        pem_content = payload
    else:
        pem_content = base64.b64encode(payload)

    if secret_type == s.SecretType.PRIVATE:
        headers = _get_pem_headers("PRIVATE KEY")
        pem = headers[0] + pem_content + headers[1]
    elif secret_type == s.SecretType.PUBLIC:
        headers = _get_pem_headers("PUBLIC KEY")
        pem = headers[0] + pem_content + headers[1]
    elif secret_type == s.SecretType.CERTIFICATE:
        headers = _get_pem_headers("CERTIFICATE")
        pem = headers[0] + pem_content + headers[1]

    return pem


def _get_pem_headers(pem_name):
    header = "-----BEGIN {}-----".format(pem_name)
    footer = "-----END {}-----".format(pem_name)
    return (header, footer)
