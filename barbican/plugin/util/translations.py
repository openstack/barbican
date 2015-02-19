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
                                enforce_text_only=False):
    """Normalize unencrypted prior to plugin encryption processing."""
    if not unencrypted:
        raise s.SecretNoPayloadProvidedException()

    # Validate and normalize content-type.
    normalized_mime = mime_types.normalize_content_type(content_type)
    if not mime_types.is_supported(normalized_mime):
        raise s.SecretContentTypeNotSupportedException(content_type)

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
            try:
                base64.b64decode(unencrypted)
            except TypeError:
                raise s.SecretPayloadDecodingError()
            unencrypted = unencrypted
        elif mime_types.use_binary_content_as_is(content_type,
                                                 content_encoding):
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


def analyze_before_decryption(content_type):
    """Determine support for desired content type."""
    if not mime_types.is_supported(content_type):
        raise s.SecretAcceptNotSupportedException(content_type)


def denormalize_after_decryption(unencrypted, content_type):
    """Translate the decrypted data into the desired content type."""
    # Process plain-text type.
    if content_type in mime_types.PLAIN_TEXT:
        # normalize text to binary string
        try:
            unencrypted = unencrypted.decode('utf-8')
        except UnicodeDecodeError:
            raise s.SecretAcceptNotSupportedException(content_type)

    # Process binary type.
    elif content_type not in mime_types.BINARY:
        raise s.SecretContentTypeNotSupportedException(content_type)

    return unencrypted
