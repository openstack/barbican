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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto
from oslo_serialization import base64

from barbican import i18n as u  # noqa
from barbican.plugin.interface import secret_store as s
from barbican.plugin.util import mime_types


def normalize_before_encryption(unencrypted, content_type, content_encoding,
                                secret_type, enforce_text_only=False):
    """Normalize unencrypted prior to plugin encryption processing.

    This normalizes the secrets before they are handed off to the SecretStore
    for storage. This converts all data to Base64 data. If the data is plain
    text then it encoded using utf-8 first and then Base64 encoded. Binary
    data is simply converted to Base64.

    :param str unencrypted: Raw payload
    :param str content_type: The media type for the payload
    :param str content_encoding: Transfer encoding
    :param str secret_type: The type of secret
    :param bool enforce_text_only: Require text content_type or base64
        content_encoding
    :returns: Tuple containing the normalized (base64 encoded) payload and
        the normalized media type.
    """
    if not unencrypted:
        raise s.SecretNoPayloadProvidedException()

    # Validate and normalize content-type.
    normalized_media_type = normalize_content_type(content_type)

    # Process plain-text type.
    if normalized_media_type in mime_types.PLAIN_TEXT:
        # normalize text to binary and then base64 encode it
        b64payload = base64.encode_as_bytes(unencrypted)

    # Process binary type.
    else:
        if not content_encoding:
            b64payload = base64.encode_as_bytes(unencrypted)
        elif content_encoding.lower() == 'base64':
            if not isinstance(unencrypted, bytes):
                b64payload = unencrypted.encode('utf-8')
            else:
                b64payload = unencrypted
        elif enforce_text_only:
            # For text-based protocols (such as the one-step secret POST),
            #   only 'base64' encoding is possible/supported.
            raise s.SecretContentEncodingMustBeBase64()
        else:
            # Unsupported content-encoding request.
            raise s.SecretContentEncodingNotSupportedException(
                content_encoding
            )

    return b64payload, normalized_media_type


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
            unencrypted = base64.decode_as_text(unencrypted)
        except UnicodeDecodeError:
            raise s.SecretAcceptNotSupportedException(content_type)

    # Process binary type.
    elif content_type in mime_types.BINARY:
        unencrypted = base64.decode_as_bytes(unencrypted)
    else:
        raise s.SecretContentTypeNotSupportedException(content_type)

    return unencrypted


def convert_pem_to_der(pem, secret_type):
    if secret_type == s.SecretType.PRIVATE:
        return _convert_private_pem_to_der(pem)
    elif secret_type == s.SecretType.PUBLIC:
        return _convert_public_pem_to_der(pem)
    elif secret_type == s.SecretType.CERTIFICATE:
        return _convert_certificate_pem_to_der(pem)
    else:
        reason = u._("Secret type can not be converted to DER")
        raise s.SecretGeneralException(reason=reason)


def convert_der_to_pem(der, secret_type):
    if secret_type == s.SecretType.PRIVATE:
        return _convert_private_der_to_pem(der)
    elif secret_type == s.SecretType.PUBLIC:
        return _convert_public_der_to_pem(der)
    elif secret_type == s.SecretType.CERTIFICATE:
        return _convert_certificate_der_to_pem(der)
    else:
        reason = u._("Secret type can not be converted to PEM")
        raise s.SecretGeneralException(reason=reason)


def _convert_private_pem_to_der(pem):
    private_key = serialization.load_pem_private_key(
        pem,
        password=None,
        backend=default_backend()
    )
    der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return der


def _convert_private_der_to_pem(der):
    private_key = serialization.load_der_private_key(
        der,
        password=None,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem


def _convert_public_pem_to_der(pem):
    public_key = serialization.load_pem_public_key(
        pem,
        backend=default_backend()
    )
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return der


def _convert_public_der_to_pem(der):
    public_key = serialization.load_der_public_key(
        der,
        backend=default_backend()
    )
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def _convert_certificate_pem_to_der(pem):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
    der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    return der


def _convert_certificate_der_to_pem(der):
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
    pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    return pem
