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
Field-level encryption/decryption.

These utilities are intended to be applied onto a dictionary of field
value, independent of the entity type, as long as these fields match
a list of protection-fields below.
"""

FIELDS_ENCRYPT_DECRYPT = {'plain_text': 'cypher_text'}


def generate_dek(fields):
    """
    Generate a data encryption key based on the input parameters,
    placing the result in the 'plain_text' key of the same
    input parameters.
    """
    #TODO: Supply algorithm
    fields['plain_text'] = "TODO: Gen a dek based on input params"


def encrypt_value(value):
    """Encrypt the supplied value"""
    #TODO: Supply algorithm
    return value if value is None else '[encrypt-this]{0}'.format(value)


def encrypt(fields, ok_to_generate=False):
    """Encrypt in-place the data of any fields found in FIELDS_TO_PROTECT"""

    if ok_to_generate and 'plain_text' not in fields:
        generate_dek(fields)

    for pt in (pt for pt, ct in FIELDS_ENCRYPT_DECRYPT.iteritems() if
               pt in fields):
        ct = FIELDS_ENCRYPT_DECRYPT[pt]
        fields[ct] = encrypt_value(fields[pt])
        if pt != ct:
            del fields[pt]

    fields['kek_metadata'] = "dummymetadata"


def decrypt_value(value):
    """Decrypt the supplied value"""
    #TODO: Supply algorithm
    if value is None:
        return None
    prefix = '[encrypt-this]'
    return value[len(prefix):] if value.startswith(prefix) else value


def decrypt(fields):
    """Decrypt in-place the data of any fields found in FIELDS_TO_PROTECT"""
    for pt in (pt for pt, ct in FIELDS_ENCRYPT_DECRYPT.iteritems() if
               ct in fields):
        ct = FIELDS_ENCRYPT_DECRYPT[pt]
        fields[pt] = decrypt_value(fields[ct])
        if pt != ct:
            del fields[ct]


def generate_response_for(accepts, secret):
    """
    Handles decrypting and formatting secret information, typically for
    response to a requesting http client with the specified accepts.
    """
    response = None

    if not accepts or not secret or not secret.encrypted_data:
        return response

    # Look for first direct match to encrypted data.
    for datum in secret.encrypted_data:
        if datum.mime_type == accepts:
            response = decrypt_value(datum.cypher_text)
            break

    # TODO: Deal with non-direct matches (i.e. that require conversion)
    if not response:
        pass

    return response


