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


def encrypt_value(value):
    """Encrypt the supplied value"""
    #TODO: Supply algorithm
    return value if value is None else '[encrypt-this]{0}'.format(value)


def encrypt(fields):
    """Encrypt in-place the data of any fields found in FIELDS_TO_PROTECT"""
    
    if "plain_text" not in fields:
        #TODO: Generate secret of mime-type here
        fields['plain_text'] = "TODO: Generate real secret here"
    
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
