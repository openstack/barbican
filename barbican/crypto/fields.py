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


FIELDS_TO_PROTECT = ['secret', 'private_key', 'public_key']


def encrypt_value(value):
    """Encrypt the supplied value"""
    # TBD: Supply algorithm
    return value if value is None else '[encrypt-this]%s' % value


def encrypt(fields):
    """Encrypt in-place the data of any fields found in FIELDS_TO_PROTECT"""
    for key in (key for key in FIELDS_TO_PROTECT if key in fields):
        fields[key] = encrypt_value(fields[key])


def decrypt_value(value):
    """Decrypt the supplied value"""
    # TBD: Supply algorithm
    if value is None:
        return None
    prefix = '[encrypt-this]'
    return value[len(prefix):] if value.startswith(prefix) else value


def decrypt(fields):
    """Decrypt in-place the data of any fields found in FIELDS_TO_PROTECT"""
    for key in (key for key in FIELDS_TO_PROTECT if key in fields):
        fields[key] = decrypt_value(fields[key])
