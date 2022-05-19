#    Copyright 2018 Fujitsu.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_serialization import jsonutils as json
from oslo_versionedobjects import fields

# Import field errors from oslo.versionedobjects
KeyTypeError = fields.KeyTypeError
ElementTypeError = fields.ElementTypeError

# Import fields from oslo.versionedobjects
BooleanField = fields.BooleanField
UnspecifiedDefault = fields.UnspecifiedDefault
IntegerField = fields.IntegerField
NonNegativeIntegerField = fields.NonNegativeIntegerField
UUIDField = fields.UUIDField
FloatField = fields.FloatField
NonNegativeFloatField = fields.NonNegativeFloatField
StringField = fields.StringField
SensitiveStringField = fields.SensitiveStringField
EnumField = fields.EnumField
DateTimeField = fields.DateTimeField
DictOfStringsField = fields.DictOfStringsField
DictOfNullableStringsField = fields.DictOfNullableStringsField
DictOfIntegersField = fields.DictOfIntegersField
ListOfStringsField = fields.ListOfStringsField
SetOfIntegersField = fields.SetOfIntegersField
ListOfSetsOfIntegersField = fields.ListOfSetsOfIntegersField
ListOfDictOfNullableStringsField = fields.ListOfDictOfNullableStringsField
DictProxyField = fields.DictProxyField
ObjectField = fields.ObjectField
ListOfObjectsField = fields.ListOfObjectsField
VersionPredicateField = fields.VersionPredicateField
FlexibleBooleanField = fields.FlexibleBooleanField
DictOfListOfStringsField = fields.DictOfListOfStringsField
IPAddressField = fields.IPAddressField
IPV4AddressField = fields.IPV4AddressField
IPV6AddressField = fields.IPV6AddressField
IPV4AndV6AddressField = fields.IPV4AndV6AddressField
IPNetworkField = fields.IPNetworkField
IPV4NetworkField = fields.IPV4NetworkField
IPV6NetworkField = fields.IPV6NetworkField
AutoTypedField = fields.AutoTypedField
BaseEnumField = fields.BaseEnumField
MACAddressField = fields.MACAddressField
ListOfIntegersField = fields.ListOfIntegersField
PCIAddressField = fields.PCIAddressField

Enum = fields.Enum
Field = fields.Field
FieldType = fields.FieldType
Set = fields.Set
Dict = fields.Dict
List = fields.List
Object = fields.Object
IPAddress = fields.IPAddress
IPV4Address = fields.IPV4Address
IPV6Address = fields.IPV6Address
IPNetwork = fields.IPNetwork
IPV4Network = fields.IPV4Network
IPV6Network = fields.IPV6Network


class Json(FieldType):
    def coerce(self, obj, attr, value):
        if isinstance(value, str):
            loaded = json.loads(value)
            return loaded
        return value

    def from_primitive(self, obj, attr, value):
        return self.coerce(obj, attr, value)

    def to_primitive(self, obj, attr, value):
        return json.dumps(value)


class DictOfObjectsField(AutoTypedField):
    def __init__(self, objtype, subclasses=False, **kwargs):
        self.AUTO_TYPE = Dict(Object(objtype, subclasses))
        self.objname = objtype
        super(DictOfObjectsField, self).__init__(**kwargs)


class JsonField(AutoTypedField):
    AUTO_TYPE = Json()
