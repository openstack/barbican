"""
Copyright 2014-2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from functionaltests.api.v1.models.base_models import BaseModel


class SecretRefModel(BaseModel):

    def __init__(self, name=None, secret_ref=None):
        self.name = name
        self.secret_ref = secret_ref


class ContainerModel(BaseModel):

    def __init__(self, name=None, type=None, secret_refs=[],
                 container_ref=None, consumers=None, status=None,
                 updated=None, created=None, creator_id=None):
        self.name = name
        self.type = type
        self.secret_refs = secret_refs
        self.container_ref = container_ref
        self.consumers = consumers
        self.status = status
        self.updated = updated
        self.created = created
        self.creator_id = creator_id

    @classmethod
    def dict_to_obj(cls, input_dict):
        secret_refs = [SecretRefModel(**secret_ref) for secret_ref in
                       input_dict.get('secret_refs', [])]
        return cls(input_dict.get('name'), input_dict.get('type'), secret_refs,
                   container_ref=input_dict.get('container_ref'))
