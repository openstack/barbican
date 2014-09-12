"""
Copyright 2014 Rackspace

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
from functionaltests.api.v1.models.secret_models import SecretModel


class OrderModel(BaseModel):

    def __init__(self, status=None, secret_ref=None, updated=None,
                 created=None, type=None, meta=None, order_ref=None):
        super(OrderModel, self).__init__()
        self.status = status
        self.secret_ref = secret_ref
        self.updated = updated
        self.created = created
        self.type = type
        self.meta = meta
        self.order_ref = order_ref

    @classmethod
    def dict_to_obj(cls, input_dict):
        secret_metadata = input_dict.get('secret')
        if secret_metadata:
            input_dict['secret'] = SecretModel.dict_to_obj(secret_metadata)

        return super(OrderModel, cls).dict_to_obj(input_dict)
