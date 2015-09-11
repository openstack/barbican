"""
Copyright 2015 Cisco Systems

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


class QuotasModel(BaseModel):

    def __init__(self, secrets=None, orders=None, containers=None,
                 consumers=None, cas=None):
        super(QuotasModel, self).__init__()
        self.secrets = secrets
        self.orders = orders
        self.containers = containers
        self.consumers = consumers
        self.cas = cas


class QuotasResponseModel(BaseModel):

    def __init__(self, quotas=None):
        super(QuotasResponseModel, self).__init__()
        self.quotas = quotas

    @classmethod
    def dict_to_obj(cls, input_dict):
        quotas = QuotasModel(**input_dict.get('quotas'))
        return cls(quotas=quotas)


class ProjectQuotaRequestModel(BaseModel):

    def __init__(self, project_quotas=None):
        super(ProjectQuotaRequestModel, self).__init__()
        self.project_quotas = project_quotas

    @classmethod
    def dict_to_obj(cls, input_dict):
        project_quotas = QuotasModel(**input_dict.get('project_quotas'))
        return cls(project_quotas=project_quotas)


class ProjectQuotaOneModel(BaseModel):

    def __init__(self, project_quotas=None):
        super(ProjectQuotaOneModel, self).__init__()
        self.project_quotas = QuotasModel(**project_quotas)


class ProjectQuotaListItemModel(BaseModel):

    def __init__(self, project_id=None, project_quotas=None):
        super(ProjectQuotaListItemModel, self).__init__()
        self.project_id = project_id
        self.project_quotas = QuotasModel(**project_quotas)


class ProjectQuotaListModel(BaseModel):

    def __init__(self, project_quotas=None):
        super(ProjectQuotaListModel, self).__init__()
        self.project_quotas = project_quotas

    @classmethod
    def dict_to_obj(cls, input_dict):
        project_quotas = [ProjectQuotaListItemModel(**project_quotas_item)
                          for project_quotas_item in
                          input_dict.get('project_quotas', [])]
        return cls(project_quotas=project_quotas)
