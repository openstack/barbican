# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Justin Santa Barbara
# All Rights Reserved.
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

"""Base class for all model objects."""

from sqlalchemy import Column
from sqlalchemy import Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base, declared_attr


class Persisted(object):

    id = Column(Integer, primary_key=True)

    @declared_attr
    def __tablename__(self):
        return self.__name__.lower()

Base = declarative_base(cls=Persisted)
