# Copyright 2025 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import abc
import traceback

from oslo_db.sqlalchemy import session
from sqlalchemy import orm
from sqlalchemy.orm import scoping

from barbican.model import models


class BaseKEKRewrap(metaclass=abc.ABCMeta):

    def __init__(self, conf):
        self.db_engine = session.create_engine(conf.database.connection)
        self._session_creator = scoping.scoped_session(
            orm.sessionmaker(
                bind=self.db_engine,
            )
        )

    @abc.abstractmethod
    def rewrap_kek(self, project, kek):
        raise NotImplementedError

    @property
    def db_session(self):
        return self._session_creator()

    def get_keks_for_project(self, project):
        keks = []
        with self.db_session.begin() as transaction:
            print('Retrieving KEKs for Project {}'.format(project.id))
            query = transaction.session.query(models.KEKDatum)
            query = query.filter_by(project_id=project.id)
            query = query.filter_by(plugin_name=self.plugin_name)

            keks = query.all()

        return keks

    def get_projects(self):
        print('Retrieving all available projects')

        projects = []
        with self.db_session.begin() as transaction:
            projects = transaction.session.query(models.Project).all()

        return projects

    def execute(self, dry_run=True):
        self.dry_run = dry_run
        if self.dry_run:
            print('-- Running in dry-run mode --')

        projects = self.get_projects()
        for project in projects:
            keks = self.get_keks_for_project(project)
            for kek in keks:
                try:
                    self.rewrap_kek(project, kek)
                except Exception:
                    print('Error occurred! SQLAlchemy automatically rolled-'
                          'back the transaction')
                    traceback.print_exc()
