#!/usr/bin/env python

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
import argparse
import json
import traceback

import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.orm import scoping

from barbican.common import utils
from barbican.model import models
from barbican.plugin.crypto import p11_crypto

# Use config values from p11_crypto
CONF = p11_crypto.CONF


class KekRewrap(object):

    def __init__(self, db_connection, library_path, login, slot_id,
                 new_mkek_label):
        self.dry_run = False
        self.new_label = new_mkek_label
        self.db_engine = sqlalchemy.create_engine(db_connection)
        self._session_creator = scoping.scoped_session(
            orm.sessionmaker(
                bind=self.db_engine,
                autocommit=True
            )
        )
        self.crypto_plugin = p11_crypto.P11CryptoPlugin(CONF)
        self.pkcs11 = self.crypto_plugin.pkcs11
        self.plugin_name = utils.generate_fullname_for(self.crypto_plugin)

    def rewrap_kek(self, project, kek):
        with self.db_session.begin():
            meta_dict = json.loads(kek.plugin_meta)

            if self.dry_run:
                msg = 'Would have unwrapped key with {} and rewrapped with {}'
                print(msg.format(meta_dict['mkek_label'], self.new_label))
                print('Would have updated KEKDatum in db {}'.format(kek.id))

            else:
                hsm_session = self.pkcs11.create_working_session()

                print('Rewrapping KEK {}'.format(kek.id))
                print('Pre-change IV: {}, Wrapped Key: {}'.format(
                    meta_dict['iv'], meta_dict['wrapped_key']))

                updated_meta = self.pkcs11.rewrap_kek(
                    iv=meta_dict['iv'],
                    wrapped_key=meta_dict['wrapped_key'],
                    hmac=meta_dict['hmac'],
                    mkek_label=meta_dict['mkek_label'],
                    hmac_label=meta_dict['hmac_label'],
                    key_length=32,
                    session=hsm_session
                )

                self.pkcs11.close_session(hsm_session)
                print('Post-change IV: {}, Wrapped Key: {}'.format(
                    updated_meta['iv'], updated_meta['wrapped_key']))

                # Update KEK metadata in DB
                kek.plugin_meta = json.dumps(updated_meta)

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

    @property
    def db_session(self):
        return self._session_creator()

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


def main():
    script_desc = ('Utility to re-wrap project KEKs after rotating an MKEK.')

    parser = argparse.ArgumentParser(description=script_desc)
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Displays changes that will be made (Non-destructive)'
    )
    args = parser.parse_args()

    rewrapper = KekRewrap(
        db_connection=CONF.sql_connection,
        library_path=CONF.p11_crypto_plugin.library_path,
        login=CONF.p11_crypto_plugin.login,
        slot_id=CONF.p11_crypto_plugin.slot_id,
        new_mkek_label=CONF.p11_crypto_plugin.mkek_label
    )
    rewrapper.execute(args.dry_run)

if __name__ == '__main__':
    main()
