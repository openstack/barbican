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
import base64
import json
import traceback

import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.orm import scoping

from barbican.common import utils
from barbican.model import models
from barbican.plugin.crypto import p11_crypto
from barbican.plugin.crypto.pkcs11 import P11CryptoPluginException

# Use config values from p11_crypto
CONF = p11_crypto.CONF


class KekSignatureMigrator(object):

    def __init__(self, db_connection, library_path, login, slot_id):
        self.dry_run = False
        self.db_engine = sqlalchemy.create_engine(db_connection)
        self._session_creator = scoping.scoped_session(
            orm.sessionmaker(
                bind=self.db_engine,
                autocommit=True
            )
        )
        self.crypto_plugin = p11_crypto.P11CryptoPlugin(CONF)
        self.plugin_name = utils.generate_fullname_for(self.crypto_plugin)
        self.pkcs11 = self.crypto_plugin.pkcs11
        self.session = self.pkcs11.get_session()

    def recalc_kek_hmac(self, project, kek):
        with self.db_session.begin():
            meta_dict = json.loads(kek.plugin_meta)
            iv = base64.b64decode(meta_dict['iv'])
            wrapped_key = base64.b64decode(meta_dict['wrapped_key'])
            hmac = base64.b64decode(meta_dict['hmac'])
            kek_data = iv + wrapped_key
            hmac_key = self.pkcs11.get_key_handle(
                meta_dict['hmac_label'], self.session)

            # Verify if hmac signature validates with new method
            try:
                self.pkcs11.verify_hmac(hmac_key, hmac, kek_data, self.session)
                sig_good = True
            except P11CryptoPluginException as e:
                if 'CKR_SIGNATURE_INVALID' in e.message:
                    sig_good = False
                else:
                    raise

            if sig_good:
                msg = 'Skipping KEK {}, good signature'
                print(msg.format(kek.kek_label))
                return

            # Previous method failed.
            # Verify if hmac signature validates with old method
            try:
                self.pkcs11.verify_hmac(
                    hmac_key, hmac, wrapped_key, self.session
                )
                sig_bad = True
            except P11CryptoPluginException as e:
                if 'CKR_SIGNATURE_INVALID' in e.message:
                    sig_bad = False
                else:
                    raise

            if not sig_bad:
                msg = "Skipping KEK {}, can not validate with either method!"
                print(msg.format(kek.kek_label))
                return

            if self.dry_run:
                msg = 'KEK {} needs recalculation'
                print(msg.format(kek.kek_label))
                return

            # Calculate new HMAC
            new_hmac = self.pkcs11.compute_hmac(
                hmac_key, kek_data, self.session
            )

            # Update KEK plugin_meta with new hmac signature
            meta_dict['hmac'] = base64.b64encode(new_hmac)
            kek.plugin_meta = p11_crypto.json_dumps_compact(meta_dict)

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
                    self.recalc_kek_hmac(project, kek)
                except Exception:
                    print('Error occurred! SQLAlchemy automatically rolled-'
                          'back the transaction')
                    traceback.print_exc()


def main():
    script_desc = (
        'Utility to migrate existing project KEK signatures to include IV.'
    )

    parser = argparse.ArgumentParser(description=script_desc)
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Displays changes that will be made (Non-destructive)'
    )
    args = parser.parse_args()

    migrator = KekSignatureMigrator(
        db_connection=CONF.sql_connection,
        library_path=CONF.p11_crypto_plugin.library_path,
        login=CONF.p11_crypto_plugin.login,
        slot_id=CONF.p11_crypto_plugin.slot_id
    )
    migrator.execute(args.dry_run)

if __name__ == '__main__':
    main()
