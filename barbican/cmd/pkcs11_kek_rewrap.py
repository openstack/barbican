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

# Use config values from p11_crypto
CONF = p11_crypto.CONF


class KekRewrap(object):

    def __init__(self, conf):
        self.dry_run = False
        self.db_engine = sqlalchemy.create_engine(conf.sql_connection)
        self._session_creator = scoping.scoped_session(
            orm.sessionmaker(
                bind=self.db_engine,
                autocommit=True
            )
        )
        self.crypto_plugin = p11_crypto.P11CryptoPlugin(conf)
        self.pkcs11 = self.crypto_plugin.pkcs11
        self.plugin_name = utils.generate_fullname_for(self.crypto_plugin)
        self.hsm_session = self.pkcs11.get_session()
        self.new_mkek_label = self.crypto_plugin.mkek_label
        self.new_hmac_label = self.crypto_plugin.hmac_label
        self.new_mkek = self.crypto_plugin._get_master_key(self.new_mkek_label)
        self.new_mkhk = self.crypto_plugin._get_master_key(self.new_hmac_label)

    def rewrap_kek(self, project, kek):
        with self.db_session.begin():
            meta_dict = json.loads(kek.plugin_meta)

            if self.dry_run:
                msg = 'Would have unwrapped key with {} and rewrapped with {}'
                print(msg.format(meta_dict['mkek_label'], self.new_mkek_label))
                print('Would have updated KEKDatum in db {}'.format(kek.id))

                print('Rewrapping KEK {}'.format(kek.id))
                print('Pre-change IV: {}, Wrapped Key: {}'.format(
                    meta_dict['iv'], meta_dict['wrapped_key']))
                return

            session = self.hsm_session

            # Get KEK's master keys
            kek_mkek = self.pkcs11.get_key_handle(
                meta_dict['mkek_label'], session
            )
            kek_mkhk = self.pkcs11.get_key_handle(
                meta_dict['hmac_label'], session
            )
            # Decode data
            iv = base64.b64decode(meta_dict['iv'])
            wrapped_key = base64.b64decode(meta_dict['wrapped_key'])
            hmac = base64.b64decode(meta_dict['hmac'])
            # Verify HMAC
            kek_data = iv + wrapped_key
            self.pkcs11.verify_hmac(kek_mkhk, hmac, kek_data, session)
            # Unwrap KEK
            kek = self.pkcs11.unwrap_key(kek_mkek, iv, wrapped_key, session)

            # Wrap KEK with new master keys
            new_kek = self.pkcs11.wrap_key(self.new_mkek, kek, session)
            # Compute HMAC for rewrapped KEK
            new_kek_data = new_kek['iv'] + new_kek['wrapped_key']
            new_hmac = self.pkcs11.compute_hmac(self.new_mkhk, new_kek_data,
                                                session)
            # Destroy unwrapped KEK
            self.pkcs11.destroy_object(kek, session)

            # Build updated meta dict
            updated_meta = meta_dict.copy()
            updated_meta['mkek_label'] = self.new_mkek_label
            updated_meta['hmac_label'] = self.new_hmac_label
            updated_meta['iv'] = base64.b64encode(new_kek['iv'])
            updated_meta['wrapped_key'] = base64.b64encode(
                new_kek['wrapped_key'])
            updated_meta['hmac'] = base64.b64encode(new_hmac)

            print('Post-change IV: {}, Wrapped Key: {}'.format(
                updated_meta['iv'], updated_meta['wrapped_key']))

            # Update KEK metadata in DB
            kek.plugin_meta = p11_crypto.json_dumps_compact(updated_meta)

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

    rewrapper = KekRewrap(CONF)
    rewrapper.execute(args.dry_run)
    rewrapper.pkcs11.return_session(rewrapper.hsm_session)

if __name__ == '__main__':
    main()
