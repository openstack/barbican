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
import six
import sys

from barbican.plugin.crypto import pkcs11


class KeyGenerator(object):

    def __init__(self, ffi=None):
        self.parser = self.get_main_parser()
        self.subparsers = self.parser.add_subparsers(
            title='subcommands',
            description='Action to perform'
        )
        self.add_mkek_args()
        self.add_hmac_args()
        self.args = self.parser.parse_args()
        if not self.args.passphrase:
            password = six.moves.input("Please enter your password: ")
        self.pkcs11 = pkcs11.PKCS11(
            library_path=self.args.library_path,
            login_passphrase=self.args.passphrase or password,
            rw_session=True,
            slot_id=int(self.args.slot_id),
            ffi=ffi
        )
        self.session = self.pkcs11.get_session()

    def get_main_parser(self):
        """Create a top-level parser and arguments."""
        parser = argparse.ArgumentParser(
            description='Barbican MKEK & HMAC Generator'
        )
        parser.add_argument(
            '--library-path',
            default='/usr/lib/libCryptoki2_64.so',
            help='Path to vendor PKCS11 library'
        )
        parser.add_argument(
            '--passphrase',
            default=None,
            help='Password to login to PKCS11 session'
        )
        parser.add_argument(
            '--slot-id',
            default=1,
            help='HSM Slot id (Should correspond to a configured PKCS11 slot)'
        )

        return parser

    def add_mkek_args(self):
        """Create MKEK generation parser and arguments."""
        create_parser = self.subparsers.add_parser('mkek', help='Generates a '
                                                   'new MKEK.')
        create_parser.add_argument('--length', '-l', default=32,
                                   help='the length of the MKEK')
        create_parser.add_argument('--label', '-L', default='primarymkek',
                                   help='the label for the MKEK')
        create_parser.set_defaults(func=self.generate_mkek)

    def add_hmac_args(self):
        """Create HMAC generation parser and arguments."""
        create_parser = self.subparsers.add_parser('hmac', help='Generates a '
                                                   'new HMAC.')
        create_parser.add_argument('--length', '-l', default=32,
                                   help='the length of the HMACKEY')
        create_parser.add_argument('--label', '-L', default='primaryhmac',
                                   help='the label for the HMAC')
        create_parser.set_defaults(func=self.generate_hmac)

    def verify_label_does_not_exist(self, label, session):
        key_handle = self.pkcs11.get_key_handle(label, session)
        if key_handle:
            print (
                "The label {label} already exists! "
                "Please try again.".format(label=label)
            )
            sys.exit(1)

    def generate_mkek(self, args):
        """Process the generate MKEK with given arguments"""
        self.verify_label_does_not_exist(args.label, self.session)
        self.pkcs11.generate_key(args.length, self.session, args.label,
                                 encrypt=True, wrap=True, master_key=True)
        print ("MKEK successfully generated!")

    def generate_hmac(self, args):
        """Process the generate HMAC with given arguments"""
        self.verify_label_does_not_exist(args.label, self.session)
        self.pkcs11.generate_key(args.length, self.session, args.label,
                                 sign=True, master_key=True)
        print ("HMAC successfully generated!")

    def execute(self):
        """Parse the command line arguments."""
        try:
            self.args.func(self.args)
        except Exception as e:
            print(e)
        finally:
            self.pkcs11.return_session(self.session)


def main():
    kg = KeyGenerator()
    kg.execute()


if __name__ == '__main__':
    main()
