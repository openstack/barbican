#!/usr/bin/env python
# Copyright 2010-2015 OpenStack LLC.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
    CLI interface for barbican management
"""

from __future__ import print_function

import argparse
import six
import sys

from oslo_config import cfg
from oslo_log import log as logging

from barbican.cmd import pkcs11_kek_rewrap as pkcs11_rewrap
from barbican.common import config
from barbican.model import clean
from barbican.model.migration import commands
from barbican.plugin.crypto import pkcs11
import barbican.version

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


# Decorators for actions
def args(*args, **kwargs):
    def _decorator(func):
        func.__dict__.setdefault('args', []).insert(0, (args, kwargs))
        return func
    return _decorator


class DbCommands(object):
    """Class for managing barbican database"""

    description = "Subcommands for managing barbican database"

    clean_description = "Clean up soft deletions in the database"

    @args('--db-url', '-d', metavar='<db-url>', dest='dburl',
          help='barbican database URL')
    @args('--min-days', '-m', metavar='<min-days>', dest='min_days', type=int,
          default=90, help='minimum number of days to keep soft deletions. '
          'default is %(default)s days.')
    @args('--verbose', '-V', action='store_true', dest='verbose',
          default=False, help='Show verbose information about the clean up.')
    @args('--log-file', '-L', metavar='<log-file>', type=str, default=None,
          dest='log_file', help='Set log file location. '
          'Default value for log_file can be found in barbican.conf')
    @args('--clean-unassociated-projects', '-p', action='store_true',
          dest='do_clean_unassociated_projects', default=False,
          help='Remove projects that have no '
               'associated resources.')
    @args('--soft-delete-expired-secrets', '-e', action='store_true',
          dest='do_soft_delete_expired_secrets', default=False,
          help='Soft delete secrets that are expired.')
    def clean(self, dburl=None, min_days=None, verbose=None, log_file=None,
              do_clean_unassociated_projects=None,
              do_soft_delete_expired_secrets=None):
        """Clean soft deletions in the database"""
        if dburl is None:
            dburl = CONF.sql_connection
        if log_file is None:
            log_file = CONF.log_file

        clean.clean_command(
            sql_url=dburl,
            min_num_days=min_days,
            do_clean_unassociated_projects=do_clean_unassociated_projects,
            do_soft_delete_expired_secrets=do_soft_delete_expired_secrets,
            verbose=verbose,
            log_file=log_file)

    revision_description = "Create a new database version file"

    @args('--db-url', '-d', metavar='<db-url>', dest='dburl',
          help='barbican database URL')
    @args('--message', '-m', metavar='<message>', default='DB change',
          help='the message for the DB change')
    @args('--autogenerate', action="store_true", dest='autogen',
          default=False, help='autogenerate from models')
    def revision(self, dburl=None, message=None, autogen=None):
        """Process the 'revision' Alembic command."""
        if dburl is None:
            commands.generate(autogenerate=autogen, message=str(message),
                              sql_url=CONF.sql_connection)
        else:
            commands.generate(autogenerate=autogen, message=str(message),
                              sql_url=str(dburl))

    upgrade_description = "Upgrade to a future database version"

    @args('--db-url', '-d', metavar='<db-url>', dest='dburl',
          help='barbican database URL')
    @args('--version', '-v', metavar='<version>', default='head',
          help='the version to upgrade to, or else '
          'the latest/head if not specified.')
    def upgrade(self, dburl=None, version=None):
        """Process the 'upgrade' Alembic command."""
        if dburl is None:
            commands.upgrade(to_version=str(version),
                             sql_url=CONF.sql_connection)
        else:
            commands.upgrade(to_version=str(version), sql_url=str(dburl))

    history_description = "Show database changset history"

    @args('--db-url', '-d', metavar='<db-url>', dest='dburl',
          help='barbican database URL')
    @args('--verbose', '-V', action='store_true', dest='verbose',
          default=False, help='Show full information about the revisions.')
    def history(self, dburl=None, verbose=None):
        if dburl is None:
            commands.history(verbose, sql_url=CONF.sql_connection)
        else:
            commands.history(verbose, sql_url=str(dburl))

    current_description = "Show current revision of database"

    @args('--db-url', '-d', metavar='<db-url>', dest='dburl',
          help='barbican database URL')
    @args('--verbose', '-V', action='store_true', dest='verbose',
          default=False, help='Show full information about the revisions.')
    def current(self, dburl=None, verbose=None):
        if dburl is None:
            commands.current(verbose, sql_url=CONF.sql_connection)
        else:
            commands.current(verbose, sql_url=str(dburl))


class HSMCommands(object):
    """Class for managing HSM/pkcs11 plugin"""

    description = "Subcommands for managing HSM/PKCS11"

    gen_mkek_description = "Generates a new MKEK"

    @args('--library-path', metavar='<library-path>', dest='libpath',
          default='/usr/lib/libCryptoki2_64.so',
          help='Path to vendor PKCS11 library')
    @args('--slot-id', metavar='<slot-id>', dest='slotid', default=1,
          help='HSM Slot id (Should correspond to a configured PKCS11 slot, \
          default is 1)')
    @args('--passphrase', metavar='<passphrase>', default=None, required=True,
          help='Password to login to PKCS11 session')
    @args('--label', '-L', metavar='<label>', default='primarymkek',
          help='The label of the Master Key Encrypt Key')
    @args('--length', '-l', metavar='<length>', default=32,
          help='The length of the Master Key Encrypt Key (default is 32)')
    def gen_mkek(self, passphrase, libpath=None, slotid=None, label=None,
                 length=None):
        self._create_pkcs11_session(str(passphrase), str(libpath), int(slotid))
        self._verify_label_does_not_exist(str(label), self.session)
        self.pkcs11.generate_key(int(length), self.session, str(label),
                                 encrypt=True, wrap=True, master_key=True)
        self.pkcs11.return_session(self.session)
        print ("MKEK successfully generated!")

    gen_hmac_description = "Generates a new HMAC key"

    @args('--library-path', metavar='<library-path>', dest='libpath',
          default='/usr/lib/libCryptoki2_64.so',
          help='Path to vendor PKCS11 library')
    @args('--slot-id', metavar='<slot-id>', dest='slotid', default=1,
          help='HSM Slot id (Should correspond to a configured PKCS11 slot, \
          default is 1)')
    @args('--passphrase', metavar='<passphrase>', default=None, required=True,
          help='Password to login to PKCS11 session')
    @args('--label', '-L', metavar='<label>', default='primarymkek',
          help='The label of the Matser HMAC Key')
    @args('--length', '-l', metavar='<length>', default=32,
          help='The length of the Master HMAC Key (default is 32)')
    def gen_hmac(self, passphrase, libpath=None, slotid=None, label=None,
                 length=None):
        self._create_pkcs11_session(str(passphrase), str(libpath), int(slotid))
        self._verify_label_does_not_exist(str(label), self.session)
        self.pkcs11.generate_key(int(length), self.session, str(label),
                                 sign=True, master_key=True)
        self.pkcs11.return_session(self.session)
        print ("HMAC successfully generated!")

    rewrap_pkek_description = "Re-wrap project MKEKs"

    @args('--dry-run', action="store_true", dest='dryrun', default=False,
          help='Displays changes that will be made (Non-destructive)')
    def rewrap_pkek(self, dryrun=None):
        rewrapper = pkcs11_rewrap.KekRewrap(pkcs11_rewrap.CONF)
        rewrapper.execute(dryrun)
        rewrapper.pkcs11.return_session(rewrapper.hsm_session)

    def _create_pkcs11_session(self, passphrase, libpath, slotid):
        self.pkcs11 = pkcs11.PKCS11(
            library_path=libpath, login_passphrase=passphrase,
            rw_session=True, slot_id=slotid
        )
        self.session = self.pkcs11.get_session()

    def _verify_label_does_not_exist(self, label, session):
        key_handle = self.pkcs11.get_key_handle(label, session)
        if key_handle:
            print (
                "The label {label} already exists! "
                "Please try again.".format(label=label)
            )
            sys.exit(1)


CATEGORIES = {
    'db': DbCommands,
    'hsm': HSMCommands,
}


# Modifying similiar code from nova/cmd/manage.py
def methods_of(obj):
    """Get all callable methods of an object that don't start with underscore

    returns a list of tuples of the form (method_name, method)
    """

    result = []
    for fn in dir(obj):
        if callable(getattr(obj, fn)) and not fn.startswith('_'):
            result.append((fn, getattr(obj, fn),
                          getattr(obj, fn+'_description', None)))
    return result


# Shamelessly taking same code from nova/cmd/manage.py
def add_command_parsers(subparsers):
    """Add subcommand parser to oslo_config object"""

    for category in CATEGORIES:
        command_object = CATEGORIES[category]()

        desc = getattr(command_object, 'description', None)
        parser = subparsers.add_parser(category, description=desc)
        parser.set_defaults(command_object=command_object)

        category_subparsers = parser.add_subparsers(dest='action')

        for (action, action_fn, action_desc) in methods_of(command_object):
            parser = category_subparsers.add_parser(action,
                                                    description=action_desc)

            action_kwargs = []
            for args, kwargs in getattr(action_fn, 'args', []):
                # Assuming dest is the arg name without the leading
                # hyphens if no dest is supplied
                kwargs.setdefault('dest', args[0][2:])
                if kwargs['dest'].startswith('action_kwarg_'):
                    action_kwargs.append(
                        kwargs['dest'][len('action_kwarg_'):])
                else:
                    action_kwargs.append(kwargs['dest'])
                    kwargs['dest'] = 'action_kwarg_' + kwargs['dest']

                parser.add_argument(*args, **kwargs)

            parser.set_defaults(action_fn=action_fn)
            parser.set_defaults(action_kwargs=action_kwargs)

            parser.add_argument('action_args', nargs='*',
                                help=argparse.SUPPRESS)


# Define subcommand category
category_opt = cfg.SubCommandOpt('category',
                                 title='Command categories',
                                 help='Available categories',
                                 handler=add_command_parsers)


def main():
    """Parse options and call the appropriate class/method."""
    CONF = config.new_config()
    CONF.register_cli_opt(category_opt)

    try:
        logging.register_options(CONF)
        logging.setup(CONF, "barbican-manage")
        cfg_files = cfg.find_config_files(project='barbican')

        CONF(args=sys.argv[1:],
             project='barbican',
             prog='barbican-manage',
             version=barbican.version.__version__,
             default_config_files=cfg_files)

    except RuntimeError as e:
        sys.exit("ERROR: %s" % e)

    # find sub-command and its arguments
    fn = CONF.category.action_fn
    fn_args = [arg.decode('utf-8') for arg in CONF.category.action_args]
    fn_kwargs = {}
    for k in CONF.category.action_kwargs:
        v = getattr(CONF.category, 'action_kwarg_' + k)
        if v is None:
            continue
        if isinstance(v, six.string_types):
            v = v.decode('utf-8')
        fn_kwargs[k] = v

    # call the action with the remaining arguments
    try:
        ret = fn(*fn_args, **fn_kwargs)
        return(ret)
    except Exception as e:
        sys.exit("ERROR: %s" % e)

if __name__ == '__main__':
    main()
