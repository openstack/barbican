# Copyright (c) 2016, GohighSec
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ast
import re

from hacking import core
import pycodestyle


"""
Guidelines for writing new hacking checks

 - Use only for Barbican specific tests. OpenStack general tests
   should be submitted to the common 'hacking' module.
 - Pick numbers in the range B3xx. Find the current test with
   the highest allocated number and then pick the next value.
 - Keep the test method code in the source file ordered based
   on the B3xx value.
 - List the new rule in the top level HACKING.rst file
 - Add test cases for each new rule to barbican/tests/test_hacking.py
"""

oslo_namespace_imports = re.compile(r"from[\s]*oslo[.](.*)")
dict_constructor_with_list_copy_re = re.compile(r".*\bdict\((\[)?(\(|\[)")
no_log_warn = re.compile(r".*LOG.warn\(.*\)")


class BaseASTChecker(ast.NodeVisitor):
    """Provides a simple framework for writing AST-based checks.

    Subclasses should implement visit_* methods like any other AST visitor
    implementation. When they detect an error for a particular node the
    method should call ``self.add_error(offending_node)``. Details about
    where in the code the error occurred will be pulled from the node
    object.

    Subclasses should also provide a class variable named CHECK_DESC to
    be used for the human readable error message.

    """

    CHECK_DESC = 'No check message specified'

    def __init__(self, tree, filename):
        """This object is created automatically by pycodestyle.

        :param tree: an AST tree
        :param filename: name of the file being analyzed
                         (ignored by our checks)
        """
        self._tree = tree
        self._errors = []

    def run(self):
        """Called automatically by pycodestyle."""
        self.visit(self._tree)
        return self._errors

    def add_error(self, node, message=None):
        """Add an error caused by a node to the list of errors for pep8."""

        message = message or self.CHECK_DESC
        error = (node.lineno, node.col_offset, message, self.__class__)
        self._errors.append(error)

    def _check_call_names(self, call_node, names):
        if isinstance(call_node, ast.Call):
            if isinstance(call_node.func, ast.Name):
                if call_node.func.id in names:
                    return True
        return False


class CheckLoggingFormatArgs(BaseASTChecker):
    """Check for improper use of logging format arguments.

    LOG.debug("Volume %s caught fire and is at %d degrees C and climbing.",
              ('volume1', 500))

    The format arguments should not be a tuple as it is easy to miss.

    """
    name = "check_logging_format_args"
    version = "1.0"

    CHECK_DESC = 'B310 Log method arguments should not be a tuple.'
    LOG_METHODS = [
        'debug', 'info',
        'warn', 'warning',
        'error', 'exception',
        'critical', 'fatal',
        'trace', 'log'
    ]

    def _find_name(self, node):
        """Return the fully qualified name or a Name or Attribute."""
        if isinstance(node, ast.Name):
            return node.id
        elif (isinstance(node, ast.Attribute)
                and isinstance(node.value, (ast.Name, ast.Attribute))):
            method_name = node.attr
            obj_name = self._find_name(node.value)
            if obj_name is None:
                return None
            return obj_name + '.' + method_name
        elif isinstance(node, str):
            return node
        else:  # could be Subscript, Call or many more
            return None

    def visit_Call(self, node):
        """Look for the 'LOG.*' calls."""
        # extract the obj_name and method_name
        if isinstance(node.func, ast.Attribute):
            obj_name = self._find_name(node.func.value)
            if isinstance(node.func.value, ast.Name):
                method_name = node.func.attr
            elif isinstance(node.func.value, ast.Attribute):
                obj_name = self._find_name(node.func.value)
                method_name = node.func.attr
            else:  # could be Subscript, Call or many more
                return super(CheckLoggingFormatArgs, self).generic_visit(node)

            # obj must be a logger instance and method must be a log helper
            if (obj_name != 'LOG'
                    or method_name not in self.LOG_METHODS):
                return super(CheckLoggingFormatArgs, self).generic_visit(node)

            # the call must have arguments
            if not len(node.args):
                return super(CheckLoggingFormatArgs, self).generic_visit(node)

            # any argument should not be a tuple
            for arg in node.args:
                if isinstance(arg, ast.Tuple):
                    self.add_error(arg)

        return super(CheckLoggingFormatArgs, self).generic_visit(node)


@core.flake8ext
def check_oslo_namespace_imports(physical_line, logical_line, filename):
    """'oslo_' should be used instead of 'oslo.'

    B317
    """
    if pycodestyle.noqa(physical_line):
        return
    if re.match(oslo_namespace_imports, logical_line):
        msg = ("B317: '%s' must be used instead of '%s'.") % (
            logical_line.replace('oslo.', 'oslo_'),
            logical_line)
        yield(0, msg)


@core.flake8ext
def dict_constructor_with_list_copy(logical_line):
    """Use a dict comprehension instead of a dict constructor

    B318
    """
    msg = (
        "B318: Must use a dict comprehension instead of a dict constructor "
        "with a sequence of key-value pairs."
    )
    if dict_constructor_with_list_copy_re.match(logical_line):
        yield (0, msg)


@core.flake8ext
def no_log_warn_check(logical_line):
    """Disallow 'LOG.warn'

    B320
    """
    msg = ("B320: LOG.warn is deprecated, please use LOG.warning!")
    if re.match(no_log_warn, logical_line):
        yield(0, msg)
