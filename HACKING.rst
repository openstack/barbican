Barbican Style Commandments
============================

- Step 1: Read the OpenStack Style Commandments
  http://docs.openstack.org/developer/hacking/
- Step 2: Read on


Barbican Specific Commandments
-------------------------------

- [B310] Check for improper use of logging format arguments.
- [B311] Use assertIsNone(...) instead of assertEqual(None, ...).
- [B312] Use assertTrue(...) rather than assertEqual(True, ...).
- [B313] Validate that debug level logs are not translated.
- [B314] str() and unicode() cannot be used on an exception. Remove or use six.text_type().
- [B315] Translated messages cannot be concatenated.  String should be
  included in translated message.
- [B316] Log messages, except debug ones, require translations!
- [B317] 'oslo_' should be used instead of 'oslo.'
- [B318] Must use a dict comprehension instead of a dict constructor
  with a sequence of key-value pairs.
- [B319] Ensure to not use xrange().
- [B320] Do not use LOG.warn as it's deprecated.
- [B321] Use assertIsNotNone(...) rather than assertNotEqual(None, ...) or
  assertIsNot(None, ...).

LOG Translations
----------------

LOG.debug messages will not get translated. Use  ``_LI()`` for
``LOG.info``, ``_LW`` for ``LOG.warning``, ``_LE`` for ``LOG.error``
and ``LOG.exception``, and ``_LC()`` for ``LOG.critical``.

``_()`` is preferred for any user facing message, even if it is also
going to a log file.  This ensures that the translated version of the
message will be available to the user.

The log marker functions (``_LI()``, ``_LW()``, ``_LE()``, and ``_LC()``)
must only be used when the message is only sent directly to the log.
Anytime that the message will be passed outside of the current context
(for example as part of an exception) the ``_()`` marker function
must be used.

A common pattern is to define a single message object and use it more
than once, for the log call and the exception.  In that case, ``_()``
must be used because the message is going to appear in an exception that
may be presented to the user.

For more details about translations, see
http://docs.openstack.org/developer/oslo.i18n/guidelines.html

Creating Unit Tests
-------------------
For every new feature, unit tests should be created that both test and
(implicitly) document the usage of said feature. If submitting a patch for a
bug that had no unit test, a new passing unit test should be added. If a
submitted bug fix does have a unit test, be sure to add a new one that fails
without the patch and passes with the patch.

Running Tests
-------------
The testing system is based on a combination of tox and testr. If you just
want to run the whole suite, run `tox` and all will be fine. However, if
you'd like to dig in a bit more, you might want to learn some things about
testr itself. A basic walkthrough for OpenStack can be found at
http://wiki.openstack.org/testr

OpenStack Trademark
-------------------

OpenStack is a registered trademark of OpenStack, LLC, and uses the
following capitalization:

   OpenStack

Commit Messages
---------------
Using a common format for commit messages will help keep our git history
readable. Follow these guidelines:

  First, provide a brief summary (it is recommended to keep the commit title
  under 50 chars).

  The first line of the commit message should provide an accurate
  description of the change, not just a reference to a bug or
  blueprint. It must be followed by a single blank line.

  Following your brief summary, provide a more detailed description of
  the patch, manually wrapping the text at 72 characters. This
  description should provide enough detail that one does not have to
  refer to external resources to determine its high-level functionality.

  Once you use 'git review', two lines will be appended to the commit
  message: a blank line followed by a 'Change-Id'. This is important
  to correlate this commit with a specific review in Gerrit, and it
  should not be modified.

For further information on constructing high quality commit messages,
and how to split up commits into a series of changes, consult the
project wiki:

   http://wiki.openstack.org/GitCommitMessages
