Contributing to Barbican
========================

For general information on contributing to OpenStack, please check out the
`contributor guide <https://docs.openstack.org/contributors/>`_ to get started.
It covers all the basics that are common to all OpenStack projects: the
accounts you need, the basics of interacting with our Gerrit review system, how
we communicate as a community, etc.

Below will cover the more project specific information you need to get started
with the Barbican project, which is responsible for the following OpenStack
deliverables:

barbican
    | The OpenStack Key Manager service.
    | code: https://opendev.org/openstack/barbican
    | docs: https://docs.openstack.org/barbican
    | api-ref: https://docs.openstack.org/barbican/latest/api/index.html#api-reference
    | StoryBoard: https://storyboard.openstack.org/#!/project/openstack/barbican

barbican-ui
    | Horizon extension for the OpenStack Key Manager API.
    | code: https://opendev.org/openstack/barbican-ui
    | StoryBoard: https://storyboard.openstack.org/#!/project/openstack/barbican-ui

python-barbicanclient
    | Python client library for the OpenStack Key Manager API.
    | code: https://opendev.org/openstack/python-barbicanclient
    | docs: https://docs.openstack.org/python-barbicanclient
    | StoryBoard: https://storyboard.openstack.org/#!/project/openstack/python-barbicanclient

barbican-tempest-plugin
    | Additional Barbican tempest-based tests beyond those in the
      main OpenStack Integration Test Suite (tempest).
    | code: https://opendev.org/openstack/barbican-tempest-plugin
    | StoryBoard: https://storyboard.openstack.org/#!/project/openstack/barbican-tempest-plugin

ansible-role-lunasa-hsm
    | Ansible role to manage Luna SA Hardware Security Module (HSM) client software
    | code: https://opendev.org/openstack/ansible-role-lunasa-hsm
    | StoryBoard: https://storyboard.openstack.org/#!/project/openstack/ansible-role-lunasa-hsm

See the ``CONTRIBUTING.rst`` file in each code repository for more
information about contributing to that specific deliverable.  Additionally,
you should look over the docs links above; most components have helpful
developer information specific to that deliverable.

Communication
~~~~~~~~~~~~~

IRC
    People working on the Barbican project may be found in the
    ``#openstack-barbican`` channel on OFTC during working hours
    in their timezone.  The channel is logged, so if you ask a question
    when no one is around, you can check the log to see if it's been
    answered: http://eavesdrop.openstack.org/irclogs/%23openstack-barbican/

weekly meeting
    Tuesdays at 13:00 UTC in ``#openstack-barbican`` on OFTC.
    Meetings are logged: http://eavesdrop.openstack.org/meetings/barbican/

    More information (including a link to the Agenda, some pointers on
    meeting etiquette, and an ICS file to put the meeting on your calendar)
    can be found at: http://eavesdrop.openstack.org/#Barbican_Meeting

mailing list
    We use the openstack-discuss@lists.openstack.org mailing list for
    asynchronous discussions or to communicate with other OpenStack teams.
    Use the prefix ``[barbican]`` in your subject line (it's a high-volume
    list, so most people use email filters).

    More information about the mailing list, including how to subscribe
    and read the archives, can be found at:
    http://lists.openstack.org/cgi-bin/mailman/listinfo/openstack-discuss

meet-ups
    The Barbican project usually has a presence at the OpenDev/OpenStack
    Project Team Gathering that takes place at the beginning of each
    development cycle.  Planning happens on an etherpad whose URL is
    announced at the weekly meetings and on the mailing list.

Contacting the Core Team
~~~~~~~~~~~~~~~~~~~~~~~~

The barbican-core team is an active group of contributors who are responsible
for directing and maintaining the Barbican project.  As a new contributor, your
interaction with this group will be mostly through code reviews, because
only members of barbican-core can approve a code change to be merged into the
code repository.

.. note::
   Although your contribution will require reviews by members of
   barbican-core, these aren't the only people whose reviews matter.
   Anyone with a gerrit account can post reviews, so you can ask
   other developers you know to review your code ... and you can
   review theirs.  (A good way to learn your way around the codebase
   is to review other people's patches.)

   If you're thinking, "I'm new at this, how can I possibly provide
   a helpful review?", take a look at `How to Review Changes the
   OpenStack Way
   <https://docs.openstack.org/project-team-guide/review-the-openstack-way.html>`_.

You can learn more about the role of core reviewers in the OpenStack
governance documentation:
https://docs.openstack.org/contributors/common/governance.html#core-reviewer

The membership list of barbican-core is maintained in gerrit:
https://review.opendev.org/#/admin/groups/178,members

New Feature Planning
~~~~~~~~~~~~~~~~~~~~

The Barbican project uses both "specs" and "blueprints" to track new features.
Here's a quick rundown of what they are and how the Barbican project uses them.

specs
    | Exist in the barbican-specs repository.
      Each spec must have a story in StoryBoard associated with it for tracking
      purposes.

    | A spec is required for any new Barbican core feature, anything that
      changes the Key Manager API, or anything that entails a mass change
      to the existing codebase.

    | The specs repository is: https://opendev.org/openstack/barbican-specs
    | It contains a ``README.rst`` file explaining how to file a spec.

    | You can read rendered specs docs at:
    | https://specs.openstack.org/openstack/barbican-specs/

blueprints
    | Exist in StoryBoard, where they can be targeted to release milestones.
    | You file one at https://storyboard.openstack.org/#!/project/openstack/barbican-specs

    | Examples of changes that can be covered by a blueprint only are:

    * adding a new backend; or
    * adding support for a defined capability that already exists in one or
      more existing backends.

Feel free to ask in ``#openstack-barbican`` or at the weekly meeting if you
have an idea you want to develop and you're not sure whether it requires
a blueprint *and* a spec or simply a blueprint.

The Barbican project observes the OpenStack-wide deadlines,
for example, final release of non-client libraries (barbican), final
release for client libraries (python-barbicanclient), feature freeze,
etc.  These are also noted and explained on the release schedule for the
current development cycle.

Task Tracking
~~~~~~~~~~~~~

We track our tasks in `StoryBoard
<https://storyboard.openstack.org/#!/project_group/barbican>`_.  See the top of
the page for the URL of each Barbican project deliverable.

If you're looking for some smaller, easier work item to pick up and get started
on, search for the 'low-hanging-fruit' tag in the Bugs section.

When you start working on a bug, make sure you assign it to yourself.
Otherwise someone else may also start working on it, and we don't want to
duplicate efforts.  Also, if you find a bug in the code and want to post a
fix, make sure you file a bug (and assign it to yourself!) just in case someone
else comes across the problem in the meantime.

Reporting a Bug
~~~~~~~~~~~~~~~

You found an issue and want to make sure we are aware of it? You can do so in
the StoryBoard of the affected deliverable.

Getting Your Patch Merged
~~~~~~~~~~~~~~~~~~~~~~~~~

The Barbican project policy is that a patch must have two +2s before it can
be merged.  (Exceptions are documentation changes, which require only a
single +2, and specs, for which the PTL may require more than two +2s,
depending on the complexity of the proposal.)

Patches lacking unit tests are unlikely to be approved.  Check out the
testing-barbican section of the Barbican Contributors Guide for a
discussion of the kinds of testing we do with barbican.

In addition, some changes may require a release note.  Any patch that
changes functionality, adds functionality, or addresses a significant
bug should have a release note.  You can find more information about
how to write a release note in the release-notes section of the
Barbican Contributors Guide.

Keep in mind that the best way to make sure your patches are reviewed in
a timely manner is to review other people's patches.  We're engaged in a
cooperative enterprise here.

You can see who's been doing what with Barbican recently in Stackalytics:
https://www.stackalytics.com/report/activity?module=barbican-group

Project Team Lead Duties
~~~~~~~~~~~~~~~~~~~~~~~~

All common PTL duties are enumerated in the `PTL guide
<https://docs.openstack.org/project-team-guide/ptl.html>`_.
