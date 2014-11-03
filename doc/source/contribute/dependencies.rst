Adding/Updating Dependencies
============================

Adding new Dependency
---------------------

If you need to add a new dependency to Barbican, you must edit a few things:

#. Add the package name (and minimum version if applicable) to the
   requirements.txt file in the root directory.

   .. note:: All dependencies and their version specifiers must come from the
             Openstack `global requirements`_ repository.
#. We support deployment on CentOS 6.4, so you should check CentOS + EPEL 6 yum
   repos to figure out the name of the rpm package that provides the package
   you're adding. Add this package name as a dependency in
   ``rpmbuild/SPECS/barbican.spec``.
#. If there is no package available in CentOS or EPEL, or if the latest
   available package's version is lower than the minimum required version we
   must build an rpm for it ourselves. Add a line to
   ``rpmbuild/package_dependencies.sh`` so that jenkins will build an rpm using
   fpm and upload it to the cloudkeep yum repo.


.. _`global requirements`: https://git.openstack.org/cgit/openstack/requirements/tree/global-requirements.txt


Configure/Update Project from Oslo-Incubator
--------------------------------------------

The Barbican project utilizes components from the ``oslo-incubator`` project,
such as logging and configuration support modules. The following steps may be
used to setup and maintain the project environment:

#. In the ``barbican`` folder, ensure there is a file named
   ``openstack-common.conf`` with content such as the following:

   .. code-block:: ini

       [DEFAULT]

       # The list of modules to copy from openstack-common
       modules=gettextutils,jsonutils,log,local,notifier,timeutils,uuidutils,importutils

       # The base module to hold the copy of openstack.common
       base=barbican
#. From another directory in your environment (other than within barbican),
   clone the ``oslo-incubator`` project as:
   ``git clone https://github.com/openstack/oslo-incubator.git``.
#. ``cd oslo-incubator``
#. Configure a virtual environment, and then enter it.
#. Execute ``pip install -r requirements.txt``.
#. Execute ``python update.py <path to barbican folder>``. For example, if the
   ``olso-incubator`` folder is in the same parent folder as ``barbican``,
   supply ``../barbican`` for the path. Output such as the following should
   occur:

   .. code-block:: text

       Copying openstack.common.gettextutils under the barbican module in ../barbican
       Copying openstack.common.jsonutils under the barbican module in ../barbican
       ...(munch)...
       Copying openstack.common.loopingcall under the barbican module in ../barbican
#. An ``openstack`` folder should now be visible under the ``barbican`` folder.
