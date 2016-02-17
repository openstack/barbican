Adding/Updating Dependencies
============================

Adding new Dependency
---------------------

If you need to add a new dependency to Barbican, you must edit a few things:

#. Add the package name (and minimum version if applicable) to the
   requirements.txt file in the root directory.

   .. note:: All dependencies and their version specifiers must come from the
             OpenStack `global requirements`_ repository.
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
