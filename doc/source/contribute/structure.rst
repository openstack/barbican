Project Structure
=================

#. ``barbican/`` (Barbican-specific Python source files)

   #. ``api/`` (REST API related source files)

      #. ``controllers/`` (Pecan-based controllers handling REST-based requests)
      #. ``middleware/`` (Middleware business logic to process REST requests)

   #. ``common/`` (Modules shared across other Barbican folders)
   #. ``model/`` (SQLAlchemy-based model classes)
   #. ``openstack/`` (OpenStack utility Python source and folders - generated
      from oslo-incubator)
   #. ``plugin/`` (Plugin related logic, interfaces and look-up management)

      #. ``resources.py`` (Supports interactions with plugins)
      #. ``crypto/`` (Hardware security module (HSM) logic and plugins)
      #. ``interface/`` (Certificate manager and secret store interface
         classes)
      #. (The remaining modules here are implementations of above interfaces)

   #. ``queue/`` (Client and server interfaces to the queue)

      #. ``client.py`` (Allows clients to publish tasks to queue)
      #. ``server.py`` (Runs the worker service, responds to enqueued tasks)

   #. ``tasks/`` (Worker-related controllers and implementations)
   #. ``tests/`` (Unit tests)

#. ``bin/`` (Start-up scripts for the Barbican nodes (API and worker))
#. ``rpmbuild/`` (RPM package artifacts)
#. ``etc/barbican/`` (Configuration files)
#. ``functionaltests`` (Functional Barbican tests, DevStack gate configuration)
#. ``doc/source`` (Sphinx documentation)
#. ``docs/src`` (Docbook documentation - on hold pending project tagging)
