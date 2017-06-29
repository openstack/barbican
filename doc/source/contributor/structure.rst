Project Structure
=================

#. ``barbican/`` (Barbican-specific Python source files)

   #. ``api/`` (REST API related source files)

      #. ``controllers/`` (Pecan-based controllers handling REST-based requests)
      #. ``middleware/`` (Middleware business logic to process REST requests)

   #. ``cmd/`` (Barbican admin command source files)
   #. ``common/`` (Modules shared across other Barbican folders)
   #. ``locale/`` (Translation templates)
   #. ``model/`` (SQLAlchemy-based model classes)
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

#. ``bin/`` (Start-up scripts for the Barbican nodes)
#. ``devstack/`` (Barbican DevStack plugin, DevStack gate configuration and
    Vagrantfile for installing DevStack VM)
#. ``etc/barbican/`` (Configuration files)
#. ``functionaltests`` (Functional Barbican tests)
#. ``doc/source`` (Sphinx documentation)
#. ``releasenotes`` (Barbican Release Notes)
