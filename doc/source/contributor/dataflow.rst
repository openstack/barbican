Dataflow
========

Bootup flow when the Barbican API service begins
------------------------------------------------

This is the sequence of calls for booting up the Barbican API server:

#. ``bin/barbican.sh start``: Launches a WSGI service that performs a
   PasteDeploy process, invoking the middleware components found in
   ``barbican/api/middleware`` as configured in
   ``etc/barbican/barbican-api-paste``. The middleware
   components invoke and then execute the Pecan application created via
   ``barbican/api/app.py:create_main_app()``, which also
   defines the controllers (defined in ``barbican/api/controllers/``) used to
   process requested URI routes.


Typical flow when the Barbican API executes
-------------------------------------------

For **synchronous** calls, the following sequence is generally followed:

#. A client sends an HTTP REST request to the Barbican API server.
#. The WSGI server and routing invokes a method on one of the
   ``XxxxController`` classes in ``barbican/api/controllers/xxxx.py``,
   keyed to an HTTP verb (so one of POST, GET, DELETE, or PUT).

   #. Example - GET /secrets:

      #. In ``barbican/api/controllers/secrets.py``, the ``SecretController``'s
         ``on_get()`` is invoked.
      #. A ``SecretRepo`` repository class (found in
         ``barbican/model/respositories.py``) is then used to retrieve the
         entity of interest, in this case as a ``Secret`` entity  defined in
         ``barbican/model/models.py``.
      #. The payload is decrypted as needed, via
         ``barbican/plugin/resources.py``'s ``get_secret()`` function.
      #. A response JSON is formed and returned to the client.

For **asynchronous** calls, the following sequence is generally followed:

#. A client sends an HTTP REST request to the Barbican API server.
#. The WSGI server and routing again invokes a method on one of the
   ``XxxxcController`` classes in ``barbican/api/controllers/``.
#. A remote procedure call (RPC) task is enqueue for later processing by a
   worker node.

   #. Example - POST /orders:

      #. In ``barbican/api/controllers/orders.py``, the ``OrdersController``'s
         ``on_post()`` is invoked.
      #. The ``OrderRepo`` repository class (found in
         ``barbican/model/respositories.py``) is then used to create the
         ``barbican/model/models.py``'s ``Order`` entity in a 'PENDING' state.
      #. The Queue API's ``process_type_order()`` method on the ``TaskClient``
         class (found in ``barbican/queue/client.py``) is invoked to send a
         message to the queue for asynchronous processing.
      #. A response JSON is formed and returned to the client.

#. The Queue service receives the message sent above, invoking a corresponding
   method on ``barbican/queue/server.py``'s ``Tasks`` class. This method then
   invokes the ``process_and_suppress_exceptions()`` method on one of the
   ``barbican/tasks/resources.py``'s ``BaseTask`` implementors. This method
   can then utilize repository classes as needed to retrieve and update
   entities. It may also interface with third party systems via plugins`. The
   ``barbican/queue/client.py``'s ``TaskClient`` class above may also be
   invoked from a worker node for follow on asynchronous processing steps.

   #. Example - POST /orders (continued):

      #. Continuing the example above, the queue would invoke the
         ``process_type_order()`` method on ``barbican/queue/server.py``'s
         ``Tasks`` class. Note the method is named the same as the
         ``TaskClient`` method above by convention.

      #. This method then invokes ``process_and_suppress_exceptions()`` on
         the ``barbican/tasks/resources.py``'s ``BeginTypeOrder`` class. This
         class is responsible for processing all newly-POST-ed orders.
