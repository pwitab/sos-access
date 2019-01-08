.. _api:

=============
API Reference
=============

Client
------

.. module:: sos_access.client

.. autoclass:: SOSAccessClient
   :members:

.. autoclass:: TCPTransport
   :members:


Schemas and models
------------------

sos-access uses marshmallow and xmltodict to first make objects into dicts and
then into xml when dumping data and the opposit when loading data


.. module:: sos_access.schemas

.. autoclass:: SOSAccessRequest
   :members:

.. autoclass:: SOSAccessSchema
   :members:


.. autoclass:: AlarmRequest
   :members:

.. autoclass:: AlarmRequestSchema
   :members:


.. autoclass:: AlarmResponse
   :members:

.. autoclass:: AlarmResponseSchema
   :members:

.. autoclass:: PingRequest
   :members:

.. autoclass:: PingRequestSchema
   :members:

.. autoclass:: PingResponse
   :members:

.. autoclass:: PingResponseSchema
   :members:

.. autoclass:: NewAuthRequest
   :members:

.. autoclass:: NewAuthRequestSchema
   :members:

.. autoclass:: NewAuthResponse
   :members:

.. autoclass:: NewAuthResponseSchema
   :members:


