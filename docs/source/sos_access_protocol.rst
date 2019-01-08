.. _sos_access_protocol:

SOS Access v4 Protocol
======================

SOS Access V4 protocol is intended for transmission of alarm signals between
alarm transmitters and receivers.

Functions for monitoring the transmission link are included.

It is an XML based protocol and nly printable 8-bits characters from
ISO8859-1 are allowed.

The protocol consists of the following message types:

Alarm Requests
--------------

<alarmrequest>
    Alarm, reset or information message
<alarmresponse>
    Response message for <alarmrequests>

Change password
---------------

<requestnewauthentication>
    Request new password
<requestnewauthenticationresponse>
    Response message for <requestnewauthentication> messages, containing the
    new password

Monitored Links
---------------

<pingrequest>
    Hearbeat message from the alarm transmitter
<pingresponse>
    Response message for <pingrequest>


Client Implementation
---------------------

In the sos-access client the messages are modeled by the following classes

.. module:: sos_access.schemas

<alarmrequest> -> :class:`AlarmRequest`

<alarmresponse> -> :class:`AlarmResponse`

<requestnewauthentication> -> :class:`NewAuthRequest`

<requestnewauthenticationresponse> -> :class:`NewAuthResponse`

<pingrequest> -> :class:`PingRequest`

<pingresponse> -> :class:`PingResponse`


Alarm Transmission
==================

<alarmrequest> is the telegram that is used when an alarm is sent to the alarm
receiver. The server responds with a <alarmresponse>


The maximum message size for a single telegram is limited to 100 000 characters
including XML- header and XML-tags.

.. _alarm-request:

Alarm Requests  <alarmrequest>
------------------------------

Element definitions
^^^^^^^^^^^^^^^^^^^

<alarmrequest>
   | Containing element of the alarm request

<reference>
   |  OPTIONAL
   |  1-50 Characters
   |  This id is only a reference number/string.
      It is not treated by the receiver although it is returned in the
      <alarmresponse> and is stored in the log for trace purposes.

<authentication>
   |  SUPPLIED BY ALARM OPERATOR
   |  15 Characters
   |  Password for the alarm transmitter

<receiver>
   |  SUPPLIED BY ALARM OPERATOR
   |  1-20 Characters
   |  Distribution information. Determines to which alarm monitoring center
      the alarm are distributed to if the alarm receiver has several monitoring
      centers.

<transmittertime>
   |  OPTIONAL
   |  23 Characters.
   |  Ex.”2002-05-28 11:35:20.022”
      Time stamp from the transmitter. Only used for log/trace.

.. todo::

   Contact SOS Alarm and double check if this only supports RFC-822 without
   timestamp.

<alarmtype>
   |  "OPTIONAL" -> If not present the receiver will assume "AL"
   |  2 Characters
   |  Indicates Alarm or Restore: "AL" = Alarm, "RE" = Restore

<transmittertype>
   |  SUPPLIED BY ALARM OPERATOR
   |  5 Characters
   |  Type of transmitter. Ex: “MC200”


<transmittercode>
   |  SUPPLIED BY ALARM OPERATOR
   |  1-15 Characters
   |  Alarm transmitter number (customer code).  Ex: “12345678”


<transmitterarea>
   |  OPTIONAL
   |  1-5 Characters
   |  Different areas on an alarm transmitter can be used to initiate a
      different action at the alarm receiver on the same alarm code and from
      the same alarm transmitter

<eventcode>
   |  1-25 Characters
   |  The event code is the carrier of the alarm event. The event codes need to
      be set up at the alarm operator so that an action will be initiated.
      The exact event code can technically be anything but it is common to use
      for example SIA codes, (FA = Fire Alarm, BA = Burglary Alarm)

<section>
   |  OPTIONAL
   |  1-5 Characters
   |  Section identification. Short code for the section where the alarm is
      active

<sectiontext>
   |  OPTIONAL
   |  1-40 Characters
   |  Section description. Long description of the section where the alarm is
      active

<detector>
   |  OPTIONAL
   |  1-5 Characters
   |  Detector identification. Short code for the detector that set the alarm
      active

<detectortext>
   |  OPTIONAL
   |  1-40 Characters
   |  Detector description. Long description of the detector that set the alarm
      active

<additionalinfo>
   |  OPTIONAL
   |  1-2000 Characters
   |  Additional information about the alarm. Lines are separated by CR+LF or
      LF; (LF = ASCII 10 (0x0a) and CR= ASCII 13 (0x0d))

<position>
   |  OPTIONAL
   |  n Characters
   |  Contains inner element <pos> that holds the Geographical coordinate.

   |  RT90 (2,5 gon West): “xXXXXXXXyYYYYYYY” where x is the x-coordinate, y is
      the y- coordinate. Values are given in meters.

      .. code-block:: xml
         :caption: RT90

         <position>
            <pos>x1234567y1234567</pos>
         </position>

   |  WGS84 (Lat/Long): “NDDMMmmEDDDMMmm” where DD are degrees; MM minutes;
      mm decimal minutes (leading 0 shall be given on the longitude if needed).

      .. code-block:: xml
         :caption: WGS84

         <position>
            <pos>E597295E0176288</pos>
         </position>

.. todo::

   Contact SOS Alarm and clarify what happens when an alarm transmitter has a
   position in the recieving system but a different one is provided via the
   alarm.


XML Examples <alarmrequest>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^


.. code-block:: xml
   :caption: Example of minimum data to send alarm.

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <alarmrequest>
      <authentication>hxp4x9nnwxjatv8</authentication>
      <receiver>42</receiver>
      <alarmtype>AL</alarmtype>
      <transmittertype>SV300</transmittertype>
      <transmittercode>1234567</transmittercode>
      <eventcode>BA</eventcode>
    </alarmrequest>


.. code-block:: xml
   :caption: Example sending alarm using reference.

   <?xml version="1.0" encoding="ISO-8859-1"?>
   <alarmrequest>
      <authentication>hxp4x9nnwxjatv8</authentication>
      <reference>1</reference>
      <receiver>42</receiver>
      <alarmtype>AL</alarmtype>
      <transmittertype>SV300</transmittertype>
      <transmittercode>1234567</transmittercode>
      <eventcode>BA</eventcode>
   </alarmrequest>


.. code-block:: xml
   :caption: Example of restoring previous sent fire alarm.

    <?xml version="1.0" encoding="ISO-8859-1"?>
   <alarmrequest>
      <authentication>hxp4x9nnwxjatv8</authentication>
      <reference>13843</reference>
      <receiver>42</receiver>
      <transmittertype>SV300</transmittertype>
      <transmittercode>1234567</transmittercode>
      <alarmtype>RE</alarmtype>
      <eventcode>FA</eventcode>
   </alarmrequest>^



Alarm Response  <alarmresponse>
-------------------------------

Element definitions
^^^^^^^^^^^^^^^^^^^

<alarmresponse>
    |   Containing element of the alarm response

<reference>
    |   OPTIONAL
    |   1-50 Characters
    |   The transmitter reference from the <alarmrequest> if sent to the receiver.

<status>
    |   Described in :ref:`response-codes`

<info>
    |   Status information in clear text. Also described in :ref:`response-codes`

<arrivaltime>
    |   The time when the receiver received the alarm message.


XML Examples <alarmresponse>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: xml
   :caption: Example of positive response

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <alarmresponse>
        <reference>001</reference>
        <status>0</status>
        <info>OK</info>
        <arrivaltime>2006-12-24 15:00:00.000</arrivaltime>
    </alarmresponse>

.. code-block:: xml
   :caption: Example of on negative response of a message with wrong authentication

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <alarmresponse>
        <reference>001</reference>
        <status>6</status>
        <info>NOT_AUTHORIZED</info>
        <arrivaltime>2006-12-24 15:00:00</arrivaltime>
    </alarmresponse>


Requesting new authentication/password
======================================

Alarm receiver should implement a function to change the password.

This function should change the password after the first connection to the
alarm receiver. The new password shall be stored in the transmitter and used
here after. This prevents that and installation company or anybody else knows
the password.

This makes it very hard to setup another transmitter to send false alarms.

The new password should not be visible in the configuration interface for
the alarm transmitter.

If an error occurs during the password change, the old password will be valid
until the first message with the new password is received.

If the NOT_AUTHORIZED reply is received from transmitter the receiver should
alert the customer to take proper action. It might be necessary to contact the
alarm operators customer support for a new password.

If the transmitter is replaced a new password is required from alarm operator.

The change off passoword is requested with <requestnewauthentication> and the
response <requestnewauthenticationresponse> is sent back containing the new
password.

New Auth Request <requestnewauthentication>
--------------------------------------------

Element definitions
^^^^^^^^^^^^^^^^^^^

<requestnewauthentication>
    |   Containing element of the new auth request

<authentication>
    |   15 Characters
    |   Authentication (current password)

<reference>
    |   OPTIONAL
    |   1-50 Characters
    |   See :ref:`alarm-request`

<transmittercode>
    |   See :ref:`alarm-request`

<transmittertype>
    |   See :ref:`alarm-request`



XML Examples <requestnewauthentication>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: xml
   :caption: New auth request with reference

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <requestnewauthentication>
        <authentication>l4x85dshyrbla27</authentication>
        <reference>46</reference>
        <transmittercode>1234567</transmittercode>
        <transmittertype>ET800</transmittertype>
    </requestnewauthentication>



New Auth Response <requestnewauthenticationresponse>
----------------------------------------------------

Element definitions
^^^^^^^^^^^^^^^^^^^

<requestnewauthenticationresponse>
    |   Containing element of the new auth response

<reference>
    |   1-50 Characters
    |   See :ref:`alarm-request`

<status>
    |   Described in :ref:`response-codes`

<info>
    |   Status information in clear text. Also described in :ref:`response-codes`

<newauthentication>
    |   15 Characters
    |   The new password.

<arrivaltime>
    |   The time when the receiver received the request.


XML Examples <requestnewauthenticationresponse>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: xml
   :caption: New auth response with reference

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <requestnewauthenticationresponse>
        <reference>46</reference>
        <status>0</status>
        <info>OK</info>
        <authentication>8usedlb54a234md</authentication>
        <arrivaltime>2006-12-24 15:00:00</arrivaltime>
    </requestnewauthenticationresponse>


Monitored Connection
====================

Monitored connection is a function where the alarm receiver monitors that the
transmitter sends heartbeat signals on a regular basis. The alarm transmitter
is the initiating part in this function. If the receiver does not get a
heartbeat signal in the agreed interval a line fault alarm is generated to
the alarm operator.

The service is available in four different levels:

1. 25 hours (90000 seconds)
2. 5 hours (18000 seconds)
3. 180 seconds
4. 90 seconds


When using heartbeat levels 3 and 4 it is mandatory to implement failover
functionality in transmitter. If the primary receiver fails to handle the
incoming request, the transmitter should resend the alarm to failover receiver.

If the failover receiver fails as well the transmitter shall have alternative
delivery way over example GPRS or/and UMTS.

Each service level requires that at least two heartbeat signals shall be sent
within the interval.

It is recommend that the transmitter sends at least three heartbeat signals per
servicelevel time but no more than six.


.. todo::

    There is a protection if sending <pingrequest> very shortly a after each
    other that the server responds with PING_TO_OFTEN. What is this exact timelimit? Contact SOS Alarm and ask.

If heartbeat signals is sent to frequent an error message will be replied in the
ping request response (PING_TO_OFTEN).

The heartbeat is sent in a <pingrequest> and the server answers with a
<pingresponse>

The alarm receiver sends a response message after receiving the ping request.
In the response message, the time is attached; this can be used for
synchronizing the clock in the transmitter.


Ping Request <pingrequest>
--------------------------

Element definitions
^^^^^^^^^^^^^^^^^^^

<pingrequest>
    |   Containing element of the ping request

<authentication>
    |   15 Characters
    |   Authentication (current password)

<reference>
    |   OPTIONAL
    |   1-50 Characters
    |   See :ref:`alarm-request`

<transmittercode>
    |   See :ref:`alarm-request`

<transmittertype>
    |   See :ref:`alarm-request`



XML Examples <pingrequest>
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: xml
   :caption: ping request with reference

    <?xml version="1.0" encoding="iso-8859-1"?>
    <pingrequest>
        <authentication>hxp4x9nnwxjatv8</authentication>
        <reference>734632</reference>
        <transmittercode>208013</transmittercode>
        <transmittertype>SV300</transmittertype>
    </pingrequest>


Ping Response <pingresponse>
-----------------------------

Element definitions
^^^^^^^^^^^^^^^^^^^

<pingresponse>
    |   Containing element of the ping response

<reference>
    |   1-50 Characters
    |   See :ref:`alarm-request`

<status>
    |   Described in :ref:`response-codes`

<info>
    |   Status information in clear text. Also described in :ref:`response-codes`

<arrivaltime>
    |   The time when the receiver received the alarm message.


XML Examples <requestnewauthenticationresponse>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: xml
   :caption: New ping response with reference

    <?xml version="1.0" encoding="iso-8859-1"?>
    <pingresponse>
        <reference>734632</reference>
        <status>0</status>
        <info>OK</info>
        <arrivaltime>2005-02-28 11:35:42.012</arrivaltime>
    </pingresponse>




.. _response-codes:

Response Codes
==============

The following response codes with their status number and info description:

=======  ================================  ========================================
Status    Info                              Description
=======  ================================  ========================================
0        OK                                  OK
1        INVALID_LENGTH                      Message to long.
2        INVALID_XML                         Invalid xml content.
3        WRONG_CONTENT                       Wrong data content, i.e. to long text for a field.
4        NOT_AUTHORIZED                      Not authorized, wrong transmitter, instance or password
5        NOT_TREATED_NOT_DISTRIBUTED         Not treated or distributed. Fail over address should be used.
7        MANDATORY_DATA_MISSING              Mandatory XML tag missing
9        SERVICE_UNAVAIVABLE                 Not authorized for heartbeat service.
10       DUPLICATED_ALARM                    Same alarm received multiple times.
98       SERVER_ERROR                        Unknown server error
99       OTHER_ERROR                         Unknown receiver error, the transmitter should send alarm to failover address.
100      XML_HEADER_MISSING_OR_INVALID       Invalid or missing XML header.
101      PING_TO_OFTEN                       Heartbeat is sent to often.
=======  ================================  ========================================




