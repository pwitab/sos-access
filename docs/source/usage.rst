.. _usage:

============
Installation
============

sos-access requires python version > 3.6

To install use pip:

.. code-block:: bash

    pip install sos-access


===============
Create a Client
===============

A client represents one transmitter. If you want to send alarms from several
transmitters you need to create several client instances.

The SOS Alarm Access v4 requires you to set up two receivers when sending alarm.
For development and testing this is not really necessary. We have the
use_single_receiver to tell the client that it is ok that only one receiver
was supplied.

For creating clients that sends the alarms encrypted to the alarm receiver set use_tls to True

.. code-block:: python

    client = SOSAccessClient(
        transmitter_code='IK00001',
        transmitter_type='SV001',
        authentication='012345678912345',
        receiver_address='alarm.example.com',
        receiver_id='ALARM-OPER',
        use_single_receiver=True,
        use_tls=True
        )


===============
Send an  Alarm
===============

It is easy to send an alarm. Just use the .send_alarm() function.
The minimal you need to supply is an event_code. You need to agree on an event
code schema with your alarm operator to make actions in case of an alarm.

.. code-block:: python

    # Simple invocation
    response = client.send_alarm(event_code='AL')


    # All options
    response = client.send_alarm(
        event_code='AL',
        transmitter_time=datetime.datetime.now(),
        reference='my_first_alarm',
        transmitter_area='12345',
        section='1',
        section_text='my_section',
        detector='1',
        detector_text='my_detector',
        additional_info={'key': 'test'},
        position=None
        )


.. note::

    additional_info supports receiving a string, dict or an iterable
    (list, set, tuple). If dict it will be generated as a string with all keys
    and values on different rows. If an iterable it will be converted into a
    string with all items on different rows.


.. note::

    As of now there is no good handling of position data. You will need to
    supply the correctly formatted position yourself.

===========
Send a ping
===========

Ping is sent via the .ping() method.

.. code-block:: python

    response = client.ping(reference='my-ping')  # reference will only appear in logs.



==============================
Change password of transmitter
==============================

It is possible to change the password of the transmitter. You need to be aware
that the client does not persist this password anywhere. If you change the
password you need to collect the new password returned from the receiver server
and store it for later use.


.. code-block:: python

    new_auth_response = client.request_new_auth()

    my_save_pass_func(new_auth_response.new_authentication)


.. note::

    The new password only starts working after the first new transmission
    using it. Until then you can use the old password.


=======
Retries
=======

The client implements a retry functionality between the primary and secondary
alarm receiver.

In the specification of the SOS Access v4 protocol there is nothing hindering
the client from keep alternately retrying each server for ever. But this is not
practical. The standard value of retry for the client is 3 times on each receiver.

If you need to change this then subclass the client and change MAX_RETRY

.. code-block:: python

    class ManyRetryClient(SOSAccessClient):
        MAX_RETRY = 100


