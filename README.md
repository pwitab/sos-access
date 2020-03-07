# sos-access
Python client for sending alarm information via SOS Access v4

# Installation

Python version supported: 3.6+

```bash
pip install sos-access
``` 

# Example usage:


```python

client = SOSAccessClient(
    transmitter_code='IK00001',
    transmitter_type='SV001',
    authentication='012345678912345',
    receiver_address=('alarm.example.com',1234),
    receiver_id='ALARM-OPER',
    use_single_receiver=True,
    use_tls=True
)

client.send_alarm(event_code='AL')

```

# Documentation

See full documentation on https://sos-access.readthedocs.io
