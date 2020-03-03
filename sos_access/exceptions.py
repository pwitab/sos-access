class SOSAccessClientException(Exception):
    """General exception in client"""


class SOSAccessServerException(Exception):
    """General exception in server"""


class IncorrectlyConfigured(SOSAccessClientException):
    """The client is incorrectly configured"""


class SOSAccessError(SOSAccessClientException):
    """General Exception in transfer of alarms"""


class InvalidLength(SOSAccessError):
    """Message is too long"""


class InvalidXML(SOSAccessError):
    """Invalid XML content"""


class WrongContent(SOSAccessError):
    """Incorrect data in content. ex: too long text in a field."""


class NotAuthorized(SOSAccessError):
    """Not autorized. wrong combination of transmitter, instance or password."""


class NotTreatedNotDistributed(SOSAccessError):
    """Alarm not treated or distributed."""  # Use failover address


class MandatoryDataMissing(SOSAccessError):
    """Mandatory XML tag missing"""


class ServiceUnavailable(SOSAccessError):
    """Not autorized to use heartbeat service"""


class DuplicateAlarm(SOSAccessError):
    """Same alarm received multiple times"""


class OtherError(SOSAccessError):
    """Unknown receiver error"""  # use failover address.


class XMLHeaderError(SOSAccessError):
    """XML Header missing, or invalid"""


class PingToOften(SOSAccessError):
    """Heartbeat is sent too often"""


class ServerSystemError(SOSAccessServerException):
    """System error in receiving server"""


class TCPTransportError(Exception):
    """Something went wrong in sending data"""


class AlarmReceiverConnectionError(SOSAccessClientException):
    """Not possible to connect to the Alarm receivers specified"""


class XMLParseError(Exception):
    """Problem parsing XML"""
