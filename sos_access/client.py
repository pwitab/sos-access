import logging
import socket
import ssl
import time

from sos_access.exceptions import (
    SOSAccessClientException,
    IncorrectlyConfigured,
    InvalidLength,
    InvalidXML,
    WrongContent,
    NotAuthorized,
    NotTreatedNotDistributed,
    MandatoryDataMissing,
    ServiceUnavailable,
    DuplicateAlarm,
    OtherError,
    XMLHeaderError,
    PingToOften,
    ServerSystemError,
    TCPTransportError,
    XMLParseError,
)
from sos_access.schemas import (
    AlarmRequestSchema,
    AlarmRequest,
    AlarmResponseSchema,
    PingRequest,
    PingRequestSchema,
    PingResponseSchema,
    NewAuthRequestSchema,
    NewAuthResponseSchema,
    NewAuthRequest,
    PingResponse,
    AlarmResponse,
    NewAuthResponse,
)

from sos_access.decorators import alternating_retry

logger = logging.getLogger(__name__)


# TODO: Implement Point class for different ways of generation a geografical
#       point and use to position.
# TODO: What event codes are there? An official list?
# TODO: Find better description on what Section and detector is used for in the recieiver
# TODO: Document monitored connections
# TODO: add proper logging
# TODO: convert time to utc aware


class SOSAccessClient:
    """
    Client implementing the SOS Access v4 protocol to be used for sending Alarm
    Requests to alarm operators.

    :param str transmitter_code: The code that identifies the transmitter.
        Supplied by alarm operator
    :param str transmitter_type: The transmitter type.
        Supplied by alarm operator
    :param str authentication:  Password for the alarm transmitter.
        Supplied by alarm operator
    :param str receiver_id: ID for the receiving system. Needed for the
        protocol, but might not be needed by the alarm operator.
    :param (str, int) receiver_address: Tuple of host (IP or FQDN) and port
    :param (str, int) secondary_receiver_address: Tuple of host (IP or FQDN)
        and port
    :param bool use_single_receiver:  To enable not
        supplying secondary_receiver_address
    :param bool use_tls:  Indicates if the transmission of alarm should be
        encrypted using TLS. This library does not support SSLv3 since it is
        insecure.
    """

    MAX_RETRY = 3
    ENCODING = "latin-1"  # it is in the specs only to allow iso-8859-1

    def __init__(
        self,
        transmitter_code,
        transmitter_type,
        authentication,
        receiver_id,
        receiver_address,
        secondary_receiver_address=None,
        use_single_receiver=False,
        use_tls=False,
    ):
        self.transmitter_code = transmitter_code
        self.transmitter_type = transmitter_type
        self.authentication = authentication
        self.receiver_id = receiver_id
        self.receiver_address = receiver_address
        self.secondary_receiver_address = secondary_receiver_address
        self.use_single_receiver = use_single_receiver
        self.use_tls = use_tls

        if self.secondary_receiver_address is None and not use_single_receiver:
            raise IncorrectlyConfigured(
                "Both primary and secondary receiver address is needed."
            )

        # load all schemas so we don't have to remember to do it again.
        self.alarm_request_schema = AlarmRequestSchema()
        self.alarm_response_schema = AlarmResponseSchema()
        self.ping_request_schema = PingRequestSchema()
        self.ping_response_schema = PingResponseSchema()
        self.new_auth_request_schema = NewAuthRequestSchema()
        self.new_auth_response_schema = NewAuthResponseSchema()

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"transmitter_code={self.transmitter_code}, "
            f"transmitter_type={self.transmitter_type}, "
            f"authentication=<redacted>, "
            f"receiver_id={self.receiver_id}, "
            f"receiver_address={self.receiver_address}, "
            f"secondary_receiver_address={self.secondary_receiver_address}, "
            f"use_single_receiver={self.use_single_receiver}, "
            f"use_tls={self.use_tls})"
        )

    def send_alarm(
        self,
        event_code,
        transmitter_time=None,
        reference=None,
        transmitter_area=None,
        section=None,
        section_text=None,
        detector=None,
        detector_text=None,
        additional_info=None,
        position=None,
    ) -> AlarmResponse:
        """
        Sends an alarm in the receiver.

        :param str event_code: The event code of the alarm.
        :param datetime.datetime transmitter_time: Time of the device or system sending
            the alarm
        :param str reference:  A reference that will show up in logs on the
            alarm receiver.
        :param str transmitter_area:  Can be used to control different action at
            the alarm operator on the same transmitter and event_code.
        :param str section:  Section ID
        :param str section_text: Section Description
        :param str detector: Detector ID
        :param str detector_text: Detector Description
        :param str|dict|list|set|tuple additional_info: Extra information about alarm
        :param str position: Position data

        :return: :class:`AlarmResponse` from alarm receiver
        """
        alarm_request = AlarmRequest(
            event_code=event_code,
            transmitter_type=self.transmitter_type,
            transmitter_code=self.transmitter_code,
            authentication=self.authentication,
            receiver=self.receiver_id,
            alarm_type="AL",
            transmitter_time=transmitter_time,
            reference=reference,
            transmitter_area=transmitter_area,
            section=section,
            section_text=section_text,
            detector=detector,
            detector_text=detector_text,
            additional_info=additional_info,
            position=position,
        )
        logger.info(f"Sending alarm request: {alarm_request}")

        return self._send_alarm(alarm_request)

    def restore_alarm(
        self,
        event_code,
        transmitter_time=None,
        reference=None,
        transmitter_area=None,
        section=None,
        section_text=None,
        detector=None,
        detector_text=None,
        additional_info=None,
        position=None,
    ) -> AlarmResponse:
        """
        Restores an alarm in the receiver.

        :param str event_code: The event code of the alarm.
        :param str transmitter_time: Time of the device or system sending the alarm
        :param str reference:  A reference that will show up in logs on the
            alarm receiver.
        :param str transmitter_area:  Can be used to control different action at
            the alarm operator on the same transmitter and event_code.
        :param str section:  Section ID
        :param str section_text: Section Description
        :param str detector: Detector ID
        :param str detector_text: Detector Description
        :param str|dict|list|set|tuple additional_info: Extra information about alarm
        :param str position: Position data

        :return: :class:`AlarmResponse` from alarm receiver

        .. todo::
            Is all the extra fields necessary on alarm restore?

        """
        alarm_request = AlarmRequest(
            event_code=event_code,
            transmitter_type=self.transmitter_type,
            transmitter_code=self.transmitter_code,
            authentication=self.authentication,
            receiver=self.receiver_id,
            alarm_type="RE",
            transmitter_time=transmitter_time,
            reference=reference,
            transmitter_area=transmitter_area,
            section=section,
            section_text=section_text,
            detector=detector,
            detector_text=detector_text,
            additional_info=additional_info,
            position=position,
        )
        logger.info(f"Sending restore alarm request: {alarm_request}")

        return self._send_alarm(alarm_request)

    @alternating_retry
    def _send_alarm(
        self, alarm_request: AlarmRequest, secondary=False
    ) -> AlarmResponse:
        """
        Sending function so it is wrappable with alternating_retry and we can
        check the status of the response object

        :param AlarmRequest alarm_request: The
            :class:`AlarmRequest` to send.
        :param bool secondary: Indicates if the secondary receiver should be
            used. Is used by alternating_retry
        :return: :class:`AlarmRequest`
        """

        out_data = self.alarm_request_schema.dump(alarm_request)
        logger.debug(f"Sending SOS Access Data: {out_data}")
        alarm_response = self.transmit(
            out_data, self.alarm_response_schema, secondary=secondary
        )
        logger.info(f"Received alarm response: {alarm_response}")
        self._check_response_status(alarm_response)
        return alarm_response

    def ping(self, reference=None) -> PingResponse:
        """
        Sends a heart beat message to indicate to the alarm operator that
        the alarm device is still operational

        :param str reference: Is used as reference for the request and can be
            searched for in logs.

        :return: :class:`PingResponse`
        """

        ping_request = PingRequest(
            authentication=self.authentication,
            transmitter_code=self.transmitter_code,
            transmitter_type=self.transmitter_type,
            reference=reference,
        )
        logger.info(f"Sending {ping_request}")
        return self._send_ping(ping_request)

    @alternating_retry
    def _send_ping(self, ping_request: PingRequest, secondary=False) -> PingResponse:
        """
        Sending function so it is wrappable with alternating_retry and we can
        check the status of the response object

        :param PingRequest ping_request: The
            :class:`PingRequest` to send.
        :param bool secondary: Indicates if the secondary receiver should be
            used. Is used by alternating_retry
        :return: :class:`PingResponse`
        """
        out_data = self.ping_request_schema.dump(ping_request)
        logger.debug(f"Sending SOS Access data: {out_data}")
        ping_response = self.transmit(
            out_data, self.ping_response_schema, secondary=secondary
        )
        logger.info(f"Received {ping_response}")
        self._check_response_status(ping_response)
        return ping_response

    def request_new_auth(self, reference=None) -> NewAuthResponse:
        """
        Send a request for new password on the server. This is used so that
        you can have a standard password when deploying devices but it is
        changed to something the alarm installer does not know when the alarm
        is operational

        :param str reference: Is used as reference for the request and can be
            searched for in logs.

        :return: :class:`NewAuthResponse`
        """

        new_auth_request = NewAuthRequest(
            authentication=self.authentication,
            transmitter_code=self.transmitter_code,
            transmitter_type=self.transmitter_type,
            reference=reference,
        )
        logger.info(f"Sending {new_auth_request}")
        return self._send_request_new_auth(new_auth_request)

    @alternating_retry
    def _send_request_new_auth(
        self, new_auth_request: NewAuthRequest, secondary=False
    ) -> NewAuthResponse:
        """
        Sending function so it is wrappable with alternating_retry and we can
        check the status of the response object

        :param NewAuthRequest new_auth_request: The
            :class:`NewAuthRequest` to send.
        :param bool secondary: Indicates if the secondary receiver should be
            used. Is used by alternating_retry

        :return: :class:`NewAuthResponse`
        """
        out_data = self.new_auth_request_schema.dump(new_auth_request)
        logger.debug(f"Sending SOS Access data: {out_data}")
        new_auth_response = self.transmit(
            out_data, self.new_auth_response_schema, secondary=secondary
        )
        logger.info(f"Received {new_auth_response}")
        self._check_response_status(new_auth_response)
        return new_auth_response

    def transmit(self, data, response_schema, secondary=False):
        """
        Will create a TCP connection and send the request and received the
        response and then close the TCP connection.

        :param str data: The SOS Access XML data to be sent.
        :param AlarmResponseSchema|PingResponseSchema|NewAuthResponseSchema response_schema: The
            schema used to deserialize the response.
        :param bool secondary: Indicates if to use the secondary receiver.
        """

        if secondary:
            address = self.secondary_receiver_address
        else:
            address = self.receiver_address
        logger.info(
            f"Starting new connection to {address} with " f"secure={self.use_tls}"
        )

        with TCPTransport(address, secure=self.use_tls) as transport:
            transport.connect()

            transport.send(data.encode(self.ENCODING))

            return self._receive(transport, response_schema)

    def _receive(self, transport, response_schema, timeout=10):
        """
        Some alarm receivers will send the response in several packets.
        Try and parse for each packet and if it doesnt work read some more.

        :param TCPTransport transport: the current transport that has a
            connection to the alarm receiver
        :param AlarmResponseSchema|PingResponseSchema|NewAuthResponseSchema response_schema: The
            schema used to deserialize the response.
        :param int timeout: Indicates how long to try and read more data.

        """
        in_data = ""
        start_time = time.time()
        duration = 0
        while duration < timeout:
            in_data = in_data + transport.receive().decode(self.ENCODING)
            try:
                response = response_schema.load(in_data)
                logger.debug(f"Received SOS Access Data: {in_data}")
                return response
            except XMLParseError:
                duration = time.time() - start_time
                continue

        raise SOSAccessClientException("Reading response within timeout failed")

    @staticmethod
    def _check_response_status(response):
        """
        Checks the status of the response and raise appropriate errors if the
        request wasn't successful.

        :param AlarmResponse|PingResponse|NewAuthResponse response: Response object

        """
        # TODO: Test!
        if response.status == 1:
            raise InvalidLength(f"{response.info}: Message is too long.")
        elif response.status == 2:
            raise InvalidXML(f"{response.info}: Invalid XML content.")
        elif response.status == 3:
            raise WrongContent(
                f"{response.info}: Wrong data content. "
                f"Ex: too long text in a field."
            )
        elif response.status == 4:
            raise NotAuthorized(
                f"{response.info}: Wrong combination of "
                f"transmitter, instance and password"
            )
        elif response.status == 5:
            # Fail over should kick in.
            raise NotTreatedNotDistributed(
                f"{response.info}: Error in "
                f"processing. It has neither been "
                f"treated or distributed"
            )
        elif response.status == 7:
            raise MandatoryDataMissing(
                f"{response.info}: Mandatory XML tag " f"missing"
            )
        elif response.status == 9:
            raise ServiceUnavailable(
                (
                    f"{response.info}: Heartbeat is not enabled on the server for "
                    f"this transmitter or you are not authorized to use it."
                )
            )
        elif response.status == 10:
            raise DuplicateAlarm(
                f"{response.info}: The same alarm was received" f" multiple times"
            )
        elif response.status == 98:
            raise ServerSystemError(f"{response.info}: General receiver error")
        elif response.status == 99:
            # Failover should kick in.
            raise OtherError(f"{response.info}: Unknown receiver error")
        elif response.status == 100:
            raise XMLHeaderError(f"{response.info}: Invalid or missing XML " f"header")
        elif response.status == 101:
            raise PingToOften(f"{response.info}: Heartbeat is sent too often")


class TCPTransport:
    """
    A context manager for TCP sockets to make sure the are closed correctly.
    Can create both secure and non secures sockets.

    """

    def __init__(self, address, secure=False, timeout=5):
        self.address = address
        self.timeout = timeout
        self.socket = self._get_socket(secure, timeout)

    def __enter__(self):
        # If we dont do anything in __enter__ we dont have to handle exceptions
        # twice....
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()
        # Catch any error related to the socket and raise as TCP error
        if exc_type in (OSError, IOError, ssl.SSLError, socket.error, socket.timeout):
            raise TCPTransportError from exc_type(exc_val, exc_tb)

    def _get_socket(self, secure=False, timeout=None):
        """
        Returns socket. If secure is True the socket is wrapped in an
        SSL Context
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout or self.timeout)

        if secure:
            # Setting Purpose to CLIENT_AUTH might seem a bit backwards. But
            # SOS Access v4 is using SSL/TLS for encryption not authentications
            # and verification. There is no cert and no hostname to check so
            # setting the purpose to Client Auth diables that in a nifty way.
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            return self.context.wrap_socket(sock)

        else:
            return sock

    def connect(self, address=None):
        _address = address or self.address
        self.socket.connect(_address)

    def send(self, data):
        """Send data over socket with correct encoding"""
        self.socket.sendall(data)

    def receive(self):
        """Receive data on socket and decode using correct encoding"""
        data = self.socket.recv(4096)
        return data
