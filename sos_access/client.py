import logging
import socket
import ssl

from sos_access.exceptions import (IncorrectlyConfigured, InvalidLength,
                                   InvalidXML, WrongContent, NotAuthorized,
                                   NotTreatedNotDistributed,
                                   MandatoryDataMissing, ServiceUnavailable,
                                   DuplicateAlarm, OtherError, XMLHeaderError,
                                   PingToOften, ServerSystemError)
from sos_access.schemas import (AlarmRequestSchema, AlarmRequest,
                                AlarmResponseSchema, PingRequest,
                                PingRequestSchema, PingResponseSchema,
                                NewAuthRequestSchema, NewAuthResponseSchema,
                                NewAuthRequest)

# TODO: Does not yet support sending restore messages.
# Sending no alarm type defaults to alarm_type AL and to restore we need to send
# alarm type RE.

logger = logging.getLogger(__name__)


class SOSAccessClient:
    """
    Client implementing the SOS Access v4 protocol to be used for sending Alarm
    Requests to alarm operators.

    :param transmitter_code:
    :param transmitter_type:
    :param authentication:
    :param receiver_id:
    :param receiver_address:
    :param secondary_receiver_address:
    :param use_single_receiver:
    :param use_tls:
    """

    def __init__(self, transmitter_code, transmitter_type, authentication,
                 receiver_id, receiver_address, secondary_receiver_address=None,
                 use_single_receiver=False, use_tls=False):

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
                'Both primary and secondary receiver address is needed.')

        if use_tls:
            self.session_class = SecureSOSAccessSession
        else:
            self.session_class = SOSAccessSession

        # load all schemas so we don't have to remember to do it again.
        self.alarm_request_schema = AlarmRequestSchema()
        self.alarm_response_schema = AlarmResponseSchema()
        self.ping_request_schema = PingRequestSchema()
        self.ping_response_schema = PingResponseSchema()
        self.new_auth_request_schema = NewAuthRequestSchema()
        self.new_auth_response_schema = NewAuthResponseSchema()

    @staticmethod
    def _check_response_status(response):
        """
        Checks the status of the response and raise approriate errors if the
        request wasn't successful.

        :param response:
        """
        # TODO: Test!
        if response.status == 1:
            exception_info = f'{response.info}'
            raise InvalidLength(exception_info)
        elif response.status == 2:
            exception_info = f'{response.info}'
            raise InvalidXML(exception_info)
        elif response.status == 3:
            exception_info = f'{response.info}'
            raise WrongContent(exception_info)
        elif response.status == 4:
            exception_info = f'{response.info}'
            raise NotAuthorized(exception_info)
        elif response.status == 5:
            exception_info = f'{response.info}'
            raise NotTreatedNotDistributed(exception_info)
        elif response.status == 7:
            exception_info = f'{response.info}'
            raise MandatoryDataMissing(exception_info)
        elif response.status == 9:
            exception_info = (f'{response.info}: Hearbeat is not enabled on the'
                              f' server for this alarm device')
            raise ServiceUnavailable(exception_info)
        elif response.status == 10:
            exception_info = f'{response.info}'
            raise DuplicateAlarm(exception_info)
        elif response.status == 98:
            exception_info = f'{response.info}'
            raise  ServerSystemError(exception_info)
        elif response.status == 99:
            exception_info = f'{response.info}'
            raise OtherError(exception_info)
        elif response.status == 100:
            exception_info = f'{response.info}'
            raise XMLHeaderError(exception_info)
        elif response.status == 101:
            exception_info = f'{response.info}'
            raise PingToOften(exception_info)


    def send_alarm(self, event_code, alarm_type=None, transmitter_time=None,
                   reference=None, transmitter_area=None, section=None,
                   section_text=None, detector=None, detector_text=None,
                   additional_info=None, position=None):
        """
        Sends an alarm to system.

        :param event_code:
        :param alarm_type:
        :param transmitter_time:
        :param reference:
        :param transmitter_area:
        :param section:
        :param section_text:
        :param detector:
        :param detector_text:
        :param additional_info:
        :param position:
        :return:
        """
        alarm_request = AlarmRequest(event_code=event_code,
                                     transmitter_type=self.transmitter_type,
                                     transmitter_code=self.transmitter_code,
                                     authentication=self.authentication,
                                     receiver=self.receiver_id,
                                     alarm_type=alarm_type,
                                     transmitter_time=transmitter_time,
                                     reference=reference,
                                     transmitter_area=transmitter_area,
                                     section=section, section_text=section_text,
                                     detector=detector,
                                     detector_text=detector_text,
                                     additional_info=additional_info,
                                     position=position)

        with self.session_class(self) as session:
            out_data = self.alarm_request_schema.dump(alarm_request)
            session.send(out_data)
            in_data = session.receive()
            alarm_response = self.alarm_response_schema.load(in_data)
            self._check_response_status(alarm_response)
            print(in_data)
            return alarm_response

    def ping(self, reference=None):
        """Sends a heart beat message to indicate to the alarm operator that
        the alarm device is still operational
        """

        ping_request = PingRequest(authentication=self.authentication,
                                   transmitter_code=self.transmitter_code,
                                   transmitter_type=self.transmitter_type,
                                   reference=reference)

        with self.session_class(self) as session:
            out_data = self.ping_request_schema.dump(ping_request)
            session.send(out_data)
            in_data = session.receive()
            ping_response = self.ping_response_schema.load(in_data)
            self._check_response_status(ping_response)
            print(in_data)
            return ping_response

    def request_new_auth(self, reference=None):
        """
        Send a request for new password on the server. This is used so that
        you can have a standard password when deploying devices but it is
        changed to something the alarm installer does not know when the alarm
        is operational
        """


        new_auth_request = NewAuthRequest(authentication=self.authentication,
                                          transmitter_code=self.transmitter_code,
                                          transmitter_type=self.transmitter_type,
                                          reference=reference)

        with self.session_class(self) as session:
            out_data = self.new_auth_request_schema.dump(new_auth_request)
            print(out_data)
            session.send(out_data)
            in_data = session.receive()
            print(in_data)
            # TODO: if an server exception is raised it will not send back the correct response with all field.
            new_auth_response = self.new_auth_response_schema.load(in_data)
            self._check_response_status(new_auth_response)
            print(in_data)
            print(new_auth_response.new_authentication)
            self.authentication = new_auth_response.new_authentication
            return new_auth_response.new_authentication


class SOSAccessSession:
    """
    Session handling TCP socket and sending and receiving data with the corect
    encoding.
    """

    ENCODING = 'latin-1'  # it is in the specs only to allow iso-8859-1

    # TODO: how to handle secondary receiver?
    def __init__(self, client: SOSAccessClient):
        self.client = client
        self.socket = self._get_socket()

    def __enter__(self):
        # TODO: need to handle exceptions in enter
        self.socket.connect(self.client.receiver_address)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()
        # handle and reraise exceptions from socket.
        # handle and reraise eceptions from client error.
        # handle SSLErrors!
        pass

    def _get_socket(self):
        """Returns socket for the session"""
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send(self, data):
        """Send data over socket with correct encoding"""
        self.socket.sendall(data.encode(self.ENCODING))

    def receive(self):
        """Receive data on socket and decode using correct encoding"""
        data = self.socket.recv(4096)
        return data.decode(self.ENCODING)


class SecureSOSAccessSession(SOSAccessSession):
    """
    Session handling encrypted connections to alarm operators.
    """

    def _get_socket(self):
        """Returns SSL/TLS socket"""
        # Setting Purpose to CLIENT_AUTH might seem a bit backwards. But
        # SOS Access v4 is using SSL/TLS for encryption not authentications and
        # verification. There is no cert and no hostname to check so setting the
        # purpose to Client Auth diables that in a nifty way.
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.context.wrap_socket(sock)
