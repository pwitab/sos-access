import marshmallow
from marshmallow.validate import Length, OneOf
import xmltodict
import xml
from sos_access.exceptions import XMLParseError

ALLOWED_STATUS_CODES = [0, 1, 2, 3, 4, 5, 7, 9, 10, 98, 99, 100, 101]

ALARM_TYPES = ["AL", "RE"]


# TODO: write tests for all schemas.


class SOSAccessRequest:
    """Base SOS Access Request class"""

    pass


class AlarmRequest(SOSAccessRequest):

    """
    Represents an AlarmRequest


    """

    def __init__(
        self,
        event_code,
        transmitter_type,
        transmitter_code,
        authentication,
        receiver,
        alarm_type=None,
        transmitter_time=None,
        reference=None,
        transmitter_area=None,
        section=None,
        section_text=None,
        detector=None,
        detector_text=None,
        additional_info=None,
        position=None,
    ):
        self.event_code = event_code
        self.transmitter_type = transmitter_type
        self.transmitter_code = transmitter_code
        self.authentication = authentication
        self.receiver = receiver
        self.alarm_type = alarm_type
        self.transmitter_time = transmitter_time
        self.reference = reference
        self.transmitter_area = transmitter_area
        self.section = section
        self.section_text = section_text
        self.detector = detector
        self.detector_text = detector_text
        self.additional_info = additional_info
        self.position = position

    @property
    def additional_info_text(self):
        """
        Additional info is extra info about the alarm. Input is added using the
        additional_info but we are under constraint to format the output
        properly. We accept a list of values. Each item should be printed on a
        separate line. We use CR+LF to separate lines.
        If we dont get a list we try to make a string of it and send it on.
        We must keep the resulting text under 2000 chars. On list input we
        truncate the last input that makes the message go over the limit
        On single row we truncate the data and add ... to it.

        :return: text
        """
        text = ""
        max_length = 2000
        if isinstance(self.additional_info, (list, tuple)):

            for item in self.additional_info:
                line = f"{item} \r\n"
                if len(text + line) > max_length:
                    break
                text = text + line  # TODO: Test
            return text

        elif isinstance(self.additional_info, dict):
            # print key and value on each row.
            for key, value in self.additional_info.items():
                line = f"{key}: {value} \r\n"
                if len(text + line) > max_length:
                    break
                text = text + line
            return text

        else:
            line = str(self.additional_info)
            if len(line) > max_length:
                line = line[:1997]
            return line

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"event_code={self.event_code}, "
            f"transmitter_type={self.transmitter_type}, "
            f"transmitter_code={self.transmitter_code}), "
            f"receiver={self.receiver})"
        )


class AlarmResponse(SOSAccessRequest):
    """
    Represents an AlarmResponse
    """

    def __init__(self, status, info, arrival_time=None, reference=None):
        self.reference = reference
        self.status = status
        self.info = info
        self.arrival_time = arrival_time

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"status={self.status}, "
            f"info={self.info}, "
            f"arrival_time={self.arrival_time.isoformat()}, "
            f"reference={self.reference})"
        )


class NewAuthRequest(SOSAccessRequest):
    """
    Represents a NewAuthRequest
    """

    def __init__(
        self, authentication, transmitter_code, transmitter_type, reference=None
    ):
        self.authentication = authentication
        self.reference = reference
        self.transmitter_code = transmitter_code
        self.transmitter_type = transmitter_type

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"authentication={self.authentication}, "
            f"transmitter_code={self.transmitter_code}, "
            f"transmitter_type={self.transmitter_type}, "
            f"reference={self.reference})"
        )


class NewAuthResponse(SOSAccessRequest):
    """
    Represents a NewAuthResponse
    """

    def __init__(
        self, status, info, new_authentication=None, arrival_time=None, reference=None
    ):
        self.reference = reference
        self.status = status
        self.info = info
        self.new_authentication = new_authentication
        self.arrival_time = arrival_time

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"new_authentication=<redacted>, "
            f"status={self.status}, "
            f"info={self.info}, "
            f"arrival_time={self.arrival_time.isoformat()}, "
            f"reference={self.reference})"
        )


class PingRequest(SOSAccessRequest):
    """
    Represents a PingRequest
    """

    def __init__(
        self, authentication, transmitter_code, transmitter_type, reference=None
    ):
        self.authentication = authentication
        self.reference = reference
        self.transmitter_code = transmitter_code
        self.transmitter_type = transmitter_type

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"authentication=<redacted>, "
            f"transmitter_code={self.transmitter_code}, "
            f"transmitter_type={self.transmitter_type}, "
            f"reference={self.reference})"
        )


class PingResponse(SOSAccessRequest):
    """
    Represents a PingResponse
    """

    def __init__(self, status, info, arrival_time=None, reference=None):
        self.reference = reference
        self.status = status
        self.info = info
        self.arrival_time = arrival_time  # Alarm Request

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"status={self.status}, "
            f"info={self.info}, "
            f"arrival_time={self.arrival_time.isoformat()}, "
            f"reference={self.reference})"
        )


class PositionSchema(marshmallow.Schema):

    """
    Scheme declaring the serializing of position data.

    <pos> Geographical coordinate in the format
    RT90 (2,5 gon West):
    “xXXXXXXXyYYYYYYY”

    where x is the x-coordinate, y is the y-
    coordinate. Values are given in meters.

    Ex. ”x1234567y1234567”.

    or in the format WGS84 (Lat/Long):
    “NDDMMmmEDDDMMmm”
    where DD are degrees; MM minutes; mm
    decimal minutes (leading 0 shall be given on
    the longitude if needed).

    ex WGS84
    <position>
    <pos>E597295E0176288</pos>
    </position>
    Ex RT90
    <position>
    <pos>x1234567y1234567</pos>
    <position>
    """

    pos = marshmallow.fields.String(required=True, validate=[Length(min=14, max=16)])

    class Meta:
        ordered = True


class SOSAccessSchema(marshmallow.Schema):
    """
    Main Schema for serializing and deserializing SOS Access XML data
    """

    __envelope__ = None
    __model__ = None

    @marshmallow.pre_load()
    def load_xml(self, data, **kwargs):
        try:
            # incoming XML
            parsed_data = xmltodict.parse(data)

            # remove envelope
            in_data = parsed_data[self.__envelope__]
        except xml.parsers.expat.ExpatError as e:
            raise XMLParseError from e
        return in_data

    @marshmallow.post_dump()
    def dump_xml(self, data, **kwargs):
        # add the envelope
        data_to_dump = {self.__envelope__: data}
        # make xml
        try:
            # the encoding is the same as latin-1 but if we specify latin-1 the xml
            # header will say latin-1 too. to be compliant with SOS Alarm we use the
            # text that their alarm server outputs.
            out_data = xmltodict.unparse(data_to_dump, encoding="iso-8859-1")
        except xml.parsers.expat.ExpatError as e:
            raise XMLParseError from e
        return out_data

    @marshmallow.post_load()
    def make_object(self, data, **kwargs):
        return self.__model__(**data)


class AlarmRequestSchema(SOSAccessSchema):
    """
    Schema for dumping and loading a AlarmRequest
    """

    __envelope__ = "alarmrequest"
    __model__ = AlarmRequest

    reference = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=50)]
    )
    authentication = marshmallow.fields.String(
        required=True, validate=[Length(equal=15)]
    )
    receiver = marshmallow.fields.String(
        required=True, validate=[Length(min=1, max=20)]
    )
    transmitter_time = marshmallow.fields.DateTime(
        allow_none=True, data_key="transmittertime"
    )
    alarm_type = marshmallow.fields.String(
        allow_none=True, validate=[OneOf(ALARM_TYPES)], data_key="alarmtype"
    )
    transmitter_type = marshmallow.fields.String(
        required=True, validate=[Length(equal=5)], data_key="transmittertype"
    )
    transmitter_code = marshmallow.fields.String(
        required=True, validate=[Length(min=1, max=15)], data_key="transmittercode"
    )
    transmitter_area = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=5)], data_key="transmitterarea"
    )
    event_code = marshmallow.fields.String(
        required=True, validate=[Length(min=1, max=25)], data_key="eventcode"
    )
    section = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=5)], data_key="section"
    )
    section_text = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=40)], data_key="sectiontext"
    )
    detector = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=5)]
    )
    detector_text = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=40)], data_key="detectortext"
    )
    # Lines in additionalinfo is separated via CR+LF or LF. CR = 0x0a LF = 0x0d
    additional_info = marshmallow.fields.String(
        allow_none=True,
        validate=[Length(min=1, max=2000)],
        data_key="additionalinfo",
        load_only=True,
    )
    additional_info_text = marshmallow.fields.String(
        allow_none=True,
        validate=[Length(min=1, max=2000)],
        data_key="additionalinfo",
        dump_only=True,
    )

    position = marshmallow.fields.Nested(PositionSchema, allow_none=True)

    class Meta:
        ordered = True


# Alarm Response


class AlarmResponseSchema(SOSAccessSchema):
    """
    Schema for dumping and loading a AlarmResponse
    """

    __envelope__ = "alarmresponse"
    __model__ = AlarmResponse

    reference = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=50)]
    )
    status = marshmallow.fields.Integer(
        required=True, validate=[OneOf(ALLOWED_STATUS_CODES)]
    )
    info = marshmallow.fields.String(required=True, validate=[Length(min=1, max=255)])
    arrival_time = marshmallow.fields.DateTime(
        allow_none=True, data_key="arrivaltime", datetimeformat="rfc"
    )

    class Meta:
        ordered = True


# Request new authentication


class NewAuthRequestSchema(SOSAccessSchema):
    """
    Schema for dumping and loading a NewAuthRequest
    """

    __envelope__ = "requestnewauthentication"
    __model__ = NewAuthRequest

    authentication = marshmallow.fields.String(
        required=True, validate=[Length(equal=15)]
    )
    reference = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=50)]
    )
    transmitter_code = marshmallow.fields.String(
        required=True, validate=[Length(min=1, max=15)], data_key="transmittercode"
    )
    transmitter_type = marshmallow.fields.String(
        required=True, validate=[Length(equal=5)], data_key="transmittertype"
    )

    class Meta:
        ordered = True


# Request new authentication response


class NewAuthResponseSchema(SOSAccessSchema):
    """
    Schema for dumping and loading a NewAuthResponse
    """

    __envelope__ = "requestnewauthenticationresponse"
    __model__ = NewAuthResponse

    reference = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=50)]
    )
    status = marshmallow.fields.Integer(
        required=True, validate=[OneOf(ALLOWED_STATUS_CODES)]
    )
    info = marshmallow.fields.String(required=True, validate=[Length(min=1, max=255)])
    new_authentication = marshmallow.fields.String(
        required=False, validate=[Length(equal=15)], data_key="newauthentication"
    )
    arrival_time = marshmallow.fields.DateTime(
        allow_none=True, data_key="arrivaltime", datetimeformat="rfc"
    )

    class Meta:
        ordered = True


# Ping request


class PingRequestSchema(SOSAccessSchema):
    """
    Schema for dumping and loading a PingRequest
    """

    __envelope__ = "pingrequest"
    __model__ = PingRequest

    authentication = marshmallow.fields.String(
        required=True, validate=[Length(equal=15)]
    )
    reference = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=50)]
    )
    transmitter_code = marshmallow.fields.String(
        required=True, validate=[Length(min=1, max=15)], data_key="transmittercode"
    )
    transmitter_type = marshmallow.fields.String(
        required=True, validate=[Length(equal=5)], data_key="transmittertype"
    )

    class Meta:
        ordered = True


# Ping response


class PingResponseSchema(SOSAccessSchema):
    """
    Schema for dumping and loading a PingResponse
    """

    __envelope__ = "pingresponse"
    __model__ = PingResponse

    reference = marshmallow.fields.String(
        allow_none=True, validate=[Length(min=1, max=50)]
    )
    status = marshmallow.fields.Integer(
        required=True, validate=[OneOf(ALLOWED_STATUS_CODES)]
    )
    info = marshmallow.fields.String(required=True, validate=[Length(min=1, max=255)])
    arrival_time = marshmallow.fields.DateTime(
        allow_none=True, data_key="arrivaltime", datetimeformat="rfc"
    )

    class Meta:
        ordered = True
