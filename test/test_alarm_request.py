import pytest
from sos_access.schemas import AlarmRequest


def test_alarm_request_additional_info_dict_to_string():

    alarm = AlarmRequest(
        event_code="AL",
        authentication="123456678",
        additional_info={"test": "test", "test2": 1},
        transmitter_code="IK00001",
        transmitter_type="SV001",
        receiver="Test",
    )

    assert alarm.additional_info_text == "test: test \r\ntest2: 1 \r\n"


def test_alarm_request_additional_info_dict_to_string_max_lenght():
    # create a dict that would be longer than 2000 chars
    test_dict = {}
    for x in enumerate(range(0, 1000)):
        test_dict[str(x)] = str(x)

    assert len(str(test_dict)) > 2000

    alarm = AlarmRequest(
        event_code="AL",
        authentication="123456678",
        additional_info=test_dict,
        transmitter_code="IK00001",
        transmitter_type="SV001",
        receiver="Test",
    )

    assert len(alarm.additional_info_text) == 1997


def test_alarm_request_additional_info_string_max_length():

    test_string = "{:<2200}".format("Teststring")
    assert len(test_string) > 2000

    alarm = AlarmRequest(
        event_code="AL",
        authentication="123456678",
        additional_info=test_string,
        transmitter_code="IK00001",
        transmitter_type="SV001",
        receiver="Test",
    )

    assert len(alarm.additional_info_text) == 1997


def test_alarm_request_additional_info_list_to_string():
    alarm = AlarmRequest(event_code="AL", authentication="123456678",
        additional_info=["test", "test2"], transmitter_code="IK00001",
        transmitter_type="SV001", receiver="Test", )

    assert alarm.additional_info_text == "test \r\ntest2 \r\n"


def test_alarm_request_additional_info_list_to_string_max_length():
    # create a dict that would be longer than 2000 chars
    test_list = list()
    for x in enumerate(range(0, 2000)):
        test_list.append(str(x))

    assert len(str(test_list)) > 2000

    alarm = AlarmRequest(event_code="AL", authentication="123456678",
        additional_info=test_list, transmitter_code="IK00001", transmitter_type="SV001",
        receiver="Test", )

    assert len(alarm.additional_info_text) == 1990