import logging

from sos_access.exceptions import (
    AlarmReceiverConnectionError,
    TCPTransportError,
    NotTreatedNotDistributed,
    OtherError,
)

logger = logging.getLogger(__name__)

fail_over_errors = (TCPTransportError, NotTreatedNotDistributed, OtherError)


def alternating_retry(func):
    """
    Decorator function that will allow for retrying alternately between the
    primary and secondary alarm receiver server.
    """

    def retried_func(*args, **kwargs):
        use_secondary = kwargs.get("secondary", False)
        retry_count = 0
        client = args[0]

        # if we only have a single receiver we only have to try on that.
        if client.use_single_receiver:
            max_retries = client.MAX_RETRY
        else:
            max_retries = client.MAX_RETRY * 2

        while retry_count < max_retries:
            try:
                kwargs["secondary"] = use_secondary
                result = func(*args, **kwargs)
                return result
            except fail_over_errors as e:
                logger.info(
                    f"Failed to deliver message to one receiver. "
                    f"Switching to the other"
                    f"Error was {e}"
                )
                if not client.use_single_receiver:
                    use_secondary = not use_secondary  # toggle fail over
                retry_count = retry_count + 1

        # if it comes out of the loop we raise new exeption.
        raise AlarmReceiverConnectionError(
            "Not possible to send data to any " "of the client receivers"
        )

    return retried_func
