import sys


def error_message_detail(error, error_detail: sys):
    _, _, exc_tb = error_detail.exc_info()
    file_name = exc_tb.tb_frame.f_code.co_filename
    return "Error occurred! Python script name [{0}]; line number [{1}]; error message [{2}]".format(
        file_name, exc_tb.tb_lineno, str(error)
    )


class CustomException(Exception):
    def __init__(self, error_message, error_detail):
        """
        :param error_message: Error message in string format.
        """
        super().__init__(error_message)

        self.error_message = error_message_detail(
            error_message, error_detail=error_detail
        )

    def __str__(self):
        return self.error_message
