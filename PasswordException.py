import csv

# the following are module level dunders (metadata) for the authorship information.
__author__ = 'Joshua Moreno'
__version__ = '1.0'
__date__ = '2023.04.06'
__status__ = 'Development'


class PasswordException(Exception):
    
    """
    This class represents an exception that is raised when a password does not meet certain requirements.

    :param password: The password that caused the exception.
    :param error_type: The type of error that occurred.
    :param min_required: The minimum number of characters required for a password.
    :param ch

    """

    def __init__(self, password, error_type, min_required, char_count):
        self.log = {'password': password,
                    'error_type': error_type,
                    'min_required': min_required,
                    'char_count': char_count}
        with open('password_log.txt', 'a', newline='\n') as csvfile:
            writer = csv.writer(csvfile, delimiter='|', quoting=csv.QUOTE_MINIMAL)
            writer.writerow([password, error_type, min_required, char_count])
