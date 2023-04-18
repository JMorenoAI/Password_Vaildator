# the following are module level dunders (metadata) for the authorship information.
__author__ = 'Joshua Moreno'
__version__ = '1.0'
__date__ = '2023.04.06'
__status__ = 'Development'

import PasswordException as PE
import PasswordValidator as PV
import inspect


class AdvancedPasswordValidator(PV.PasswordValidator):
    """
    A class for advanced password validation.

    Attributes:
    -----------
    Inherits attributes from PasswordValidator class.

    Methods:
    --------
    __init__(self, debug_mode=False)
        Initializes the object of the class with debug mode on/off.

    __validate_min(self)
        Validates if the length of the password is greater than or equal to MIN_LIMIT.
        Raises a PasswordException if validation fails.

    __validate_max(self)
        Validates if the length of the password is less than or equal to MAX_LIMIT.
        Raises a PasswordException if validation fails.

    __validate_symbols(self)
        Validates if the number of symbols in the password is greater than or equal to MIN_SYMBOLS.
        Raises a PasswordException if validation fails.
    """

    MIN_LIMIT = 8
    MAX_LIMIT = 30
    VALID_SYMBOLS = ('!', '@', '#', '$', '*')

    # min requirements
    # max limit
    # specific symbols

    def __init__(self, debug_mode=False):
        """
        Initializes the object of the AdvancedPasswordValidator class.

        Parameters:
        ----------
        debug_mode : bool, optional
            A flag that turns on/off debugging mode. Default is False.
        """
        super().__init__(debug_mode)

    def __validate_min(self):
        """
        Validates if the length of the password is greater than or equal to MIN_LIMIT.
        Raises a PasswordException if validation fails.
        """
        char_count = len(self.password)

        if self.debug_mode:
            print(inspect.currentframe().f_code.co_name, "=", char_count)

        if char_count < AdvancedPasswordValidator.MIN_LIMIT:
            raise PE.PasswordException(self.password, 'uppercase', AdvancedPasswordValidator.MIN_LIMIT, char_count)

    def __validate_max(self):
        """
        Validates if the length of the password is less than or equal to MAX_LIMIT.
        Raises a PasswordException if validation fails.
        """
        char_count = len(self.password)

        if self.debug_mode:
            print(inspect.currentframe().f_code.co_name, "=", char_count)

        if char_count > AdvancedPasswordValidator.MAX_LIMIT:
            raise PE.PasswordException(self.password, 'uppercase', AdvancedPasswordValidator.MAX_LIMIT, char_count)

    def __validate_symbols(self):
        """
        Validates if the number of symbols in the password is greater than or equal to MIN_SYMBOLS.
        Raises a PasswordException if validation fails.
        """
        char_count = sum(1 for char in self.password if char in AdvancedPasswordValidator.VALID_SYMBOLS)

        if self.debug_mode:
            print(inspect.currentframe().f_code.co_name, "=", char_count)

        if char_count < super().MIN_SYMBOLS:
            raise PE.PasswordException(self.password, 'symbols', super().MIN_SYMBOLS, char_count)

    def is_valid(self, password):

        """
        Check if the password meets the following criteria:
        - Contains no invalid symbols
        - Does not exceed the maximum length
        - Meets the minimum length requirement

        Args:
        - password (str): the password to check

        Returns:
        - True if the password is valid, False otherwise
        """

        super().is_valid(password)

        try:
            self.__validate_symbols()
        except PE.PasswordException as e:
            self.errors.append(e)

        try:
            self.__validate_max()
        except PE.PasswordException as e:
            self.errors.append(e)

        try:
            self.__validate_min()
        except PE.PasswordException as e:
            self.errors.append(e)

        if len(self.errors) == 0:
            return True
        else:
            return False
