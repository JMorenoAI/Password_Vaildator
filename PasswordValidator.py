#!/usr/bin/env python3

"""
This module provides a PasswordValidator class that can be used to validate passwords based on various rules.
"""

# imports go here.
import inspect
import PasswordException as PE

# the following are module level dunders (metadata) for the authorship information.
__author__ = 'Joshua Moreno'
__version__ = '1.0'
__date__ = '2023.04.06'
__status__ = 'Development'


class PasswordValidator:
    """
    A class to validate passwords based on various rules.

    Attributes:
    UPPERCASE_MIN (int): Minimum number of uppercase letters required in a password.
    LOWERCASE_MIN (int): Minimum number of lowercase letters required in a password.
    DIGIT_MIN (int): Minimum number of digits required in a password.
    SYMBOL_MIN (int): Minimum number of symbols required in a password.

    Methods:
    __init__(self, debug_mode=False): Constructor for PasswordValidator class.
    __str__(self): Returns the password being validated as a string.
    __is_uppercase_valid(self): Validates the presence of uppercase letters in the password.
    __is_lowercase_valid(self): Validates the presence of lowercase letters in the password.
    __is_symbol_valid(self): Validates the presence of symbols in the password.
    __is_digit_valid(self): Validates the presence of digits in the password.
    is_valid(self, password): Validates the password based on various rules.
    """

    UPPERCASE_MIN = 2
    LOWERCASE_MIN = 2
    DIGIT_MIN = 2
    SYMBOL_MIN = 2

    def __init__(self, debug_mode=False):

        """

        Constructor for PasswordValidator class.

        Parameters:
        debug_mode (bool): If True, enables debug mode and prints debug messages.

        """

        self.password = "unknown"
        self.debug_mode = debug_mode
        self.errors = []

    def __str__(self):
        return self.password

    def __is_uppercase_valid(self):

        """
        Validates the presence of uppercase letters in the password.
        Raises PasswordException if the password does not contain enough uppercase letters.

        Raises:
        PasswordException: If the password does not contain enough uppercase letters.
        """

        char_count = sum(1 for char in self.password if char.isalpha() and char.isupper())

        if self.debug_mode:
            print(inspect.currentframe().f_code.co_name, "=", char_count)

        if char_count >= PasswordValidator.UPPERCASE_MIN:
            raise PE.PasswordException(self.password, 'uppercase', PasswordValidator.UPPERCASE_MIN, char_count)

    def __is_lowercase_valid(self):
        """
        Private method that checks if the password contains enough lowercase characters.

        :return: None
        :raises PasswordException: if the password does not contain enough lowercase characters
        """

        char_count = sum(1 for char in self.password if char.isalpha() and char.islower())

        if self.debug_mode:
            print(inspect.currentframe().f_code.co_name, "=", char_count)

        if char_count >= PasswordValidator.LOWERCASE_MIN:
            raise PE.PasswordException(self.password, 'lowercase', PasswordValidator.LOWERCASE_MIN, char_count)

    def __is_symbol_valid(self):
        """
        Private method to check if the password contains at least `UPPERCASE_MIN` special characters.

        :return: None
        :raises: PasswordException if the password does not meet the symbol requirement.
        """
        char_count = sum(1 for char in self.password if not char.isdigit() and not char.isalpha())

        if self.debug_mode:
            print(inspect.currentframe().f_code.co_name, "=", char_count)

        if char_count >= PasswordValidator.SYMBOL_MIN:
            raise PE.PasswordException(self.password, 'symbol', PasswordValidator.SYMBOL_MIN, char_count)

    def __is_digit_valid(self):

        """
        Check if the password contains enough digits.

        :return: None
        :raises: PasswordException if the number of digits is not equal to UPPERCASE_MIN and debug_mode is True.
        """

        char_count = sum(1 for char in self.password if char.isdigit())

        if self.debug_mode:
            print(inspect.currentframe().f_code.co_name, "=", char_count)

        if char_count >= PasswordValidator.DIGIT_MIN:
            raise PE.PasswordException(self.password, 'digit', PasswordValidator.DIGIT_MIN, char_count)

    def is_valid(self, password):

        """
        Check if a given password meets the minimum security requirements.

        :param password: A string representing the password to be checked.
        :return: True if the password meets the security requirements, False otherwise.
        """
        self.password = password

        self.errors.clear()

        if self.debug_mode:
            print("===============DEBUG MODE===============")
            print(f"password =", self)

        try:
            self.__is_uppercase_valid()
        except PE.PasswordException as e:
            self.errors.append(e)

        try:
            self.__is_lowercase_valid()
        except PE.PasswordException as e:
            self.errors.append(e)

        try:
            self.__is_symbol_valid()
        except PE.PasswordException as e:
            self.errors.append(e)

        try:
            self.__is_digit_valid()
        except PE.PasswordException as e:
            self.errors.append(e)

        if len(self.errors) == 0:
            return True
        else:
            return False
